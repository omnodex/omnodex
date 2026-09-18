// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- cloud-push
 *
 * Real-time event push to the cloud relay, so a proxy session appears in the
 * hosted dashboard while it is still running.
 *
 * Hook shims call pushEventsToCloud() once per hook invocation and exit. The
 * proxy is long-lived and emits a pair of events per tool call, so it queues
 * instead: a batch goes out once the queue has been quiet for flushDelayMs,
 * or immediately when it reaches maxBatchSize. Batches are pushed one at a
 * time so events reach the relay in the order they were emitted.
 *
 * Fire-and-forget throughout. pushEventsToCloud never throws, and returns
 * false without a network call when the machine has no stream credentials or
 * no live_streaming entitlement, so an unconnected proxy pays two small disk
 * reads per batch and nothing else. Nothing here is on the agent's path: the
 * local event log is still the source of truth and is written first.
 */

import type { TraceEvent } from "@omnodex/shared";
import { pushEventsToCloud } from "@omnodex/sync-encryptor";

/** Signature of pushEventsToCloud; overridden in tests. */
export type CloudPushFn = (
  events: TraceEvent[],
  home: string,
) => Promise<boolean>;

/** Quiet period before a partial batch is sent. */
const DEFAULT_FLUSH_DELAY_MS = 250;

/** A batch this size is sent without waiting for the quiet period. */
const DEFAULT_MAX_BATCH_SIZE = 50;

export interface CloudPushQueueOptions {
  /** OMNODEX_HOME, where credentials and the cached streaming key live. */
  home: string;
  flushDelayMs?: number;
  maxBatchSize?: number;
  pushFn?: CloudPushFn;
}

export interface CloudPushQueue {
  /** Queue an event. Never throws and never blocks the caller. */
  enqueue(event: TraceEvent): void;
  /** Send everything queued so far and wait for it to land. */
  flush(): Promise<void>;
  /** Flush, then ignore any further events. Safe to call twice. */
  close(): Promise<void>;
}

/**
 * Create a batching push queue. Callers enqueue after the event has been
 * written to the local log, so a failed push loses nothing.
 */
export function createCloudPushQueue(
  opts: CloudPushQueueOptions,
): CloudPushQueue {
  const push = opts.pushFn ?? pushEventsToCloud;
  const flushDelayMs = opts.flushDelayMs ?? DEFAULT_FLUSH_DELAY_MS;
  const maxBatchSize = opts.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;

  const pending: TraceEvent[] = [];
  let timer: NodeJS.Timeout | undefined;
  let closed = false;
  // Serialises batches so they arrive in emit order, and gives flush() a
  // promise that covers pushes already in flight.
  let chain: Promise<void> = Promise.resolve();

  function drain(): Promise<void> {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (pending.length === 0) return chain;
    const batch = pending.splice(0, pending.length);
    chain = chain.then(
      () => push(batch, opts.home).then(() => undefined, () => undefined),
      () => undefined,
    );
    return chain;
  }

  return {
    enqueue(event: TraceEvent): void {
      if (closed) return;
      pending.push(event);
      if (pending.length >= maxBatchSize) {
        void drain();
        return;
      }
      if (timer !== undefined) return;
      timer = setTimeout(() => {
        timer = undefined;
        void drain();
      }, flushDelayMs);
      // The queue must never hold the proxy open past the agent's disconnect.
      timer.unref?.();
    },

    flush(): Promise<void> {
      return drain();
    },

    async close(): Promise<void> {
      await drain();
      closed = true;
    },
  };
}
