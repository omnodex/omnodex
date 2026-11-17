// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Local mode delivery: the same capture path the hook shims use. Events go
 * through any capture pause, have credentials masked, and are appended to the
 * event log; then the community event rules judge the plaintext events and
 * their findings are appended too. Live push to a connected hosted dashboard
 * is best effort. Nothing here can block the agent: telemetry arrives after
 * the call ran.
 */

import * as path from "node:path";
import { applyCapturePause, EventLog, isPauseMarker, newEventId } from "@omnodex/event-log";
import { captureDetectEnabled, judgeCaptured, maskCaptured } from "@omnodex/analyzer/capture";
import { stampCaptured } from "@omnodex/analyzer/stamp";
import { pushEventsToCloud } from "@omnodex/sync-encryptor";
import type { TraceEvent } from "@omnodex/shared";

export interface DeliverResult {
  /** Events appended, findings excluded. */
  events: number;
  findings: number;
}

export interface Sink {
  deliver(events: TraceEvent[]): Promise<DeliverResult>;
  close(): Promise<void>;
}

export interface LocalSinkOptions {
  /** The Omnodex home: the event log lives under it. */
  home: string;
  /** Time cap for judging one batch. Judging runs after the sender was answered, so this is generous. Default 15000. */
  judgeTimeoutMs?: number;
  onError?: (message: string) => void;
}

export async function createLocalSink(options: LocalSinkOptions): Promise<Sink> {
  const { home } = options;
  const note = options.onError ?? (() => undefined);
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();

  return {
    async deliver(events) {
      if (events.length === 0) return { events: 0, findings: 0 };
      // A pause drops the events (record) or keeps them on this machine only
      // (sync); pause markers are always written. Masked as written: the
      // rules below judge the events as captured.
      const written = await maskCaptured(await applyCapturePause(events, home), home);
      for (const event of written) await log.append(event);

      let kept: TraceEvent[] = [];
      if (captureDetectEnabled()) {
        const judged = events.filter((e) => !isPauseMarker(e));
        const findings = await judgeCaptured(judged, {
          newEventId,
          timeoutMs: options.judgeTimeoutMs ?? 15_000,
          onError: (err) => note(`rule evaluation skipped: ${(err as Error).message}`),
        });
        const stamped = await stampCaptured(findings, judged, {
          home,
          onError: (err) => note(`finding stamping skipped: ${(err as Error).message}`),
        });
        // Judged even while recording is paused, so a pause never hides a finding from the rules.
        kept = await applyCapturePause([...stamped], home);
        for (const finding of kept) await log.append(finding);
      }

      await pushEventsToCloud([...written, ...kept], home, 2000);
      return { events: written.length, findings: kept.length };
    },
    async close() {
      await log.close();
    },
  };
}
