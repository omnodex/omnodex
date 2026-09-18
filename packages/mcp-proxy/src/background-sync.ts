// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- background-sync
 *
 * Periodic refresh of the hosted dashboard's encrypted blob while a proxy
 * session is running.
 *
 * Hook shims sync once, when their session ends. A proxy session can last
 * hours and may never end cleanly (a desktop host that is force-quit closes
 * the pipe without a SIGTERM), so the proxy also syncs on a timer.
 *
 * Each tick calls startBackgroundSync(), which re-spawns the proxy binary
 * detached with AUTO_SYNC_CHILD_ENV set; that child runs the sync and exits.
 * The work stays out of this process because the sync replays the whole event
 * log through the projector, and node:sqlite is synchronous: doing it here
 * would stall the thread that answers the agent's tools/call requests.
 *
 * startBackgroundSync() applies its own guards (credentials, entitlement,
 * minimum interval, lock file) and never throws, so a tick on an unconnected
 * machine costs two small disk reads.
 */

import {
  readAutoSyncIntervalMs,
  startBackgroundSync,
  type AutoSyncDecision,
  type StartBackgroundSyncOptions,
} from "@omnodex/sync-encryptor";

/** Signature of startBackgroundSync; overridden in tests. */
export type StartSyncFn = (
  opts: StartBackgroundSyncOptions,
) => Promise<AutoSyncDecision>;

export interface AutoSyncTimerOptions {
  /** OMNODEX_HOME. */
  home: string;
  /**
   * Script the detached child runs. Entrypoints pass process.argv[1], and
   * must handle AUTO_SYNC_CHILD_ENV by calling runAutoSync() and exiting.
   */
  scriptPath: string;
  /** Period override. Read from stream-config.json when omitted. */
  intervalMs?: number;
  startSyncFn?: StartSyncFn;
}

export interface AutoSyncTimer {
  /** Period the timer settled on, in milliseconds. */
  readonly intervalMs: number;
  /** Cancel the timer. Safe to call twice. */
  stop(): void;
}

/**
 * Start the periodic sync. The timer is unref'd, so it never keeps the proxy
 * alive after the agent disconnects.
 */
export async function startAutoSyncTimer(
  opts: AutoSyncTimerOptions,
): Promise<AutoSyncTimer> {
  const startSync = opts.startSyncFn ?? startBackgroundSync;
  const intervalMs = opts.intervalMs ?? (await readAutoSyncIntervalMs(opts.home));

  const timer = setInterval(() => {
    void startSync({ home: opts.home, scriptPath: opts.scriptPath }).catch(
      () => undefined,
    );
  }, intervalMs);
  timer.unref?.();

  let stopped = false;
  return {
    intervalMs,
    stop(): void {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
    },
  };
}
