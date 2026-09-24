// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- automatic background sync
 *
 * Keeps the hosted dashboard's encrypted blob current without a manual
 * `omnodex sync`. Hook shims call startBackgroundSync() when a session
 * ends. It runs a few cheap file checks and, if a sync is due, re-spawns
 * the same shim script detached with AUTO_SYNC_CHILD_ENV set. The shim
 * sees that variable, calls runAutoSync() instead of reading a hook
 * payload, and exits. The hook itself returns immediately, which matters
 * for hosts that cap hook runtime at a few seconds.
 *
 * The MCP proxy uses the same mechanism from a long-lived process: a timer
 * calls startBackgroundSync() every readAutoSyncIntervalMs(), and again when
 * the agent disconnects. Spawning rather than syncing in-process keeps the
 * projector's synchronous SQLite replay off the thread answering tools/call.
 *
 * The same child also runs rule detection before it syncs, when the caller
 * asks for it (`detect: true` here, a `detect` callback in runAutoSync).
 * Detection is not gated on sync: an install with no stream, no entitlement
 * or sync turned off still gets its activity analyzed, and only the upload
 * is skipped. Findings are appended to the local log, pushed to the live
 * relay when streaming is set up, and carried by the blob sync that follows.
 * Hook shims also start the pass mid-session once backgroundPassDue() says
 * the last one is older than the timer period, so a session that runs all
 * day is not analyzed only at its end.
 *
 * Files under OMNODEX_HOME:
 *   - auto-sync-state.json  last attempt, last success, last error
 *   - auto-sync.lock        held while a sync runs; stale after 10 minutes
 *
 * Settings (stream-config.json):
 *   - auto_sync: false                      turn automatic sync off
 *   - auto_sync_min_interval_seconds: <n>   minimum gap between syncs (default 60)
 *   - auto_sync_interval_seconds: <n>       proxy timer period, and how stale a
 *                                           pass may get mid-session (default 900)
 * OMNODEX_AUTO_SYNC=0 in the environment also turns sync off.
 * OMNODEX_AUTO_DETECT=0 turns background detection off.
 *
 * Never throws: failures are recorded in auto-sync-state.json.
 */

import { refreshRuleBundle } from "./rules-refresh.js";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { TraceEvent } from "@omnodex/shared";
import { readOrFetchLicense } from "./license-cache.js";
import { pushEventsToCloud } from "./shim-push.js";

/** Set on the detached child so the shim runs a sync instead of a hook. */
export const AUTO_SYNC_CHILD_ENV = "OMNODEX_AUTO_SYNC_CHILD";

export const DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS = 60;

/**
 * How often a long-lived process (the MCP proxy) asks for a sync. Matches
 * the feature-extraction cadence so a session that never ends cleanly is
 * still no more than a quarter hour stale in the dashboard.
 */
export const DEFAULT_AUTO_SYNC_INTERVAL_SECONDS = 15 * 60;

/** A configured timer period below this is ignored; the default is used. */
const MIN_AUTO_SYNC_INTERVAL_SECONDS = 30;

/** A lock older than this is assumed to belong to a crashed sync. */
const LOCK_STALE_MS = 10 * 60 * 1000;

/** Bound on the one-time license fetch for a home that has no cache yet. */
const LICENSE_FETCH_TIMEOUT_MS = 3000;

const STATE_FILE = "auto-sync-state.json";
const LOCK_FILE = "auto-sync.lock";

export interface AutoSyncState {
  last_attempt_at?: string;
  last_success_at?: string;
  last_blob_id?: string;
  last_error?: string | null;
  last_detect_at?: string;
  last_detect_findings?: number;
  last_detect_error?: string | null;
  /**
   * A pass with detection was asked for but throttled or already running,
   * so activity since the last one may be unanalyzed. The next hook event
   * past the minimum interval starts it (backgroundPassDue).
   */
  pass_pending?: boolean;
}

export type AutoSyncDecision =
  | "started"
  | "disabled"
  | "no-credentials"
  | "not-entitled"
  | "too-soon"
  | "in-progress"
  | "error";

export type AutoSyncOutcome =
  | "synced"
  | "in-progress"
  | "no-credentials"
  | "disabled"
  | "failed";

interface SyncSettings {
  apiToken: string;
  passphrase: string;
  apiUrl: string;
  customerId: string;
  enabled: boolean;
  minIntervalMs: number;
}

type SpawnFn = (
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
) => void;

export interface StartBackgroundSyncOptions {
  /** OMNODEX_HOME. */
  home: string;
  /** Script the detached child runs; hook shims pass process.argv[1]. */
  scriptPath: string;
  /** Clock override for tests. */
  now?: number;
  /** Spawn override for tests. */
  spawnFn?: SpawnFn;
  /**
   * The child also runs detection (its runAutoSync call passes a `detect`
   * callback). Starts the child even when there is nothing to sync.
   */
  detect?: boolean;
}

export interface RunAutoSyncOptions {
  /**
   * Detection pass run under the lock before the sync. Returns the findings
   * it appended to the log. Callers load the analyzer inside it, so the
   * per-event hook path never imports it.
   */
  detect?: () => Promise<TraceEvent[]>;
  /** Live push override for tests. */
  pushFn?: (events: TraceEvent[], home: string) => Promise<boolean>;
  /**
   * Advanced rule bundle refresh, run before detection so the pass judges
   * with the current bundle. Defaults to refreshRuleBundle; tests replace it.
   */
  refreshRules?: (home: string) => Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** True when a batch of events includes the end of a session. */
export function includesSessionEnd(events: readonly TraceEvent[]): boolean {
  return events.some((e) => e.event_type === "session.ended");
}

/**
 * Start a detached background sync if one is due. Returns what it decided.
 * Records the attempt time before spawning so that sessions ending at the
 * same moment do not each start a sync.
 *
 * With `detect`, the child is started whenever detection is enabled, even
 * if there is nothing to sync; the decision then reports "started".
 */
export async function startBackgroundSync(
  opts: StartBackgroundSyncOptions,
): Promise<AutoSyncDecision> {
  try {
    const syncDecision = await syncGate(opts.home);
    const detect = opts.detect === true && detectionEnabled();
    if (typeof syncDecision === "string" && !detect) return syncDecision;

    const minIntervalMs =
      typeof syncDecision === "string"
        ? DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS * 1000
        : syncDecision.minIntervalMs;

    const now = opts.now ?? Date.now();
    const state = await readAutoSyncState(opts.home);
    const markPending = async (): Promise<void> => {
      if (detect && !state.pass_pending) {
        await writeAutoSyncState(opts.home, { ...state, pass_pending: true });
      }
    };

    if (await lockIsHeld(opts.home, now)) {
      await markPending();
      return "in-progress";
    }

    const lastAttempt = state.last_attempt_at ? Date.parse(state.last_attempt_at) : NaN;
    if (!Number.isNaN(lastAttempt) && now - lastAttempt < minIntervalMs) {
      await markPending();
      return "too-soon";
    }

    await writeAutoSyncState(opts.home, {
      ...state,
      last_attempt_at: new Date(now).toISOString(),
      pass_pending: false,
    });

    const spawnFn = opts.spawnFn ?? spawnDetached;
    spawnFn(process.execPath, [opts.scriptPath], {
      ...process.env,
      [AUTO_SYNC_CHILD_ENV]: "1",
    });
    return "started";
  } catch {
    return "error";
  }
}

/**
 * True when a hook should start a background pass mid-session: there has
 * never been one, the last attempt is older than the timer period, or a
 * pass was throttled (a session ending moments after the last one) and the
 * minimum interval has now passed. Costs two small file reads, so it is
 * cheap enough for every hook event.
 */
export async function backgroundPassDue(home: string, now = Date.now()): Promise<boolean> {
  try {
    if (!detectionEnabled() && process.env.OMNODEX_AUTO_SYNC === "0") return false;
    const state = await readAutoSyncState(home);
    const lastAttempt = state.last_attempt_at ? Date.parse(state.last_attempt_at) : NaN;
    if (Number.isNaN(lastAttempt)) return true;
    const since = now - lastAttempt;
    if (state.pass_pending && since >= DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS * 1000) return true;
    return since >= (await readAutoSyncIntervalMs(home));
  } catch {
    return false;
  }
}

/**
 * Run one background pass in the foreground, guarded by the lock: detection
 * first when a `detect` callback is given, then the sync if this install is
 * set up and entitled for it. Called by the detached child. Records both
 * outcomes in auto-sync-state.json.
 */
export async function runAutoSync(
  home: string,
  opts: RunAutoSyncOptions = {},
): Promise<AutoSyncOutcome> {
  if (!(await acquireLock(home))) return "in-progress";
  try {
    if (opts.detect && detectionEnabled()) {
      // Pro and Enterprise only; anyone else returns before any request.
      await (opts.refreshRules ?? refreshRuleBundle)(home).catch(() => undefined);
      await runDetection(home, opts.detect, opts.pushFn ?? pushEventsToCloud);
    }

    if (process.env.OMNODEX_AUTO_SYNC === "0") return "disabled";
    const settings = await readSyncSettings(home);
    if (typeof settings === "string") return "no-credentials";
    if (!settings.enabled) return "disabled";

    // Loaded lazily: hook shims import this module on every event, but
    // only the background child needs SQLite and the projector.
    const { syncReadModel } = await import("./sync-runner.js");
    try {
      const result = await syncReadModel({
        home,
        apiUrl: settings.apiUrl,
        apiToken: settings.apiToken,
        passphrase: settings.passphrase,
        customerId: settings.customerId,
      });
      await updateAutoSyncState(home, {
        last_success_at: new Date().toISOString(),
        last_blob_id: result.blobId,
        last_error: null,
      });
      return "synced";
    } catch (err) {
      await updateAutoSyncState(home, {
        last_error: (err as Error)?.message ?? String(err),
      });
      return "failed";
    }
  } catch {
    return "failed";
  } finally {
    await releaseLock(home);
  }
}

/** Read auto-sync-state.json, or an empty state if it is missing. */
export async function readAutoSyncState(home: string): Promise<AutoSyncState> {
  try {
    const raw = await fs.readFile(path.join(home, STATE_FILE), "utf8");
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as AutoSyncState) : {};
  } catch {
    return {};
  }
}

/**
 * Timer period for a long-lived process, from stream-config.json. Hook shims
 * have no timer -- they sync when a session ends -- so only the MCP proxy
 * reads this. A missing, unparseable or implausibly small value falls back to
 * the default rather than hammering the API.
 */
export async function readAutoSyncIntervalMs(home: string): Promise<number> {
  const config = await readJson(path.join(home, "stream-config.json"));
  const seconds = config?.auto_sync_interval_seconds;
  if (
    typeof seconds === "number" &&
    Number.isFinite(seconds) &&
    seconds >= MIN_AUTO_SYNC_INTERVAL_SECONDS
  ) {
    return seconds * 1000;
  }
  return DEFAULT_AUTO_SYNC_INTERVAL_SECONDS * 1000;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

function detectionEnabled(): boolean {
  return process.env.OMNODEX_AUTO_DETECT !== "0";
}

/**
 * Run the caller's detection pass and push what it found to the live relay.
 * Never throws: a failure is recorded and the sync still runs.
 */
async function runDetection(
  home: string,
  detect: () => Promise<TraceEvent[]>,
  push: (events: TraceEvent[], home: string) => Promise<boolean>,
): Promise<void> {
  try {
    const findings = await detect();
    // pushEventsToCloud is a no-op without credentials or live_streaming.
    if (findings.length > 0) await push(findings, home).catch(() => false);
    await updateAutoSyncState(home, {
      last_detect_at: new Date().toISOString(),
      last_detect_findings: findings.length,
      last_detect_error: null,
    });
  } catch (err) {
    await updateAutoSyncState(home, {
      last_detect_at: new Date().toISOString(),
      last_detect_error: (err as Error)?.message ?? String(err),
    }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * Whether a sync may run: the settings when it may, or why it may not, in
 * the order startBackgroundSync has always reported them.
 */
async function syncGate(
  home: string,
): Promise<SyncSettings | "disabled" | "no-credentials" | "not-entitled"> {
  if (process.env.OMNODEX_AUTO_SYNC === "0") return "disabled";
  const settings = await readSyncSettings(home);
  if (typeof settings === "string") return settings;
  if (!settings.enabled) return "disabled";
  return settings;
}

async function readJson(file: string): Promise<Record<string, unknown> | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function readSyncSettings(
  home: string,
): Promise<SyncSettings | "no-credentials" | "not-entitled"> {
  const config = await readJson(path.join(home, "stream-config.json"));
  const apiToken = typeof config?.api_token === "string" ? config.api_token : "";
  const passphrase = typeof config?.passphrase === "string" ? config.passphrase : "";
  if (!config || !apiToken || !passphrase) return "no-credentials";

  const apiUrl = typeof config.api_url === "string" && config.api_url
    ? config.api_url
    : "https://api.omnodex.com";

  // The license cache written by `omnodex connect` and license validation
  // carries the customer ID the blob is encrypted for. A home without one
  // fetches it here rather than staying unsynced.
  const license = await readOrFetchLicense(home, {
    apiToken,
    apiUrl,
    timeoutMs: LICENSE_FETCH_TIMEOUT_MS,
  });
  const customerId = license?.customer_id ?? "";
  if (!customerId || !license?.features.includes("encrypted_sync")) return "not-entitled";

  const intervalSeconds = config.auto_sync_min_interval_seconds;
  return {
    apiToken,
    passphrase,
    apiUrl,
    customerId,
    enabled: config.auto_sync !== false,
    minIntervalMs:
      (typeof intervalSeconds === "number" && intervalSeconds >= 0
        ? intervalSeconds
        : DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS) * 1000,
  };
}

// ---------------------------------------------------------------------------
// State and lock files
// ---------------------------------------------------------------------------

async function writeAutoSyncState(home: string, state: AutoSyncState): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  await fs.writeFile(path.join(home, STATE_FILE), JSON.stringify(state, null, 2) + "\n");
}

async function updateAutoSyncState(home: string, update: AutoSyncState): Promise<void> {
  const state = await readAutoSyncState(home);
  await writeAutoSyncState(home, { ...state, ...update });
}

async function lockIsHeld(home: string, now: number): Promise<boolean> {
  try {
    const stat = await fs.stat(path.join(home, LOCK_FILE));
    return now - stat.mtimeMs < LOCK_STALE_MS;
  } catch {
    return false;
  }
}

async function acquireLock(home: string): Promise<boolean> {
  const lockPath = path.join(home, LOCK_FILE);
  await fs.mkdir(home, { recursive: true });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const handle = await fs.open(lockPath, "wx");
      await handle.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
      await handle.close();
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") return false;
      if (await lockIsHeld(home, Date.now())) return false;
      // Stale lock from a crashed sync: remove it and try once more.
      await fs.unlink(lockPath).catch(() => undefined);
    }
  }
  return false;
}

async function releaseLock(home: string): Promise<void> {
  await fs.unlink(path.join(home, LOCK_FILE)).catch(() => undefined);
}

function spawnDetached(command: string, args: string[], env: NodeJS.ProcessEnv): void {
  const child = spawn(command, args, {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
    env,
  });
  child.on("error", () => undefined);
  child.unref();
}
