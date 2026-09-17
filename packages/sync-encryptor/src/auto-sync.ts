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
 * Files under OMNODEX_HOME:
 *   - auto-sync-state.json  last attempt, last success, last error
 *   - auto-sync.lock        held while a sync runs; stale after 10 minutes
 *
 * Settings (stream-config.json):
 *   - auto_sync: false                      turn automatic sync off
 *   - auto_sync_min_interval_seconds: <n>   minimum gap between syncs (default 60)
 * OMNODEX_AUTO_SYNC=0 in the environment also turns it off.
 *
 * Never throws: failures are recorded in auto-sync-state.json.
 */

import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { TraceEvent } from "@omnodex/shared";

/** Set on the detached child so the shim runs a sync instead of a hook. */
export const AUTO_SYNC_CHILD_ENV = "OMNODEX_AUTO_SYNC_CHILD";

export const DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS = 60;

/** A lock older than this is assumed to belong to a crashed sync. */
const LOCK_STALE_MS = 10 * 60 * 1000;

const STATE_FILE = "auto-sync-state.json";
const LOCK_FILE = "auto-sync.lock";

export interface AutoSyncState {
  last_attempt_at?: string;
  last_success_at?: string;
  last_blob_id?: string;
  last_error?: string | null;
}

export type AutoSyncDecision =
  | "started"
  | "disabled"
  | "no-credentials"
  | "not-entitled"
  | "too-soon"
  | "in-progress"
  | "error";

export type AutoSyncOutcome = "synced" | "in-progress" | "no-credentials" | "failed";

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
 */
export async function startBackgroundSync(
  opts: StartBackgroundSyncOptions,
): Promise<AutoSyncDecision> {
  try {
    if (process.env.OMNODEX_AUTO_SYNC === "0") return "disabled";

    const settings = await readSyncSettings(opts.home);
    if (settings === "no-credentials") return "no-credentials";
    if (settings === "not-entitled") return "not-entitled";
    if (!settings.enabled) return "disabled";

    const now = opts.now ?? Date.now();
    if (await lockIsHeld(opts.home, now)) return "in-progress";

    const state = await readAutoSyncState(opts.home);
    const lastAttempt = state.last_attempt_at ? Date.parse(state.last_attempt_at) : NaN;
    if (!Number.isNaN(lastAttempt) && now - lastAttempt < settings.minIntervalMs) {
      return "too-soon";
    }

    await writeAutoSyncState(opts.home, {
      ...state,
      last_attempt_at: new Date(now).toISOString(),
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
 * Run one sync in the foreground, guarded by the lock. Called by the
 * detached child. Records the outcome in auto-sync-state.json.
 */
export async function runAutoSync(home: string): Promise<AutoSyncOutcome> {
  if (!(await acquireLock(home))) return "in-progress";
  try {
    const settings = await readSyncSettings(home);
    if (typeof settings === "string") return "no-credentials";

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

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

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

  // The license cache written by `omnodex connect` and license validation
  // carries the customer ID the blob is encrypted for.
  const license = await readJson(path.join(home, "license-cache.json"));
  const response = license?.response as
    | { customer_id?: unknown; features?: unknown }
    | undefined;
  const customerId = typeof response?.customer_id === "string" ? response.customer_id : "";
  const features = Array.isArray(response?.features) ? response.features : [];
  if (!customerId || !features.includes("encrypted_sync")) return "not-entitled";

  const intervalSeconds = config.auto_sync_min_interval_seconds;
  return {
    apiToken,
    passphrase,
    apiUrl: typeof config.api_url === "string" && config.api_url
      ? config.api_url
      : "https://api.omnodex.com",
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
