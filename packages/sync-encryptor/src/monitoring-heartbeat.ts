// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- monitoring heartbeat
 *
 * Tells the hosted service, which the agent cannot edit, what this
 * machine's monitoring looks like: per platform, whether our hooks, plugin
 * and MCP entry are in place and whether hooks are switched off (from the
 * config check's last run), plus pause state, whether an agent session is
 * open, the CLI version and how many unexplained changes were recorded
 * since the last heartbeat. Metadata only: no captured content, no paths.
 *
 * Sent from the background pass, after the config check: every 15 minutes,
 * and at the next pass (at least a minute apart) when the state changed.
 * It does not depend on sync settings or a sync pause, so pausing uploads
 * cannot hide monitoring being removed. A machine without an API token
 * never sends anything.
 *
 * Fire-and-forget: a failed send is not retried until the next heartbeat
 * is due, raises no error, and writes at most one launcher.log line per
 * offline stretch (with OMNODEX_DEBUG=1). The first heartbeat that gets
 * through says it is a catch-up and when the stretch began. A refusal
 * (no Hosted plan) waits a day.
 *
 * Files under OMNODEX_HOME:
 *   - monitoring-heartbeat.json   last attempt, last send, offline stretch
 */

import { promises as fs, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { activePauses, EventLog, readPauseState } from "@omnodex/event-log";
import { CAPTURE_CONTROL_SESSION_ID, type TraceEvent } from "@omnodex/shared";
import { computeMachineId } from "./machine-id.js";
import { readMonitoringSlots } from "./monitoring-check.js";

/** How often a heartbeat goes out when nothing changed. */
export const HEARTBEAT_INTERVAL_MS = 15 * 60 * 1000;
/** Shortest gap between heartbeats, for a state that changed. */
export const HEARTBEAT_MIN_GAP_MS = 60 * 1000;
/** How long a refused heartbeat waits before trying again. */
const REFUSED_WAIT_MS = 24 * 60 * 60 * 1000;
/** A session with an event this recent, and no end, counts as open. */
export const SESSION_OPEN_WINDOW_MS = 30 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 10_000;
const STATE_FILE = "monitoring-heartbeat.json";
const TAIL_BYTES = 16 * 1024;

/** One component's state across a platform's installations. */
export type ComponentState = "ok" | "missing" | "disabled" | "none";

export interface HeartbeatPlatform {
  platform: string;
  hooks: ComponentState;
  plugin: ComponentState;
  mcp: ComponentState;
  /** Installations of this platform the config check inspected. */
  installs: number;
  /** A session this platform's hooks recorded is open. */
  session_open: boolean;
}

export interface Heartbeat {
  sent_at: string;
  cli_version: string;
  /** Any agent session open, the proxy's included. */
  session_open: boolean;
  record_paused: boolean;
  sync_paused: boolean;
  /** Unexplained monitoring changes recorded since the last heartbeat sent. */
  unexplained_changes: number;
  /** The first heartbeat after one or more failed. */
  catch_up: boolean;
  offline_since?: string;
  platforms: HeartbeatPlatform[];
}

export interface HeartbeatState {
  last_attempt_at?: string;
  last_sent_at?: string;
  /** The state last tried, to notice a change. */
  last_digest?: string;
  offline_since?: string | null;
  refused_until?: string | null;
  last_error?: string | null;
}

export type HeartbeatOutcome = "not-due" | "waiting" | "sent" | "offline" | "refused";

export interface SendHeartbeatOptions {
  apiUrl: string;
  apiToken: string;
  now?: number;
  fetchFn?: typeof fetch;
  env?: NodeJS.ProcessEnv;
}

const HOOK_PLATFORMS: Record<string, string> = {
  "claude-code-hook": "claude-code",
  "codex-hook": "codex",
  "antigravity-hook": "antigravity",
};

/** Worst first: what a platform reports when its installations differ. */
const RANK: readonly ComponentState[] = ["missing", "disabled", "ok", "none"];

/** What the config check's last state says about one component. */
function componentState(state: string): ComponentState | null {
  if (state === "ok") return "ok";
  if (state === "project_gone") return null;
  if (state.endsWith("_disabled")) return "disabled";
  return "missing";
}

function worse(a: ComponentState, b: ComponentState): ComponentState {
  return RANK.indexOf(a) <= RANK.indexOf(b) ? a : b;
}

/** Build the heartbeat from local state. Reads only. */
export async function buildHeartbeat(
  home: string,
  opts: { now?: number; since?: string; catchUp?: boolean; offlineSince?: string } = {},
): Promise<Heartbeat> {
  const now = opts.now ?? Date.now();
  const platforms = new Map<string, HeartbeatPlatform>();
  for (const [key, state] of Object.entries(await readMonitoringSlots(home))) {
    const [target = "", component = ""] = key.split("|");
    const s = componentState(state);
    if (!target || s === null || (component !== "hooks" && component !== "plugin" && component !== "mcp")) continue;
    const p = platforms.get(target) ??
      { platform: target, hooks: "none", plugin: "none", mcp: "none", installs: 0, session_open: false };
    p[component] = worse(p[component], s);
    p.installs++;
    platforms.set(target, p);
  }
  const open = await openSessions(home, now);
  for (const p of platforms.values()) p.session_open = open.has(p.platform);
  const pauses = activePauses(await readPauseState(home), now);
  return {
    sent_at: new Date(now).toISOString(),
    cli_version: cliVersion(),
    session_open: open.size > 0,
    record_paused: pauses.record !== undefined,
    sync_paused: pauses.sync !== undefined,
    unexplained_changes: await unexplainedSince(home, opts.since),
    catch_up: opts.catchUp === true,
    ...(opts.offlineSince ? { offline_since: opts.offlineSince } : {}),
    platforms: [...platforms.values()].sort((a, b) => a.platform.localeCompare(b.platform)),
  };
}

/**
 * Send a heartbeat if one is due. Never throws; a failure waits for the
 * next heartbeat rather than retrying.
 */
export async function sendMonitoringHeartbeat(home: string, opts: SendHeartbeatOptions): Promise<HeartbeatOutcome> {
  const now = opts.now ?? Date.now();
  try {
    const state = await readHeartbeatState(home);
    if (state.refused_until && now < Date.parse(state.refused_until)) return "waiting";
    const offlineSince = state.offline_since ?? undefined;
    const heartbeat = await buildHeartbeat(home, {
      now,
      ...(state.last_sent_at ? { since: state.last_sent_at } : {}),
      catchUp: offlineSince !== undefined,
      ...(offlineSince ? { offlineSince } : {}),
    });
    const digest = digestOf(heartbeat);
    const lastAttempt = state.last_attempt_at ? Date.parse(state.last_attempt_at) : NaN;
    if (!Number.isNaN(lastAttempt)) {
      const since = now - lastAttempt;
      if (since < HEARTBEAT_MIN_GAP_MS) return "not-due";
      if (since < HEARTBEAT_INTERVAL_MS && digest === state.last_digest) return "not-due";
    }
    state.last_attempt_at = heartbeat.sent_at;
    state.last_digest = digest;
    await writeHeartbeatState(home, state);

    let outcome: HeartbeatOutcome;
    try {
      const res = await (opts.fetchFn ?? fetch)(`${opts.apiUrl.replace(/\/$/, "")}/api/v1/sync/monitoring/heartbeat`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${opts.apiToken}`,
          "Content-Type": "application/json",
          "X-Omnodex-Machine-Id": computeMachineId(home),
        },
        body: JSON.stringify(heartbeat),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.ok) {
        outcome = "sent";
        state.last_sent_at = heartbeat.sent_at;
        state.offline_since = null;
        state.last_error = null;
      } else if (res.status === 400 || res.status === 401 || res.status === 403) {
        outcome = "refused";
        state.refused_until = new Date(now + REFUSED_WAIT_MS).toISOString();
        state.last_error = `HTTP ${res.status}`;
      } else {
        outcome = "offline";
        state.last_error = `HTTP ${res.status}`;
      }
    } catch (err) {
      outcome = "offline";
      state.last_error = (err as Error)?.message ?? String(err);
    }
    if (outcome === "offline" && !state.offline_since) {
      state.offline_since = heartbeat.sent_at;
      await debugLine(home, `heartbeat not delivered (${state.last_error}); next try in 15 minutes`, opts.env);
    }
    await writeHeartbeatState(home, state);
    return outcome;
  } catch {
    return "offline";
  }
}

/** Platforms with an open session; "proxy" for sessions only the proxy saw. */
async function openSessions(home: string, now: number): Promise<Set<string>> {
  const open = new Set<string>();
  const dir = path.join(home, "event-log", "sessions");
  let names: string[];
  try {
    names = await fs.readdir(dir);
  } catch {
    return open;
  }
  const control = `${CAPTURE_CONTROL_SESSION_ID.replace(/[^a-zA-Z0-9_.-]/g, "_")}.jsonl`;
  for (const name of names) {
    if (!name.endsWith(".jsonl") || name === control) continue;
    const file = path.join(dir, name);
    try {
      const stat = await fs.stat(file);
      if (now - stat.mtimeMs > SESSION_OPEN_WINDOW_MS) continue;
      const last = await lastEvent(file, stat.size);
      if (!last || last.event_type === "session.ended") continue;
      open.add(HOOK_PLATFORMS[last.interceptor] ?? "proxy");
    } catch {
      // Removed meanwhile, or unreadable: not open.
    }
  }
  return open;
}

/** The last complete event in a session file. */
async function lastEvent(file: string, size: number): Promise<TraceEvent | null> {
  const handle = await fs.open(file, "r");
  try {
    const length = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(length);
    await handle.read(buf, 0, length, size - length);
    const lines = buf.toString("utf8").split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i]!.trim();
      if (!line) continue;
      try {
        return JSON.parse(line) as TraceEvent;
      } catch {
        // A write in progress, or the cut-off first line.
      }
    }
    return null;
  } finally {
    await handle.close();
  }
}

async function unexplainedSince(home: string, since: string | undefined): Promise<number> {
  const log = new EventLog({ root: path.join(home, "event-log") });
  try {
    const events = await log.readSession(CAPTURE_CONTROL_SESSION_ID);
    return events.filter((e) => e.event_type === "monitoring.unexplained_change" && (!since || e.occurred_at > since)).length;
  } catch {
    return 0;
  } finally {
    await log.close();
  }
}

/** The state that, when it changes, sends a heartbeat before 15 minutes are up. */
function digestOf(h: Heartbeat): string {
  return JSON.stringify({
    cli_version: h.cli_version,
    session_open: h.session_open,
    record_paused: h.record_paused,
    sync_paused: h.sync_paused,
    unexplained: h.unexplained_changes > 0,
    platforms: h.platforms,
  });
}

let version: string | undefined;

/** The installed CLI's version, from the nearest omnodex package.json. */
function cliVersion(): string {
  if (version !== undefined) return version;
  version = "0.0.0-dev";
  try {
    let dir = path.dirname(fileURLToPath(import.meta.url));
    for (let i = 0; i < 6; i++) {
      try {
        const pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
        if ((pkg.name === "omnodex" || pkg.name === "@omnodex/cli") && typeof pkg.version === "string") {
          version = pkg.version as string;
          break;
        }
      } catch {
        // Not at this level.
      }
      dir = path.dirname(dir);
    }
  } catch {
    // Keep the fallback.
  }
  return version;
}

export async function readHeartbeatState(home: string): Promise<HeartbeatState> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(home, STATE_FILE), "utf8"));
    return parsed && typeof parsed === "object" ? (parsed as HeartbeatState) : {};
  } catch {
    return {};
  }
}

async function writeHeartbeatState(home: string, state: HeartbeatState): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  const file = path.join(home, STATE_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2) + "\n");
  await fs.rename(tmp, file);
}

async function debugLine(home: string, message: string, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  if (env.OMNODEX_DEBUG !== "1") return;
  await fs.appendFile(path.join(home, "launcher.log"), `${new Date().toISOString()} [heartbeat] ${message}\n`).catch(() => undefined);
}
