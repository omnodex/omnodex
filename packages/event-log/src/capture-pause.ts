// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Capture pauses: a person stops recording, or stops uploads, for a while.
 *
 * State lives in OMNODEX_HOME/pause-state.json, one entry per paused kind:
 *
 *   { "record": { "pause_id", "paused_at", "until", "by" },
 *     "sync":   { ... } }
 *
 * A missing file means nothing is paused, and an entry whose `until` has
 * passed counts as resumed, so a lost timer never leaves capture switched
 * off. Every writer of events runs them through applyCapturePause() before
 * appending:
 *
 *   record paused  ->  nothing is written except pause markers
 *   sync paused    ->  events are written with local_only: true, and every
 *                      upload path leaves them out (outboundEvents())
 *
 * Expiry is settled lazily: the first writer or command that sees an
 * expired entry removes it and writes the capture.resumed marker, stamped
 * with the time the pause actually ended. Two processes can both notice the
 * same expiry; both markers carry the same pause_id, so readers count one.
 *
 * Markers (capture.paused / capture.resumed) belong to no agent session and
 * carry no captured content, so they are never flagged local_only.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import {
  CAPTURE_CONTROL_SESSION_ID,
  SCHEMA_VERSION,
  type CapturePauseKind,
  type CapturePausedEvent,
  type CaptureResumedEvent,
  type TraceEvent,
} from "@omnodex/shared";

export const PAUSE_STATE_FILE = "pause-state.json";

/** Kinds a person can pause from the CLI today. */
export type PausableKind = Extract<CapturePauseKind, "record" | "sync">;
export const PAUSABLE_KINDS: readonly PausableKind[] = ["record", "sync"];

export interface PauseEntry {
  pause_id: string;
  /** ISO 8601. */
  paused_at: string;
  /** ISO 8601, or null for a pause that only a resume ends. */
  until: string | null;
  /** What paused it, e.g. "cli". */
  by: string;
}

export type PauseState = Partial<Record<PausableKind, PauseEntry>>;

function statePath(home: string): string {
  return path.join(home, PAUSE_STATE_FILE);
}

/** The state on disk; empty when the file is missing or unreadable. */
export async function readPauseState(home: string): Promise<PauseState> {
  try {
    const parsed = JSON.parse(await fs.readFile(statePath(home), "utf8")) as Record<string, unknown>;
    const out: PauseState = {};
    for (const kind of PAUSABLE_KINDS) {
      const e = parsed[kind] as Partial<PauseEntry> | undefined;
      if (e && typeof e.pause_id === "string" && typeof e.paused_at === "string") {
        out[kind] = { pause_id: e.pause_id, paused_at: e.paused_at, until: typeof e.until === "string" ? e.until : null, by: typeof e.by === "string" ? e.by : "cli" };
      }
    }
    return out;
  } catch {
    return {};
  }
}

async function writePauseState(home: string, state: PauseState): Promise<void> {
  const file = statePath(home);
  if (Object.keys(state).length === 0) {
    await fs.rm(file, { force: true });
    return;
  }
  await fs.mkdir(home, { recursive: true });
  const tmp = `${file}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2) + "\n");
  await fs.rename(tmp, file);
}

/** Whether an entry is still in force at `now` (unix ms). */
export function pauseActive(entry: PauseEntry | undefined, now: number): boolean {
  if (!entry) return false;
  if (entry.until === null) return true;
  const until = Date.parse(entry.until);
  return Number.isNaN(until) || now < until;
}

/** The entries still in force at `now`. */
export function activePauses(state: PauseState, now = Date.now()): PauseState {
  const out: PauseState = {};
  for (const kind of PAUSABLE_KINDS) {
    const e = state[kind];
    if (e && pauseActive(e, now)) out[kind] = e;
  }
  return out;
}

export function isPauseMarker(event: TraceEvent): boolean {
  return event.event_type === "capture.paused" || event.event_type === "capture.resumed";
}

function markerBase(at: string, now: string) {
  return {
    schema_version: SCHEMA_VERSION,
    event_id: randomUUID(),
    session_id: CAPTURE_CONTROL_SESSION_ID,
    occurred_at: at,
    recorded_at: now,
    interceptor: "analyzer" as const,
  };
}

export function pausedMarker(kind: CapturePauseKind, entry: PauseEntry, nowIso = new Date().toISOString()): CapturePausedEvent {
  return {
    ...markerBase(entry.paused_at, nowIso),
    event_type: "capture.paused",
    pause_id: entry.pause_id,
    kind,
    until: entry.until,
    machine_label: os.hostname(),
  };
}

export function resumedMarker(
  kind: CapturePauseKind,
  entry: PauseEntry,
  reason: CaptureResumedEvent["reason"],
  at: string,
  nowIso = new Date().toISOString(),
): CaptureResumedEvent {
  return {
    ...markerBase(at, nowIso),
    event_type: "capture.resumed",
    pause_id: entry.pause_id,
    kind,
    paused_at: entry.paused_at,
    reason,
    machine_label: os.hostname(),
  };
}

/**
 * Remove entries whose time has run out and return their resumed markers,
 * stamped with the moment each pause ended. Writes the file only when
 * something expired.
 */
export async function settleExpiredPauses(home: string, now = Date.now()): Promise<CaptureResumedEvent[]> {
  const state = await readPauseState(home);
  const markers: CaptureResumedEvent[] = [];
  const next: PauseState = {};
  for (const kind of PAUSABLE_KINDS) {
    const e = state[kind];
    if (!e) continue;
    if (pauseActive(e, now)) next[kind] = e;
    else markers.push(resumedMarker(kind, e, "expired", e.until ?? new Date(now).toISOString()));
  }
  if (markers.length > 0) await writePauseState(home, next);
  return markers;
}

/**
 * Start a pause. Returns the markers to append: the new pause's start, and
 * the end of a pause of the same kind it replaces.
 */
export async function startPause(
  home: string,
  kind: PausableKind,
  opts: { untilMs: number | null; by?: string; now?: number },
): Promise<{ entry: PauseEntry; markers: TraceEvent[] }> {
  const now = opts.now ?? Date.now();
  const nowIso = new Date(now).toISOString();
  const markers: TraceEvent[] = await settleExpiredPauses(home, now);
  const state = await readPauseState(home);
  const prev = state[kind];
  if (prev) markers.push(resumedMarker(kind, prev, "replaced", nowIso, nowIso));
  const entry: PauseEntry = {
    pause_id: randomUUID(),
    paused_at: nowIso,
    until: opts.untilMs === null ? null : new Date(opts.untilMs).toISOString(),
    by: opts.by ?? "cli",
  };
  state[kind] = entry;
  await writePauseState(home, state);
  markers.push(pausedMarker(kind, entry, nowIso));
  return { entry, markers };
}

/**
 * End a pause now. Returns the markers to append (an expired pause's end is
 * included), or an empty list when the kind was not paused.
 */
export async function endPause(home: string, kind: PausableKind, now = Date.now()): Promise<{ ended: PauseEntry | null; markers: TraceEvent[] }> {
  const nowIso = new Date(now).toISOString();
  const markers: TraceEvent[] = await settleExpiredPauses(home, now);
  const state = await readPauseState(home);
  const entry = state[kind] ?? null;
  if (entry) {
    delete state[kind];
    await writePauseState(home, state);
    markers.push(resumedMarker(kind, entry, "command", nowIso, nowIso));
  }
  return { ended: entry, markers };
}

/**
 * The events a writer should append, given the current pauses: pending
 * expiry markers first, then the events (none under a record pause, all
 * flagged local_only under a sync pause). Never throws; on any error the
 * events are returned unchanged, matching the rule that capture never
 * blocks the agent.
 */
export async function applyCapturePause(
  events: TraceEvent[],
  home: string,
  now = Date.now(),
): Promise<TraceEvent[]> {
  try {
    const markers = await settleExpiredPauses(home, now);
    const active = activePauses(await readPauseState(home), now);
    if (active.record) return [...markers, ...events.filter(isPauseMarker)];
    if (active.sync) {
      let flagged = false;
      for (const e of events) {
        if (!isPauseMarker(e)) {
          e.local_only = true;
          flagged = true;
        }
      }
      if (flagged) await markLocalOnlySeen(home);
    }
    return [...markers, ...events];
  } catch {
    return events;
  }
}

/**
 * The events that may leave the machine: no local_only events, and while a
 * record or sync pause is in force, only pause markers. Every upload path
 * runs its events through this, so a writer that missed applyCapturePause
 * still cannot leak an event recorded under a pause.
 */
export async function outboundEvents(events: TraceEvent[], home: string | null, now = Date.now()): Promise<TraceEvent[]> {
  let out = events.filter((e) => !e.local_only);
  if (home && out.length > 0) {
    const active = activePauses(await readPauseState(home), now);
    if (active.record || active.sync) out = out.filter(isPauseMarker);
  }
  return out;
}

/**
 * Marker file: this home has recorded something local-only, so syncs must
 * build their own read model rather than share the local dashboard's.
 */
export const LOCAL_ONLY_SEEN_FILE = "local-only-seen";

export async function markLocalOnlySeen(home: string): Promise<void> {
  const file = path.join(home, LOCAL_ONLY_SEEN_FILE);
  try {
    await fs.access(file);
  } catch {
    await fs.mkdir(home, { recursive: true });
    await fs.writeFile(file, new Date().toISOString() + "\n");
  }
}

export async function localOnlySeen(home: string): Promise<boolean> {
  try {
    await fs.access(path.join(home, LOCAL_ONLY_SEEN_FILE));
    return true;
  } catch {
    return false;
  }
}
