// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * Capture pauses for the timeline: each pause folded from its
 * capture.paused and capture.resumed markers into one row. Without them a
 * pause would look the same as data that went missing.
 */

import type { CapturePauseKind, TraceEvent } from "@omnodex/shared";

export interface PauseRow {
  pause_id: string;
  kind: CapturePauseKind;
  paused_at: string;
  /** When it ended; null while it is still in force. */
  resumed_at: string | null;
  /** When it was set to end by itself, if it had a duration. */
  until: string | null;
  /** How it ended: resumed by a person, ran out, or replaced by a new pause. */
  reason: "command" | "expired" | "replaced" | null;
  machine_label: string | null;
}

/**
 * One row per pause, oldest first. A pause can have two end markers when
 * two processes noticed its expiry; the earliest wins. An end marker
 * without its start (the start fell outside the log) still gives a row.
 */
export function pauseRows(events: Iterable<TraceEvent>): PauseRow[] {
  const rows = new Map<string, PauseRow>();
  for (const e of events) {
    if (e.event_type === "capture.paused") {
      const row = rows.get(e.pause_id);
      rows.set(e.pause_id, {
        pause_id: e.pause_id,
        kind: e.kind,
        paused_at: e.occurred_at,
        resumed_at: row?.resumed_at ?? null,
        until: e.until,
        reason: row?.reason ?? null,
        machine_label: e.machine_label ?? row?.machine_label ?? null,
      });
    } else if (e.event_type === "capture.resumed") {
      const row = rows.get(e.pause_id) ?? {
        pause_id: e.pause_id,
        kind: e.kind,
        paused_at: e.paused_at,
        resumed_at: null,
        until: null,
        reason: null,
        machine_label: e.machine_label ?? null,
      };
      if (row.resumed_at === null || e.occurred_at < row.resumed_at) {
        row.resumed_at = e.occurred_at;
        row.reason = e.reason;
      }
      rows.set(e.pause_id, row);
    }
  }
  return [...rows.values()].sort((a, b) => a.paused_at.localeCompare(b.paused_at));
}

/** What a pause stopped, for a timeline label. */
export function pauseLabel(kind: CapturePauseKind): string {
  if (kind === "record") return "Recording paused";
  if (kind === "sync") return "Uploads paused";
  return "Enforcement paused";
}

/** What resuming turned back on. */
export function resumeLabel(kind: CapturePauseKind): string {
  if (kind === "record") return "Recording resumed";
  if (kind === "sync") return "Uploads resumed";
  return "Enforcement resumed";
}

/** Whether a pause overlaps the span [from, to]; an open pause runs to now. */
export function pauseOverlaps(row: PauseRow, from: string, to: string | null): boolean {
  const end = row.resumed_at ?? "9999";
  return row.paused_at <= (to ?? "9999") && end >= from;
}
