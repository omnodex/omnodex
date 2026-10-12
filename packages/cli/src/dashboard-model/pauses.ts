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

import type { CapturePauseKind, CapturePauseRow as PauseRow } from "@omnodex/shared";

// The fold lives in shared, so sync uploads the same rows the page shows.
export type { CapturePauseRow as PauseRow } from "@omnodex/shared";
export { capturePauseRows as pauseRows } from "@omnodex/shared";

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
