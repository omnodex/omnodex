// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Capture pauses as seen by agents: read the state, and resume.
 *
 * There is deliberately no tool to pause. Pausing switches Omnodex off, so
 * only a person can do it, at a terminal (`omnodex record pause`, `omnodex
 * sync pause`). Resuming only turns capture back on, so an agent may.
 */

import * as os from "node:os";
import * as path from "node:path";
import {
  PAUSABLE_KINDS,
  activePauses,
  endPause,
  readPauseState,
  settleExpiredPauses,
} from "@omnodex/event-log";
import type { PausableKind, PauseEntry } from "@omnodex/event-log";
import type { EmitFn } from "@omnodex/shared";

export function captureHome(): string {
  return process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
}

export interface CaptureSwitch {
  state: "on" | "paused";
  paused_at?: string;
  /** When the pause ends by itself; null when only a resume ends it. */
  until?: string | null;
  effect?: string;
}

const EFFECT: Record<PausableKind, string> = {
  record: "nothing is captured or uploaded on this machine",
  sync: "events are captured locally but never uploaded",
};

function describe(kind: PausableKind, entry: PauseEntry | undefined): CaptureSwitch {
  if (!entry) return { state: "on" };
  return { state: "paused", paused_at: entry.paused_at, until: entry.until, effect: EFFECT[kind] };
}

/** The recording and upload switches, writing any expired pause's end marker. */
export async function captureStatus(home: string, emit: EmitFn): Promise<{ recording: CaptureSwitch; uploads: CaptureSwitch }> {
  for (const marker of await settleExpiredPauses(home)) await emit(marker);
  const active = activePauses(await readPauseState(home));
  return { recording: describe("record", active.record), uploads: describe("sync", active.sync) };
}

export const RESUME_TOOL = {
  name: "omnodex_resume",
  description:
    "Turns Omnodex capture back on after a person paused it: kind \"record\" resumes " +
    "recording, kind \"sync\" resumes uploads. Only resumes; pausing can only be done " +
    "by a person at a terminal.",
  inputSchema: {
    type: "object" as const,
    properties: {
      kind: { type: "string", enum: [...PAUSABLE_KINDS], description: "What to resume: record or sync" },
    },
    required: ["kind"],
  },
};

export async function handleResume(
  args: Record<string, unknown>,
  home: string,
  emit: EmitFn,
): Promise<{ status: "resumed" | "not_paused" | "invalid"; kind?: PausableKind; message: string }> {
  const kind = args.kind;
  if (kind !== "record" && kind !== "sync") {
    return { status: "invalid", message: 'kind must be "record" or "sync"' };
  }
  const { ended, markers } = await endPause(home, kind);
  for (const marker of markers) await emit(marker);
  if (!ended) return { status: "not_paused", kind, message: `${kind} was not paused` };
  return {
    status: "resumed",
    kind,
    message: kind === "record" ? "recording resumed" : "uploads resumed; events recorded while paused stay on this machine",
  };
}
