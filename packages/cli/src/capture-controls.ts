// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex record pause|resume` and `omnodex sync pause|resume`.
 *
 *   record pause  nothing is captured on this machine, and nothing uploaded
 *   sync pause    events are still captured and shown in the local
 *                 dashboard, but stay on this machine for good
 *
 * Pausing is for a person, not an agent: it needs an interactive terminal
 * and a typed confirmation, which an agent's shell tool cannot give.
 * Resuming only turns capture back on, so it needs neither.
 */

import * as path from "node:path";
import * as readline from "node:readline/promises";
import {
  EventLog,
  activePauses,
  endPause,
  readPauseState,
  settleExpiredPauses,
  startPause,
} from "@omnodex/event-log";
import type { PausableKind, PauseEntry } from "@omnodex/event-log";
import type { TraceEvent } from "@omnodex/shared";

const UNIT_MS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/** Longest pause a duration may ask for. A pause with no duration has no limit. */
export const MAX_PAUSE_MS = 30 * UNIT_MS.d!;

/**
 * "30m", "1h", "2d", "90s", or combinations such as "1h30m", in ms.
 * null for anything else.
 */
export function parseDuration(text: string): number | null {
  const trimmed = text.trim().toLowerCase();
  if (!/^(\d+[smhd])+$/.test(trimmed)) return null;
  let total = 0;
  for (const [, n, unit] of trimmed.matchAll(/(\d+)([smhd])/g)) total += Number(n) * UNIT_MS[unit!]!;
  return total > 0 && total <= MAX_PAUSE_MS ? total : null;
}

/** "1h", "2d 3h", "45m": a short form of a duration for messages. */
export function formatDuration(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60_000));
  const d = Math.floor(minutes / 1440);
  const h = Math.floor((minutes % 1440) / 60);
  const m = minutes % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(" ");
}

/** What each pause does, in one clause each, for every message about it. */
export const PAUSE_EFFECT: Record<PausableKind, string> = {
  record: "nothing is captured or uploaded on this machine",
  sync:
    "events are still captured and shown in the local dashboard, but stay on this machine " +
    "and will not be uploaded, even after you resume",
};

/** One line describing a kind's state, for `omnodex status` and the commands. */
export function describePause(kind: PausableKind, entry: PauseEntry | undefined, now = Date.now()): string {
  if (!entry) return "on";
  if (entry.until === null) return `paused since ${entry.paused_at}, until resumed: ${PAUSE_EFFECT[kind]}`;
  const left = Date.parse(entry.until) - now;
  return `paused until ${entry.until} (${formatDuration(left)} left): ${PAUSE_EFFECT[kind]}`;
}

export interface ControlIo {
  stdinIsTTY: boolean;
  stdoutIsTTY: boolean;
  /** Ask a question and return the answer. */
  ask(question: string): Promise<string>;
  log(line: string): void;
  error(line: string): void;
}

export function processIo(): ControlIo {
  return {
    stdinIsTTY: Boolean(process.stdin.isTTY),
    stdoutIsTTY: Boolean(process.stdout.isTTY),
    async ask(question) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(question);
      } finally {
        rl.close();
      }
    },
    log: (line) => console.log(line),
    error: (line) => console.error(line),
  };
}

export interface ControlOptions {
  home: string;
  io: ControlIo;
  /** Sends markers to the hosted dashboard; best effort. */
  push?: (events: TraceEvent[], home: string) => Promise<unknown>;
  now?: number;
}

async function appendMarkers(home: string, markers: TraceEvent[], push: ControlOptions["push"]): Promise<void> {
  if (markers.length === 0) return;
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  try {
    for (const m of markers) await log.append(m);
  } finally {
    await log.close();
  }
  await push?.(markers, home).catch(() => undefined);
}

const USAGE: Record<PausableKind, string> = {
  record: "omnodex record pause [duration] | resume | status",
  sync: "omnodex sync pause [duration] | resume | status",
};

/**
 * Run `omnodex <kind> <sub> [duration]`. Returns the exit code.
 */
export async function runCaptureControl(
  kind: PausableKind,
  args: string[],
  opts: ControlOptions,
): Promise<number> {
  const { home, io } = opts;
  const now = opts.now ?? Date.now();
  const positional = args.filter((a) => !a.startsWith("--"));
  const sub = positional[0] ?? "status";
  const tag = `[${kind}]`;

  if (sub === "status") {
    const markers = await settleExpiredPauses(home, now);
    await appendMarkers(home, markers, opts.push);
    const entry = activePauses(await readPauseState(home), now)[kind];
    io.log(`${tag} ${home}: ${describePause(kind, entry, now)}`);
    return 0;
  }

  if (sub === "resume") {
    const { ended, markers } = await endPause(home, kind, now);
    await appendMarkers(home, markers, opts.push);
    io.log(
      ended
        ? `${tag} resumed in ${home}: ${kind === "record" ? "capture is back on" : "new events upload again"}.`
        : `${tag} was not paused in ${home}.`,
    );
    if (ended && kind === "sync") {
      io.log(`${tag} events recorded while uploads were paused stay on this machine.`);
    }
    return 0;
  }

  if (sub !== "pause") {
    io.error(`${tag} unknown subcommand '${sub}'. Usage: ${USAGE[kind]}`);
    return 1;
  }

  const durationArg = positional[1];
  const durationMs = durationArg === undefined ? null : parseDuration(durationArg);
  if (durationArg !== undefined && durationMs === null) {
    io.error(`${tag} '${durationArg}' is not a duration. Use forms like 30m, 1h, 2d or 1h30m (up to 30d).`);
    return 1;
  }

  // Human only: an agent running this through a shell has no terminal.
  if (!io.stdinIsTTY || !io.stdoutIsTTY) {
    io.error(
      `${tag} pausing needs a person at an interactive terminal, so an agent cannot switch Omnodex off. ` +
        `Run \`omnodex ${kind} pause\` yourself in a terminal.`,
    );
    return 1;
  }
  const span = durationMs === null ? "until you resume it" : `for ${formatDuration(durationMs)}`;
  io.log(`${tag} pausing ${span}: ${PAUSE_EFFECT[kind]}.`);
  const answer = (await io.ask(`${tag} type "pause" to confirm: `)).trim().toLowerCase();
  if (answer !== "pause") {
    io.log(`${tag} not paused.`);
    return 1;
  }

  const { entry, markers } = await startPause(home, kind, {
    untilMs: durationMs === null ? null : now + durationMs,
    by: "cli",
    now,
  });
  await appendMarkers(home, markers, opts.push);
  io.log(`${tag} ${describePause(kind, entry, now)}.`);
  io.log(`${tag} resume early with \`omnodex ${kind} resume\`. This applies to ${home} only.`);
  return 0;
}

/** Lines for `omnodex status`: each pausable kind, settling expired pauses first. */
export async function captureStatusLines(home: string, now = Date.now()): Promise<{ lines: string[]; markers: TraceEvent[] }> {
  const markers = await settleExpiredPauses(home, now);
  const active = activePauses(await readPauseState(home), now);
  const lines = [
    `[status] recording:    ${describePause("record", active.record, now)}`,
    `[status] uploads:      ${describePause("sync", active.sync, now)}`,
  ];
  return { lines, markers };
}

export { appendMarkers };
