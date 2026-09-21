// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * detectEventLogs -- run detection over whole event logs on disk.
 *
 * Opens each event log root, runs detectRisks() over every session (or one
 * named session), and appends new risk.detected events to the session they
 * belong to. Idempotent: detectRisks() skips findings already in the log, so
 * a second run over unchanged data appends nothing.
 *
 * With a state file, sessions whose file has not grown since the last run
 * are skipped without being read. That is what lets the background pass run
 * at every session end without rescanning a long history each time. The
 * recorded size is taken before the session is read, so events appended
 * while a run is in progress, including the run's own findings, only cause
 * one extra rescan next time, never a missed event.
 *
 * runBackgroundDetect() is the entry point for the detached background
 * child that hook shims and the MCP proxy start (see startBackgroundSync in
 * @omnodex/sync-encryptor).
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { EventLog, newEventId as defaultNewEventId } from "@omnodex/event-log";
import type { RiskDetectedEvent } from "@omnodex/shared";
import { detectRisks } from "./detect.js";
import type { RuleRegistry } from "./registry.js";

/** Watermark file written under OMNODEX_HOME by the background pass. */
export const DETECT_STATE_FILE = "detect-state.json";

export interface DetectLogOptions {
  /** Event log root directories (each holding index.jsonl and sessions/). */
  roots: string[];
  /** Evaluate only this session. Omit to evaluate every session. */
  sessionId?: string;
  /**
   * Watermark file. When set, sessions whose file size is unchanged since
   * the recorded run are skipped, and the file is updated afterwards.
   * Omit for a full scan (the `omnodex detect` behaviour).
   */
  statePath?: string;
  newEventId?: () => string;
  registry?: RuleRegistry;
  /** Called once per evaluated session, for progress output. */
  onSession?: (report: SessionDetectReport) => void;
}

export interface SessionDetectReport {
  root: string;
  sessionId: string;
  newEvents: RiskDetectedEvent[];
  skipped: number;
}

export interface DetectLogResult {
  /** Sessions read and evaluated. */
  scanned: number;
  /** Sessions skipped because their file had not changed. */
  unchanged: number;
  /** Findings appended by this run, across all roots. */
  newEvents: RiskDetectedEvent[];
  /** Findings that were already in the log. */
  skipped: number;
}

interface DetectState {
  version: 1;
  last_run_at?: string;
  /** Per root, per session: file size in bytes when last evaluated. */
  sessions: Record<string, Record<string, number>>;
}

export async function detectEventLogs(opts: DetectLogOptions): Promise<DetectLogResult> {
  const newEventId = opts.newEventId ?? defaultNewEventId;
  const state = opts.statePath ? await readState(opts.statePath) : null;
  const result: DetectLogResult = { scanned: 0, unchanged: 0, newEvents: [], skipped: 0 };

  for (const root of opts.roots) {
    // A root with no index has no sessions. Skip it rather than init() it,
    // which would create an empty log on a home that has never recorded.
    if ((await fileSize(path.join(root, "index.jsonl"))) === null) continue;
    const log = new EventLog({ root });
    await log.init();
    const seen = state ? (state.sessions[root] ??= {}) : null;
    try {
      const all = await log.listSessions();
      const sessionIds = opts.sessionId ? all.filter((id) => id === opts.sessionId) : all;

      for (const sessionId of sessionIds) {
        const size = await fileSize(log.sessionFilePath(sessionId));
        if (seen && size !== null && seen[sessionId] === size) {
          result.unchanged++;
          continue;
        }

        const events = await log.readSession(sessionId);
        if (events.length > 0) {
          result.scanned++;
          const detection = detectRisks(events, newEventId, opts.registry);
          result.skipped += detection.skipped;
          if (detection.newEvents.length > 0) {
            await log.appendMany(detection.newEvents);
            result.newEvents.push(...detection.newEvents);
          }
          opts.onSession?.({
            root,
            sessionId,
            newEvents: detection.newEvents,
            skipped: detection.skipped,
          });
        }
        if (seen && size !== null) seen[sessionId] = size;
      }
    } finally {
      await log.close();
    }
  }

  if (state && opts.statePath) {
    state.last_run_at = new Date().toISOString();
    await writeState(opts.statePath, state);
  }
  return result;
}

/**
 * One background detection pass over this installation's event log.
 * Returns the findings it appended, so the caller can push them to the live
 * relay. Covers the same log the background sync uploads.
 */
export async function runBackgroundDetect(
  home: string,
  opts: { newEventId?: () => string; registry?: RuleRegistry } = {},
): Promise<RiskDetectedEvent[]> {
  const result = await detectEventLogs({
    roots: [path.join(home, "event-log")],
    statePath: path.join(home, DETECT_STATE_FILE),
    newEventId: opts.newEventId,
    registry: opts.registry,
  });
  return result.newEvents;
}

// ---------------------------------------------------------------------------
// State file
// ---------------------------------------------------------------------------

async function fileSize(file: string): Promise<number | null> {
  try {
    return (await fs.stat(file)).size;
  } catch {
    return null;
  }
}

async function readState(file: string): Promise<DetectState> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as Partial<DetectState>;
    if (parsed && parsed.version === 1 && parsed.sessions && typeof parsed.sessions === "object") {
      return { version: 1, last_run_at: parsed.last_run_at, sessions: parsed.sessions };
    }
  } catch {
    // Missing or unreadable: start over, which costs one full scan.
  }
  return { version: 1, sessions: {} };
}

async function writeState(file: string, state: DetectState): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  // Write then rename, so a crash mid-write never leaves a torn file.
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state) + "\n");
  await fs.rename(tmp, file);
}
