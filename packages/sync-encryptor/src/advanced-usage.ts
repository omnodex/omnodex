// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- advanced rule usage counter
 *
 * Advanced (Pro) rules run on this machine, so their usage is counted here:
 * the background pass adds each run's count of tool calls judged by at least
 * one advanced rule, and of advanced findings, to
 * OMNODEX_HOME/advanced-usage.json, by UTC day. Counts only: no rule ids,
 * paths or content ever go in the file or over the wire.
 *
 * The same pass submits the counts to POST /api/v1/usage/advanced, at most
 * once every SUBMIT_INTERVAL_MS. A submission keeps its batch_id until the
 * server accepts it, so a retry after a lost answer is not counted twice.
 * Offline, counts wait, but not forever: days older than MAX_AGE_DAYS are
 * dropped rather than billed late, and the drop is recorded so
 * `omnodex status` can show it. Both writers run in the background child
 * under the auto-sync lock, so the file has one writer at a time.
 */

import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

export const ADVANCED_USAGE_FILE = "advanced-usage.json";
/** Submissions are at least this far apart per machine. */
export const SUBMIT_INTERVAL_MS = 15 * 60 * 1000;
/** Days older than this are dropped instead of submitted. */
export const MAX_AGE_DAYS = 7;
const REQUEST_TIMEOUT_MS = 10_000;

export interface DayCounts {
  evaluated: number;
  findings: number;
}

export interface AdvancedUsageState {
  version: 1;
  /** Counted, not yet sent: UTC day to counts. */
  pending: Record<string, DayCounts>;
  /** Sent and not yet acknowledged; resent with the same batch_id. */
  in_flight?: { batch_id: string; days: Record<string, DayCounts> };
  last_attempt_at?: string;
  last_submitted_at?: string;
  last_error?: string | null;
  /** Counts dropped as too old, or refused because the plan lacks advanced rules. */
  dropped?: { evaluated: number; days: number; last_at: string };
}

const dayOf = (now: number) => new Date(now).toISOString().slice(0, 10);

export async function readAdvancedUsage(home: string): Promise<AdvancedUsageState> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(home, ADVANCED_USAGE_FILE), "utf8")) as Partial<AdvancedUsageState>;
    if (parsed?.version === 1 && parsed.pending && typeof parsed.pending === "object") {
      return parsed as AdvancedUsageState;
    }
  } catch {
    // Missing or unreadable: nothing pending.
  }
  return { version: 1, pending: {} };
}

async function writeAdvancedUsage(home: string, state: AdvancedUsageState): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  // Write then rename, so a crash mid-write never leaves a torn file.
  const file = path.join(home, ADVANCED_USAGE_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2) + "\n");
  await fs.rename(tmp, file);
}

function drop(state: AdvancedUsageState, days: Record<string, DayCounts>, now: number): void {
  const entries = Object.values(days);
  if (entries.length === 0) return;
  state.dropped = {
    evaluated: (state.dropped?.evaluated ?? 0) + entries.reduce((n, d) => n + d.evaluated, 0),
    days: (state.dropped?.days ?? 0) + entries.length,
    last_at: new Date(now).toISOString(),
  };
}

/** Move days older than MAX_AGE_DAYS out of `days` into the dropped tally. */
function pruneOld(state: AdvancedUsageState, days: Record<string, DayCounts>, now: number): void {
  const oldest = dayOf(now - MAX_AGE_DAYS * 86_400_000);
  const old: Record<string, DayCounts> = {};
  for (const day of Object.keys(days)) {
    if (day < oldest) {
      old[day] = days[day]!;
      delete days[day];
    }
  }
  drop(state, old, now);
}

/** Add one background pass's counts to today's pending total. */
export async function addAdvancedUsage(home: string, counts: DayCounts, now = Date.now()): Promise<void> {
  if (counts.evaluated <= 0 && counts.findings <= 0) return;
  const state = await readAdvancedUsage(home);
  const day = dayOf(now);
  const current = state.pending[day] ?? { evaluated: 0, findings: 0 };
  state.pending[day] = {
    evaluated: current.evaluated + Math.max(0, counts.evaluated),
    findings: current.findings + Math.max(0, counts.findings),
  };
  pruneOld(state, state.pending, now);
  await writeAdvancedUsage(home, state);
}

export type SubmitOutcome = "nothing" | "too-soon" | "submitted" | "refused" | "failed";

export interface SubmitOptions {
  apiUrl: string;
  apiToken: string;
  now?: number;
  fetchFn?: typeof fetch;
}

/**
 * Send what is pending (or resend what is in flight). Never throws; a
 * network or server failure keeps the counts for the next pass.
 */
export async function submitAdvancedUsage(home: string, opts: SubmitOptions): Promise<SubmitOutcome> {
  const now = opts.now ?? Date.now();
  const state = await readAdvancedUsage(home);
  if (!state.in_flight && Object.keys(state.pending).length === 0) return "nothing";
  const last = state.last_attempt_at ? Date.parse(state.last_attempt_at) : NaN;
  if (!Number.isNaN(last) && now - last < SUBMIT_INTERVAL_MS) return "too-soon";

  // A batch in flight too long (offline for a week) is dropped, and the
  // counts waiting behind it go out instead.
  if (state.in_flight) {
    pruneOld(state, state.in_flight.days, now);
    if (Object.keys(state.in_flight.days).length === 0) delete state.in_flight;
  }
  if (!state.in_flight) {
    pruneOld(state, state.pending, now);
    if (Object.keys(state.pending).length === 0) {
      await writeAdvancedUsage(home, state);
      return "nothing";
    }
    state.in_flight = { batch_id: randomUUID(), days: state.pending };
    state.pending = {};
  }
  state.last_attempt_at = new Date(now).toISOString();
  // Recorded before sending, so a crash mid-request resends the same batch.
  await writeAdvancedUsage(home, state);

  const batch = state.in_flight;
  const days = Object.entries(batch.days).map(([day, c]) => ({ day, evaluated: c.evaluated, findings: c.findings }));
  let outcome: SubmitOutcome;
  try {
    const res = await (opts.fetchFn ?? fetch)(`${opts.apiUrl.replace(/\/$/, "")}/api/v1/usage/advanced`, {
      method: "POST",
      headers: { Authorization: `Bearer ${opts.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ batch_id: batch.batch_id, days }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.ok) {
      outcome = "submitted";
      state.last_submitted_at = new Date(now).toISOString();
      state.last_error = null;
      delete state.in_flight;
    } else if (res.status === 400 || res.status === 403) {
      // Malformed (never retried as is) or the plan has no advanced rules:
      // these counts will never be accepted.
      outcome = "refused";
      state.last_error = `HTTP ${res.status}`;
      drop(state, batch.days, now);
      delete state.in_flight;
    } else {
      outcome = "failed";
      state.last_error = `HTTP ${res.status}`;
    }
  } catch (err) {
    outcome = "failed";
    state.last_error = (err as Error)?.message ?? String(err);
  }
  // Only the background child, under the auto-sync lock, writes this file,
  // so nothing else changed it while the request was out.
  await writeAdvancedUsage(home, state);
  return outcome;
}
