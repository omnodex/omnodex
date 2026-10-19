// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- rule signal submission
 *
 * Capture paths append one line per rule signal (a UTC day, a rule id and a
 * kind such as "would_block") to OMNODEX_HOME/rule-signals.jsonl. The
 * background pass, under the auto-sync lock, moves those lines into
 * rule-signals.json as per-day, per-rule, per-kind counts, and submits them
 * to POST /api/v1/usage/rules at most once every SUBMIT_INTERVAL_MS.
 *
 * Rule ids and counts only: no paths, commands, destinations or other
 * content ever go in either file or over the wire. A machine without an
 * API token (not connected to a dashboard) never sends anything.
 *
 * A submission keeps its batch_id until the server accepts it, so a retry
 * after a lost answer is not counted twice. Counts older than MAX_AGE_DAYS
 * are dropped rather than sent late.
 */

import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { MAX_AGE_DAYS, SUBMIT_INTERVAL_MS } from "./advanced-usage.js";

export const RULE_SIGNALS_LOG = "rule-signals.jsonl";
export const RULE_SIGNALS_FILE = "rule-signals.json";
const REQUEST_TIMEOUT_MS = 10_000;
/** Longest rule id or kind accepted from the log; anything longer is not ours. */
const MAX_KEY_CHARS = 128;

/** One count: a rule's signals of one kind on one UTC day. */
export interface RuleSignalCount {
  day: string;
  rule_id: string;
  kind: string;
  count: number;
}

export interface RuleSignalsState {
  version: 1;
  /** Counted, not yet sent, keyed "day|rule_id|kind". */
  pending: Record<string, number>;
  in_flight?: { batch_id: string; counts: Record<string, number> };
  last_attempt_at?: string;
  last_submitted_at?: string;
  last_error?: string | null;
  dropped?: { counts: number; last_at: string };
}

const dayOf = (now: number) => new Date(now).toISOString().slice(0, 10);
const key = (day: string, ruleId: string, kind: string) => `${day}|${ruleId}|${kind}`;

function unkey(k: string, count: number): RuleSignalCount {
  const [day = "", rule_id = "", kind = ""] = k.split("|");
  return { day, rule_id, kind, count };
}

export async function readRuleSignals(home: string): Promise<RuleSignalsState> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(home, RULE_SIGNALS_FILE), "utf8")) as Partial<RuleSignalsState>;
    if (parsed?.version === 1 && parsed.pending && typeof parsed.pending === "object") return parsed as RuleSignalsState;
  } catch {
    // Missing or unreadable: nothing pending.
  }
  return { version: 1, pending: {} };
}

async function writeRuleSignals(home: string, state: RuleSignalsState): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  const file = path.join(home, RULE_SIGNALS_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2) + "\n");
  await fs.rename(tmp, file);
}

function validKey(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= MAX_KEY_CHARS && !v.includes("|");
}

function pruneOld(state: RuleSignalsState, counts: Record<string, number>, now: number): void {
  const oldest = dayOf(now - MAX_AGE_DAYS * 86_400_000);
  let dropped = 0;
  for (const k of Object.keys(counts)) {
    if (k.slice(0, 10) < oldest) {
      dropped += counts[k]!;
      delete counts[k];
    }
  }
  if (dropped > 0) {
    state.dropped = { counts: (state.dropped?.counts ?? 0) + dropped, last_at: new Date(now).toISOString() };
  }
}

/**
 * Move the capture paths' signal lines into the pending counts. The log is
 * renamed before it is read, so lines appended meanwhile start a new log
 * rather than being lost. Returns how many lines were taken.
 */
export async function collectRuleSignals(home: string, now = Date.now()): Promise<number> {
  const log = path.join(home, RULE_SIGNALS_LOG);
  const taking = `${log}.${process.pid}.collect`;
  try {
    await fs.rename(log, taking);
  } catch {
    return 0;
  }
  let text = "";
  try {
    text = await fs.readFile(taking, "utf8");
  } finally {
    await fs.unlink(taking).catch(() => undefined);
  }
  const state = await readRuleSignals(home);
  let taken = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    const { day, rule_id, kind } = (parsed ?? {}) as Record<string, unknown>;
    if (typeof day !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(day) || !validKey(rule_id) || !validKey(kind)) continue;
    const k = key(day, rule_id, kind);
    state.pending[k] = (state.pending[k] ?? 0) + 1;
    taken++;
  }
  pruneOld(state, state.pending, now);
  await writeRuleSignals(home, state);
  return taken;
}

export type SubmitOutcome = "nothing" | "too-soon" | "submitted" | "refused" | "failed";

export interface SubmitRuleSignalsOptions {
  apiUrl: string;
  apiToken: string;
  now?: number;
  fetchFn?: typeof fetch;
}

/**
 * Send what is pending (or resend what is in flight). Never throws; a
 * network or server failure keeps the counts for the next pass.
 */
export async function submitRuleSignals(home: string, opts: SubmitRuleSignalsOptions): Promise<SubmitOutcome> {
  const now = opts.now ?? Date.now();
  const state = await readRuleSignals(home);
  if (!state.in_flight && Object.keys(state.pending).length === 0) return "nothing";
  const last = state.last_attempt_at ? Date.parse(state.last_attempt_at) : NaN;
  if (!Number.isNaN(last) && now - last < SUBMIT_INTERVAL_MS) return "too-soon";

  if (state.in_flight) {
    pruneOld(state, state.in_flight.counts, now);
    if (Object.keys(state.in_flight.counts).length === 0) delete state.in_flight;
  }
  if (!state.in_flight) {
    pruneOld(state, state.pending, now);
    if (Object.keys(state.pending).length === 0) {
      await writeRuleSignals(home, state);
      return "nothing";
    }
    state.in_flight = { batch_id: randomUUID(), counts: state.pending };
    state.pending = {};
  }
  state.last_attempt_at = new Date(now).toISOString();
  // Recorded before sending, so a crash mid-request resends the same batch.
  await writeRuleSignals(home, state);

  const batch = state.in_flight;
  const counts = Object.entries(batch.counts).map(([k, n]) => unkey(k, n));
  let outcome: SubmitOutcome;
  try {
    const res = await (opts.fetchFn ?? fetch)(`${opts.apiUrl.replace(/\/$/, "")}/api/v1/usage/rules`, {
      method: "POST",
      headers: { Authorization: `Bearer ${opts.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ batch_id: batch.batch_id, counts }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.ok) {
      outcome = "submitted";
      state.last_submitted_at = new Date(now).toISOString();
      state.last_error = null;
      delete state.in_flight;
    } else if (res.status === 400 || res.status === 403) {
      // Malformed, or the account may not submit: never accepted as is.
      outcome = "refused";
      state.last_error = `HTTP ${res.status}`;
      state.dropped = {
        counts: (state.dropped?.counts ?? 0) + counts.reduce((n, c) => n + c.count, 0),
        last_at: new Date(now).toISOString(),
      };
      delete state.in_flight;
    } else {
      outcome = "failed";
      state.last_error = `HTTP ${res.status}`;
    }
  } catch (err) {
    outcome = "failed";
    state.last_error = (err as Error)?.message ?? String(err);
  }
  // Only the background child, under the auto-sync lock, writes this file.
  await writeRuleSignals(home, state);
  return outcome;
}
