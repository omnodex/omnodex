// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * How advanced-tier findings appear on this machine: the local dashboard,
 * `omnodex detect` and `omnodex report` say how many there are and where
 * they can be read, and nothing else: not their rule, severity, text, or
 * the calls they are about.
 *
 * The detail lives in the hosted dashboard, which comes with the plan that
 * produces these findings. An entitled installation is pointed there; any
 * other is told the finding comes with Pro.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { RiskEventRow, SessionRow } from "@omnodex/projection";
import { riskScoreFor, roundRiskScore } from "@omnodex/shared";

const ENTITLED_TIERS = new Set(["pro", "enterprise"]);

/** Whether this installation's cached license is on a plan that includes advanced findings. */
export function advancedEntitled(home: string): boolean {
  try {
    const cache = JSON.parse(fs.readFileSync(path.join(home, "license-cache.json"), "utf8")) as {
      response?: { tier?: unknown };
    };
    const tier = cache.response?.tier;
    return typeof tier === "string" && ENTITLED_TIERS.has(tier);
  } catch {
    return false;
  }
}

export { advancedFindingsText } from "./dashboard-model/advanced.js";

const isAdvanced = (r: RiskEventRow): boolean => r.rule_tier === "advanced";

/** The findings this machine may list: everything but advanced-tier ones. */
export function shownFindings<T extends RiskEventRow>(rows: readonly T[]): T[] {
  return rows.filter((r) => !isAdvanced(r));
}

/** Advanced findings held back, per session, and what to say about them. */
export interface AdvancedHeldBack {
  hidden: Record<string, number>;
  entitled: boolean;
}

/**
 * A snapshot as this machine may show it. Advanced findings are removed,
 * not masked: a masked row would still point at the call it is about, and
 * the call says much of what the finding does. What remains is a count per
 * session. The sessions that held them are rescored from what is shown, so
 * a score's band does not give a hidden finding's severity away.
 */
export function withoutAdvancedFindings<S extends { sessions: SessionRow[]; risk_events: Record<string, RiskEventRow[]> }>(
  snapshot: S,
  entitled: boolean,
): S & { advanced: AdvancedHeldBack } {
  const hidden: Record<string, number> = {};
  const risk_events: Record<string, RiskEventRow[]> = {};
  for (const [sid, rows] of Object.entries(snapshot.risk_events)) {
    const kept = shownFindings(rows);
    if (kept.length !== rows.length) hidden[sid] = rows.length - kept.length;
    risk_events[sid] = kept;
  }
  const sessions = snapshot.sessions.map((s) =>
    s.session_id in hidden
      ? { ...s, risk_score: roundRiskScore((risk_events[s.session_id] ?? []).reduce((n, r) => n + riskScoreFor(r.severity), 0)) }
      : s);
  return { ...snapshot, sessions, risk_events, advanced: { hidden, entitled } };
}
