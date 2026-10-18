// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * How advanced-tier findings appear on this machine: the local dashboard,
 * `omnodex detect` and `omnodex report` show their severity and a pointer
 * to where they can be read, never their detail. Counts and risk scores
 * are unchanged, because the rows are still there.
 *
 * The detail lives in the hosted dashboard, which comes with the plan that
 * produces these findings. An entitled installation is pointed there; any
 * other is told the finding comes with Pro.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { RiskEventRow } from "@omnodex/projection";

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

/** What an advanced finding says on this machine. */
export function advancedFindingText(entitled: boolean): string {
  return entitled
    ? "Advanced finding. Open your Omnodex dashboard to see it."
    : "Advanced finding, available with Omnodex Pro.";
}

/**
 * A finding as this machine may show it. Community findings pass through;
 * an advanced one keeps its severity, timing and call, and loses its
 * category, description, rule, sequence and evidence. Its rule id becomes
 * an opaque one, distinct per rule, so two advanced findings on one call
 * stay two rows.
 */
export function lockAdvancedFinding<T extends RiskEventRow>(row: T, entitled: boolean): T {
  if (row.rule_tier !== "advanced") return row;
  const { evidence: _evidence, related_event_ids: _related, ...rest } = row;
  return {
    ...rest,
    category: "advanced",
    description: advancedFindingText(entitled),
    rule_id: `advanced-${createHash("sha256").update(row.rule_id).digest("hex").slice(0, 8)}`,
  } as T;
}

/** Every finding in a snapshot, as this machine may show it. */
export function lockAdvancedFindings<S extends { risk_events: Record<string, RiskEventRow[]> }>(
  snapshot: S,
  entitled: boolean,
): S {
  let changed = false;
  const risk_events: Record<string, RiskEventRow[]> = {};
  for (const [sid, rows] of Object.entries(snapshot.risk_events)) {
    risk_events[sid] = rows.map((r) => {
      const locked = lockAdvancedFinding(r, entitled);
      if (locked !== r) changed = true;
      return locked;
    });
  }
  return changed ? { ...snapshot, risk_events } : snapshot;
}
