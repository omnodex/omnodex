// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Rule signals: per-rule counts of what enforcement made of findings, so
 * the rules that would stop calls can be chosen from more than one machine.
 *
 * Each capture path appends one line per signal to
 * OMNODEX_HOME/rule-signals.jsonl: the UTC day, a rule id and a kind. No
 * paths, commands, destinations or other content, ever. The background pass
 * totals the lines and submits the counts (see the sync package).
 *
 * Kinds:
 *   would_block  the finding would have stopped or held its call, by the
 *                rule's own hint or the user's settings (muted findings
 *                never count)
 *   in_force     the user's settings make it stop or hold the call
 *   held         the call was actually stopped or held (guardrails)
 *
 * Only findings that may leave the machine count: nothing recorded under a
 * record or sync pause adds a signal. Appending a short line is atomic for
 * concurrent hook processes, so no lock is needed here. Never throws.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { outboundEvents } from "@omnodex/event-log";
import { wouldBlock, type RiskDetectedEvent } from "@omnodex/shared";

export const RULE_SIGNALS_LOG = "rule-signals.jsonl";

export type RuleSignalKind = "would_block" | "in_force" | "held";

export interface RuleSignalLine {
  day: string;
  rule_id: string;
  kind: RuleSignalKind;
}

/** The signal lines a batch of stamped findings gives. */
export function signalLines(findings: readonly RiskDetectedEvent[], now = Date.now()): RuleSignalLine[] {
  const day = new Date(now).toISOString().slice(0, 10);
  const lines: RuleSignalLine[] = [];
  for (const f of findings) {
    const e = f.enforcement;
    if (!e || !wouldBlock(e)) continue;
    lines.push({ day, rule_id: f.rule_id, kind: "would_block" });
    if (e.action !== "alert_only") lines.push({ day, rule_id: f.rule_id, kind: "in_force" });
    if (e.held) lines.push({ day, rule_id: f.rule_id, kind: "held" });
  }
  return lines;
}

/** Append the signals for stamped findings. Never throws. */
export async function appendRuleSignals(
  home: string,
  findings: readonly RiskDetectedEvent[],
  now = Date.now(),
): Promise<void> {
  try {
    const outbound = (await outboundEvents([...findings], home)) as RiskDetectedEvent[];
    const lines = signalLines(outbound, now);
    if (lines.length === 0) return;
    await fs.mkdir(home, { recursive: true });
    await fs.appendFile(path.join(home, RULE_SIGNALS_LOG), lines.map((l) => JSON.stringify(l) + "\n").join(""));
  } catch {
    // Counts are best effort; the finding itself is already in the log.
  }
}
