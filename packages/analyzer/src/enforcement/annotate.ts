// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Stamping findings with what enforcement made of them.
 *
 * A capture path (a hook shim, the MCP proxy) calls this with the findings
 * it has just produced and the events it has just written. Each finding
 * gets an `enforcement` field naming the mode, the rule's candidate verdict
 * and the verdict the user's settings give, so shadow mode needs no event
 * type of its own: the record travels wherever the finding goes.
 *
 * Nothing is stamped in monitor mode, and a finding with nothing to say
 * (alert_only on both counts, no mute) is left as it was. Any failure
 * leaves the findings unstamped: this must never cost the finding itself.
 */

import type { EnforcementMode, FindingEnforcement, RiskDetectedEvent, ToolInvokedEvent, TraceEvent } from "@omnodex/shared";
import { COMMUNITY_RULES } from "../rules/index.js";
import { loadEnforcement, type LoadedEnforcement } from "./config.js";
import { blocks, resolveVerdict, type Verdict, type VerdictRule } from "./resolve-verdict.js";

let communityById: Map<string, VerdictRule> | null = null;

function communityRule(id: string): VerdictRule | undefined {
  communityById ??= new Map(COMMUNITY_RULES.map((r) => [r.rule_id, r]));
  return communityById.get(id);
}

export interface AnnotateOptions {
  /** OMNODEX_HOME. */
  home?: string;
  /** Loaded configuration. Read per working directory when absent. */
  loaded?: (cwd: string | undefined) => LoadedEnforcement;
  /** Rule lookup. Defaults to the community rules; unknown rules resolve on overrides only. */
  rule?: (id: string) => VerdictRule | undefined;
  /** Whether the call was stopped or held. Only guardrails sets this. */
  held?: (verdict: Verdict) => boolean;
  /** Error reporting. Defaults to silence. */
  onError?: (err: unknown) => void;
}

/** The verdict for one finding on one call, under the loaded configuration. */
export function verdictFor(
  finding: RiskDetectedEvent,
  call: ToolInvokedEvent | undefined,
  loaded: LoadedEnforcement,
  rule: (id: string) => VerdictRule | undefined = communityRule,
): Verdict {
  const known = rule(finding.rule_id);
  return resolveVerdict({
    // An unknown rule (an advanced one, say) still answers to overrides.
    rule: known ?? { rule_id: finding.rule_id, severity: finding.severity },
    call,
    config: loaded,
    description: finding.description,
  });
}

/** The enforcement record for a verdict, or undefined when it has nothing to say. */
export function enforcementRecord(
  mode: EnforcementMode,
  verdict: Verdict,
  held = false,
): FindingEnforcement | undefined {
  if (mode === "monitor") return undefined;
  if (!blocks(verdict.candidate) && !blocks(verdict.action) && !verdict.muted) return undefined;
  return {
    mode,
    candidate: verdict.candidate,
    action: verdict.action,
    held: mode === "guardrails" && held,
    source: verdict.source,
    ...(verdict.muted ? { muted: true } : {}),
  };
}

/**
 * The findings, each stamped with its enforcement record where it has one.
 * Returns the same array when nothing changes.
 */
export function annotateFindings(
  findings: RiskDetectedEvent[],
  events: readonly TraceEvent[],
  opts: AnnotateOptions = {},
): RiskDetectedEvent[] {
  if (findings.length === 0) return findings;
  try {
    const calls = new Map<string, ToolInvokedEvent>();
    for (const e of events) if (e.event_type === "tool.invoked") calls.set(e.tool_call_id, e);
    const byCwd = new Map<string, LoadedEnforcement>();
    const load =
      opts.loaded ??
      ((cwd: string | undefined) => {
        const key = cwd ?? "";
        let hit = byCwd.get(key);
        if (!hit) {
          hit = loadEnforcement({ home: opts.home, cwd });
          byCwd.set(key, hit);
        }
        return hit;
      });

    let changed = false;
    const out = findings.map((finding) => {
      const call = calls.get(finding.related_event_id);
      const loaded = load(call?.cwd);
      if (loaded.mode === "monitor") return finding;
      const verdict = verdictFor(finding, call, loaded, opts.rule);
      const record = enforcementRecord(loaded.mode, verdict, opts.held?.(verdict) ?? false);
      if (!record) return finding;
      changed = true;
      return { ...finding, enforcement: record };
    });
    return changed ? out : findings;
  } catch (err) {
    opts.onError?.(err);
    return findings;
  }
}
