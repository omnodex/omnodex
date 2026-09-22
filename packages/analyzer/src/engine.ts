// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Rule engine -- interprets declarative RuleDefinition objects against
 * trace events and produces RiskFinding results.
 *
 * Design:
 *
 *   1. For each event, check whether its event_type is in rule.event_types.
 *   2. Evaluate each condition in sequence, collecting Partial<MatchContext>[]
 *      from each. An empty return means the condition did not match.
 *   3. If any condition fails, the rule produces no findings.
 *   4. When all conditions match, cross-product their contexts and merge each
 *      combination with the base context (tool_name, mcp_server from the event).
 *   5. Render the description template for each merged context.
 *
 * The cross-product in step 4 handles multi-context conditions (e.g. a
 * path_match that matches three paths produces three contexts). In current
 * rules at most one condition is multi-valued, so the product is always 1-to-N.
 *
 * Session state:
 *   The engine maintains per-session seen-sets for session_first_seen
 *   conditions, keyed by "<session_id>:<track>", rate state for
 *   rate_threshold, and, when any rule uses a sequence condition, a bounded
 *   window of each session's recent tool.invoked events. A single engine
 *   instance can safely be shared across multiple concurrent sessions.
 *   Long-running hosts call endSession() when a session ends to release it.
 */

import type { RiskSeverity, ToolInvokedEvent } from "@omnodex/shared";
import type {
  Condition,
  MatchContext,
  RiskFinding,
  RuleDefinition,
} from "./types.js";
import {
  evaluateCredentialMatch,
  evaluateIpDestination,
  evaluateOutboundCall,
  evaluatePathMatch,
  evaluateToolNameMatch,
  evaluateSessionFirstSeen,
  evaluateRateThreshold,
  evaluateDomainMatch,
  evaluateCwdBoundary,
  evaluateSequence,
} from "./conditions/index.js";
import {
  type RateThresholdState,
  createRateThresholdState,
} from "./conditions/rate-threshold.js";

// ---------------------------------------------------------------------------
// Condition dispatch
// ---------------------------------------------------------------------------

/** Default number of recent events kept per session for sequence rules. */
export const DEFAULT_SEQUENCE_WINDOW = 50;

/** Conditions that keep state across events. */
export const STATEFUL_CONDITION_TYPES: ReadonlySet<Condition["type"]> = new Set([
  "session_first_seen",
  "rate_threshold",
  "sequence",
]);

/** A stateless condition against one event; used for sequence priors. */
function evaluateStateless(
  condition: Condition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  if (STATEFUL_CONDITION_TYPES.has(condition.type)) return [];
  return evaluateCondition(condition, event, new Map(), []);
}

function evaluateCondition(
  condition: Condition,
  event: ToolInvokedEvent,
  sessionState: Map<string, Set<string>>,
  window: readonly ToolInvokedEvent[],
): Partial<MatchContext>[] {
  switch (condition.type) {
    case "path_match":
      return evaluatePathMatch(condition, event);
    case "credential_match":
      return evaluateCredentialMatch(condition, event);
    case "outbound_call":
      return evaluateOutboundCall(event);
    case "ip_destination":
      return evaluateIpDestination(condition, event);
    case "tool_name_match":
      return evaluateToolNameMatch(condition, event);
    case "session_first_seen": {
      const key = `${event.session_id}:${condition.track}`;
      if (!sessionState.has(key)) {
        sessionState.set(key, new Set<string>());
      }
      const seen = sessionState.get(key)!;
      return evaluateSessionFirstSeen(condition, event, seen);
    }
    case "domain_match":
      return evaluateDomainMatch(condition, event);
    case "cwd_boundary":
      return evaluateCwdBoundary(condition, event);
    case "sequence":
      return evaluateSequence(condition, event, window, evaluateStateless);
    case "rate_threshold":
      // Handled specially in the rule loop (needs rule_id for state key).
      // This case should not be reached; it exists for exhaustive switch.
      return [];
  }
}

const SEVERITY_ORDER: readonly RiskSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** One severity step lower, bottoming out at LOW. */
function stepDown(severity: RiskSeverity): RiskSeverity {
  return SEVERITY_ORDER[Math.max(0, SEVERITY_ORDER.indexOf(severity) - 1)];
}

// ---------------------------------------------------------------------------
// Template rendering
// ---------------------------------------------------------------------------

function renderTemplate(template: string, ctx: MatchContext): string {
  return template
    .replace(/\{\{tool_name\}\}/g, ctx.tool_name)
    .replace(/\{\{mcp_server\}\}/g, ctx.mcp_server)
    .replace(/\{\{matched_path\}\}/g, ctx.matched_path ?? "")
    .replace(/\{\{matched_label\}\}/g, ctx.matched_label ?? "")
    .replace(
      /\{\{credential_types\}\}/g,
      (ctx.credential_types ?? []).join(", "),
    )
    .replace(/\{\{matched_ip\}\}/g, ctx.matched_ip ?? "")
    .replace(/\{\{ip_classification\}\}/g, ctx.ip_classification ?? "")
    .replace(/\{\{rate_count\}\}/g, String(ctx.rate_count ?? ""))
    .replace(/\{\{rate_window\}\}/g, String(ctx.rate_window ?? ""))
    .replace(/\{\{matched_domain\}\}/g, ctx.matched_domain ?? "");
}

// ---------------------------------------------------------------------------
// Rule engine
// ---------------------------------------------------------------------------

/**
 * RuleEngine evaluates a fixed set of RuleDefinitions against trace events.
 * Construct once per detection run and call evaluate() for each event.
 *
 * The engine is stateful: it tracks per-session seen-sets for
 * session_first_seen conditions. The same instance can be reused across
 * multiple sessions and events.
 */
export class RuleEngine {
  /**
   * Per-session seen-sets for session_first_seen conditions.
   * Key: "<session_id>:<track>" (e.g. "sess-abc123:mcp_server")
   */
  private readonly sessionState = new Map<string, Set<string>>();

  /**
   * Per-session, per-rule state for rate_threshold conditions.
   * Key: "<session_id>:<rule_id>" (one state per rule since different
   * rules may have different window/threshold combinations).
   */
  private readonly rateState = new Map<string, RateThresholdState>();

  /** Recent tool.invoked events per session, for sequence conditions. */
  private readonly windows = new Map<string, ToolInvokedEvent[]>();
  private readonly windowSize: number;

  constructor(
    private readonly rules: RuleDefinition[],
    opts: { windowSize?: number } = {},
  ) {
    const usesSequence = rules.some((r) => r.conditions.some((c) => c.type === "sequence"));
    this.windowSize = usesSequence ? (opts.windowSize ?? DEFAULT_SEQUENCE_WINDOW) : 0;
  }

  /** Release everything held for a session. */
  endSession(sessionId: string): void {
    this.windows.delete(sessionId);
    const prefix = `${sessionId}:`;
    for (const key of this.sessionState.keys()) {
      if (key.startsWith(prefix)) this.sessionState.delete(key);
    }
    for (const key of this.rateState.keys()) {
      if (key.startsWith(prefix)) this.rateState.delete(key);
    }
  }

  /**
   * Evaluate all rules against a single tool.invoked event.
   * Returns one RiskFinding per rule+context combination that matched.
   */
  evaluate(event: ToolInvokedEvent): RiskFinding[] {
    const findings: RiskFinding[] = [];
    const window = this.windows.get(event.session_id) ?? [];

    for (const rule of this.rules) {
      // Skip rules not applicable to this event type.
      if (!rule.event_types.includes(event.event_type)) continue;

      const baseCtx: MatchContext = {
        tool_name: event.tool_name,
        mcp_server: event.mcp_server,
      };

      // Start with a single empty partial context and accumulate results
      // from each condition via cross-product.
      let accumulated: Partial<MatchContext>[] = [{}];

      let allMatched = true;
      for (const condition of rule.conditions) {
        let partials: Partial<import("./types.js").MatchContext>[];
        if (condition.type === "rate_threshold") {
          const rateKey = `${event.session_id}:${rule.rule_id}`;
          if (!this.rateState.has(rateKey)) {
            this.rateState.set(rateKey, createRateThresholdState());
          }
          partials = evaluateRateThreshold(
            condition,
            event,
            this.rateState.get(rateKey)!,
          );
        } else {
          partials = evaluateCondition(condition, event, this.sessionState, window);
        }
        if (partials.length === 0) {
          allMatched = false;
          break;
        }
        // Cross-product: every existing accumulated context x every new partial.
        const next: Partial<MatchContext>[] = [];
        for (const existing of accumulated) {
          for (const partial of partials) {
            next.push({ ...existing, ...partial });
          }
        }
        accumulated = next;
      }

      if (!allMatched) continue;

      // Emit one finding per accumulated context.
      for (const partial of accumulated) {
        const ctx: MatchContext = { ...baseCtx, ...partial };
        let description = renderTemplate(rule.description_template, ctx);
        if (ctx.staged_path) {
          description += ` Found in content written to ${ctx.staged_path}, not in a command that ran.`;
        }
        const finding: RiskFinding = {
          severity: ctx.staged_path
            ? (rule.staged_severity ?? stepDown(rule.severity))
            : rule.severity,
          category: rule.category,
          description,
          rule_id: rule.rule_id,
          tier: rule.tier,
        };
        if (ctx.related_event_ids?.length) finding.related_event_ids = ctx.related_event_ids;
        findings.push(finding);
      }
    }

    // Only after every rule has run: an event is never its own prior step.
    if (this.windowSize > 0) {
      window.push(event);
      if (window.length > this.windowSize) window.shift();
      this.windows.set(event.session_id, window);
    }

    return findings;
  }
}
