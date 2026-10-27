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

import type { RiskSeverity, ServerObservedEvent, ToolInvokedEvent } from "@omnodex/shared";
import type { ServerDrift } from "./machine-state.js";
import type {
  Condition,
  EvaluationContext,
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
  evaluateStaging,
  evaluateDestinationFirstSeen,
  evaluateRememberedSecret,
  evaluateFileEdit,
} from "./conditions/index.js";
import {
  type RateThresholdState,
  createRateThresholdState,
} from "./conditions/rate-threshold.js";
import { buildEvidence } from "./evidence.js";

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
  "destination_first_seen",
  "remembered_secret",
  "server_drift",
]);

/** A stateless condition against one event; used for sequence priors. */
function evaluateStateless(
  condition: Condition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  if (STATEFUL_CONDITION_TYPES.has(condition.type)) return [];
  return evaluateCondition(condition, event, new Map(), [], {});
}

function evaluateCondition(
  condition: Condition,
  event: ToolInvokedEvent,
  sessionState: Map<string, Set<string>>,
  window: readonly ToolInvokedEvent[],
  context: EvaluationContext,
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
      return evaluateSessionFirstSeen(condition, event, seen, context);
    }
    case "domain_match":
      return evaluateDomainMatch(condition, event);
    case "cwd_boundary":
      return evaluateCwdBoundary(condition, event, context);
    case "sequence":
      return evaluateSequence(condition, event, window, evaluateStateless, context.home);
    case "staging":
      return evaluateStaging(condition, event);
    case "file_edit":
      return evaluateFileEdit(condition, event);
    case "destination_first_seen":
      return evaluateDestinationFirstSeen(event, context);
    case "remembered_secret":
      return evaluateRememberedSecret(event, context);
    case "server_drift":
      // Judges server.observed events, in evaluateObservation.
      return [];
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
    .replace(/\{\{remembered_since\}\}/g, ctx.remembered_since ?? "")
    .replace(/\{\{matched_ip\}\}/g, ctx.matched_ip ?? "")
    .replace(/\{\{ip_classification\}\}/g, ctx.ip_classification ?? "")
    .replace(/\{\{rate_count\}\}/g, String(ctx.rate_count ?? ""))
    .replace(/\{\{rate_window\}\}/g, String(ctx.rate_window ?? ""))
    .replace(/\{\{matched_domain\}\}/g, ctx.matched_domain ?? "")
    .replace(/\{\{matched_destination\}\}/g, ctx.matched_destination ?? "an external endpoint");
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
  evaluate(event: ToolInvokedEvent, context: EvaluationContext = {}): RiskFinding[] {
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
          partials = evaluateCondition(condition, event, this.sessionState, window, context);
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
        if (ctx.sequence_steps?.length) {
          finding.related_event_ids = ctx.sequence_steps.map((s) => s.event.tool_call_id);
        }
        const evidence = buildEvidence(rule, event, ctx);
        if (evidence) finding.evidence = evidence;
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

  /**
   * Evaluate the server_drift rules against a server.observed event, given
   * how the server differs from its last observation (null: it does not).
   * The caller records the observation once, so every rule judges the same
   * comparison.
   */
  evaluateObservation(event: ServerObservedEvent, drift: ServerDrift | null): RiskFinding[] {
    if (!drift) return [];
    const findings: RiskFinding[] = [];
    for (const rule of this.rules) {
      if (!rule.event_types.includes(event.event_type)) continue;
      const labels: string[] = [];
      let matched = rule.conditions.length > 0;
      for (const condition of rule.conditions) {
        const label = condition.type === "server_drift" ? describeDrift(condition.change, drift) : null;
        if (label === null) {
          matched = false;
          break;
        }
        labels.push(label);
      }
      if (!matched) continue;
      const ctx: MatchContext = { tool_name: "", mcp_server: event.mcp_server, matched_label: labels.join("; ") };
      const change = rule.conditions.find((c) => c.type === "server_drift")!.change;
      findings.push({
        severity: rule.severity,
        category: rule.category,
        description: renderTemplate(rule.description_template, ctx),
        rule_id: rule.rule_id,
        tier: rule.tier,
        // Structured, so the change syncs with the finding and needs no parsing.
        evidence: {
          steps: [],
          drift: {
            server: event.mcp_server,
            transport: event.transport,
            change,
            mid_session: drift.midSession,
            ...(drift.reportedVersion ? { reported_version: drift.reportedVersion } : {}),
            ...(drift.installedVersion ? { installed_version: drift.installedVersion } : {}),
            config_changed: drift.configChanged,
            tools_added: drift.added,
            tools_removed: drift.removed,
            tools_changed: drift.changed,
            ...(drift.toolList ? { tool_list: drift.toolList } : {}),
          },
        },
      });
    }
    return findings;
  }
}

/**
 * The change a server_drift condition matches, in words, or null when the
 * drift is not that kind. "updated" takes any version or config change and
 * lists tool changes with it; "tools" and "definition" only match when the
 * version and config held still, as a change there is the less expected.
 */
function describeDrift(change: "updated" | "tools" | "definition", drift: ServerDrift): string | null {
  const updated = Boolean(drift.reportedVersion || drift.installedVersion || drift.configChanged);
  const parts: string[] = [];
  if (change === "updated") {
    if (!updated) return null;
    if (drift.reportedVersion) parts.push(`reported version ${drift.reportedVersion.from} to ${drift.reportedVersion.to}`);
    if (drift.installedVersion) parts.push(`installed version ${drift.installedVersion.from} to ${drift.installedVersion.to}`);
    if (drift.configChanged) parts.push("its configuration entry changed");
    if (drift.added.length) parts.push(`new tools: ${drift.added.join(", ")}`);
    if (drift.removed.length) parts.push(`dropped tools: ${drift.removed.join(", ")}`);
    if (drift.changed.length) parts.push(`changed tools: ${drift.changed.join(", ")}`);
  } else if (change === "tools") {
    if (updated || (!drift.added.length && !drift.removed.length)) return null;
    if (drift.added.length) parts.push(`now offers ${drift.added.join(", ")}`);
    if (drift.removed.length) parts.push(`no longer offers ${drift.removed.join(", ")}`);
  } else {
    if (updated || !drift.changed.length) return null;
    parts.push(drift.changed.join(", "));
  }
  if (drift.midSession) parts.push("announced while in use");
  return parts.join("; ");
}
