// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Evaluator -- the one place a risk.detected event is made.
 *
 * Every host that judges events uses this: batch detection over a log
 * (detectRisks, `omnodex detect`, the background pass), the local
 * dashboard's live loop, and, as they adopt it, the MCP proxy and the hook
 * shims. A finding therefore means the same thing wherever it was produced,
 * and hosts that share a log never repeat each other's findings.
 *
 * Rules are classified by the state they need:
 *
 *   event    -- judges one tool.invoked on its own
 *   session  -- needs earlier events of the session (first-seen, rate,
 *               sequence conditions)
 *   machine  -- needs state that outlives a session
 *
 * A host runs the classes it can afford. A hook shim is a fresh process per
 * event, so it runs event-class rules only; long-lived hosts and batch
 * passes run everything.
 *
 * Deduplication is on rule plus the anchoring tool_call_id, and is seeded
 * from every risk.detected the evaluator is shown, so findings written by
 * another host are never written again.
 *
 * Import from "@omnodex/analyzer/evaluator" on hot paths: that entry point
 * does not load the event log or batch helpers.
 */

import type { RiskDetectedEvent, TraceEvent, ToolInvokedEvent } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";
import { RuleEngine, STATEFUL_CONDITION_TYPES } from "./engine.js";
import { RuleRegistry } from "./registry.js";
import type { RiskFinding, RuleDefinition } from "./types.js";

export type EvaluationClass = "event" | "session" | "machine";
export type EvaluatorHost = "hook" | "proxy" | "batch";

/** Which rule classes each host runs. */
export const HOST_CLASSES: Readonly<Record<EvaluatorHost, readonly EvaluationClass[]>> = {
  hook: ["event"],
  proxy: ["event", "session", "machine"],
  batch: ["event", "session", "machine"],
};

const CLASS_ORDER: readonly EvaluationClass[] = ["event", "session", "machine"];

/**
 * The state a rule needs, derived from its conditions. Throws for a
 * sequence condition whose prior steps are themselves stateful, which the
 * engine cannot re-evaluate against events that have already passed.
 */
export function classifyRule(rule: RuleDefinition): EvaluationClass {
  let cls: EvaluationClass = "event";
  const raise = (to: EvaluationClass): void => {
    if (CLASS_ORDER.indexOf(to) > CLASS_ORDER.indexOf(cls)) cls = to;
  };
  for (const condition of rule.conditions) {
    switch (condition.type) {
      case "sequence":
        for (const prior of condition.prior) {
          if (STATEFUL_CONDITION_TYPES.has(prior.type)) {
            throw new Error(
              `${rule.rule_id}: sequence prior conditions must be stateless, got ${prior.type}`,
            );
          }
        }
        raise("session");
        break;
      case "rate_threshold":
      case "session_first_seen":
        raise("session");
        break;
      default:
        break;
    }
  }
  return cls;
}

/**
 * The rule set for this installation. Community rules today; this is the
 * single place advanced rules will be added when they are delivered.
 */
export function loadRegistry(_home?: string): RuleRegistry {
  return new RuleRegistry();
}

export interface EvaluatorOptions {
  host: EvaluatorHost;
  newEventId: () => string;
  /** Defaults to loadRegistry(). */
  registry?: RuleRegistry;
  /** Recent events kept per session for sequence rules. */
  windowSize?: number;
}

export interface EvaluatorStats {
  /** tool.invoked events evaluated (not counting observe()). */
  evaluated: number;
  /** Findings emitted. */
  findings: number;
  /** Findings suppressed because they were already recorded. */
  skipped: number;
  /** Emitted findings per rule_id. */
  byRule: Record<string, number>;
  /** Emitted findings per rule tier. */
  byTier: Record<string, number>;
}

export interface Evaluator {
  /** The rules this host runs, in registry order. */
  readonly rules: readonly RuleDefinition[];
  /**
   * Judge one event. tool.invoked may produce findings; risk.detected seeds
   * deduplication; session.ended releases the session's state; anything
   * else is ignored.
   */
  evaluate(event: TraceEvent): RiskDetectedEvent[];
  /**
   * Take in an event from history without emitting: warms session state
   * (first-seen sets, rate windows, sequence windows) and deduplication, so
   * a host that starts mid-session does not re-fire what it has missed.
   */
  observe(event: TraceEvent): void;
  /** Release everything held for a session. */
  endSession(sessionId: string): void;
  stats(): EvaluatorStats;
}

export function createEvaluator(opts: EvaluatorOptions): Evaluator {
  const allowed = new Set(HOST_CLASSES[opts.host]);
  const all = (opts.registry ?? loadRegistry()).getRules();
  const rules = all.filter((r) => allowed.has(classifyRule(r)));
  const order = new Map(rules.map((r, i) => [r.rule_id, i]));

  // Stateless and stateful rules run in separate engines so observe() can
  // warm state without paying for the stateless majority.
  const eventRules = rules.filter((r) => classifyRule(r) === "event");
  const statefulRules = rules.filter((r) => classifyRule(r) !== "event");
  const eventEngine = new RuleEngine(eventRules);
  const statefulEngine = new RuleEngine(statefulRules, { windowSize: opts.windowSize });

  const recorded = new Set<string>();
  const stats: EvaluatorStats = { evaluated: 0, findings: 0, skipped: 0, byRule: {}, byTier: {} };

  function seed(event: RiskDetectedEvent): void {
    recorded.add(`${event.rule_id}::${event.related_event_id}`);
  }

  function emit(event: ToolInvokedEvent, finding: RiskFinding): RiskDetectedEvent | null {
    const key = `${finding.rule_id}::${event.tool_call_id}`;
    if (recorded.has(key)) {
      stats.skipped++;
      return null;
    }
    recorded.add(key);

    const now = new Date().toISOString();
    const risk: RiskDetectedEvent = {
      schema_version: SCHEMA_VERSION,
      event_id: opts.newEventId(),
      session_id: event.session_id,
      occurred_at: now,
      recorded_at: now,
      interceptor: "analyzer",
      event_type: "risk.detected",
      severity: finding.severity,
      category: finding.category,
      description: finding.description,
      related_event_id: event.tool_call_id,
      rule_id: finding.rule_id,
      rule_tier: finding.tier,
    };
    if (finding.related_event_ids?.length) {
      risk.related_event_ids = [...finding.related_event_ids, event.tool_call_id];
    }

    stats.findings++;
    stats.byRule[finding.rule_id] = (stats.byRule[finding.rule_id] ?? 0) + 1;
    stats.byTier[finding.tier] = (stats.byTier[finding.tier] ?? 0) + 1;
    return risk;
  }

  function endSession(sessionId: string): void {
    eventEngine.endSession(sessionId);
    statefulEngine.endSession(sessionId);
  }

  return {
    rules,

    evaluate(event: TraceEvent): RiskDetectedEvent[] {
      switch (event.event_type) {
        case "risk.detected":
          seed(event);
          return [];
        case "session.ended":
          endSession(event.session_id);
          return [];
        case "tool.invoked": {
          stats.evaluated++;
          const findings = [...eventEngine.evaluate(event), ...statefulEngine.evaluate(event)];
          // Registry order, as a single engine would have produced them.
          findings.sort((a, b) => (order.get(a.rule_id) ?? 0) - (order.get(b.rule_id) ?? 0));
          const out: RiskDetectedEvent[] = [];
          for (const finding of findings) {
            const risk = emit(event, finding);
            if (risk) out.push(risk);
          }
          return out;
        }
        default:
          return [];
      }
    },

    observe(event: TraceEvent): void {
      if (event.event_type === "risk.detected") seed(event);
      else if (event.event_type === "tool.invoked") statefulEngine.evaluate(event);
    },

    endSession,

    stats(): EvaluatorStats {
      return {
        ...stats,
        byRule: { ...stats.byRule },
        byTier: { ...stats.byTier },
      };
    },
  };
}
