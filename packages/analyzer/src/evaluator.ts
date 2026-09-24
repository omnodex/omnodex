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
import * as os from "node:os";
import { RuleRegistry } from "./registry.js";
import { COMMUNITY_RULES } from "./rules/index.js";
import type { EvaluationContext, RiskFinding, RuleDefinition } from "./types.js";
import { createWorkspaceResolver, type WorkspaceRootsFn } from "./workspace.js";
import type { MachineState } from "./machine-state.js";
import type { McpServerTransport } from "@omnodex/shared";
import { CAPTURE_HOSTS } from "./capture.js";
import { loadAdvancedRules } from "./bundle.js";

export type EvaluationClass = "event" | "session" | "machine";
export type EvaluatorHost = "hook" | "proxy" | "batch";
export type RuleTier = "community" | "advanced";

/** Which rule classes each host runs. */
export const HOST_CLASSES: Readonly<Record<EvaluatorHost, readonly EvaluationClass[]>> = {
  hook: ["event"],
  proxy: ["event", "session", "machine"],
  batch: ["event", "session", "machine"],
};

/**
 * Which rule tiers each host runs.
 *
 * A hook shim is a process per tool call, so it never opens an advanced
 * bundle: it would pay the cost on every call, would want the opened rules
 * cached in the clear, and could not run the sequence rules that make up
 * most of an advanced set anyway. Long-lived hosts open the bundle once and
 * hold the rules in memory. Decided in
 * planning/architecture/PAID_RULE_DELIVERY.md section 3.
 */
export const HOST_TIERS: Readonly<Record<EvaluatorHost, readonly RuleTier[]>> = {
  hook: ["community"],
  proxy: ["community", "advanced"],
  batch: ["community", "advanced"],
};

const CLASS_ORDER: readonly EvaluationClass[] = ["event", "session", "machine"];

/**
 * The classes a host should still run for an event, given what the event's
 * capture path already evaluated (see CAPTURE_HOSTS). A host that tails
 * events after capture uses this so it does not race the capture process to
 * write the same finding.
 */
export function classesLeftAfterCapture(event: TraceEvent, host: EvaluatorHost): EvaluationClass[] {
  const captureHost = CAPTURE_HOSTS[event.interceptor];
  const done = new Set<EvaluationClass>(captureHost ? HOST_CLASSES[captureHost] : []);
  return HOST_CLASSES[host].filter((c) => !done.has(c));
}

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
        raise("session");
        break;
      case "session_first_seen":
        raise(condition.scope === "machine" ? "machine" : "session");
        break;
      default:
        break;
    }
  }
  return cls;
}

export interface LoadRegistryOptions {
  /**
   * Advanced rules to run alongside the community set, already opened from a
   * bundle. Nothing here fetches or decrypts: the caller decides whether this
   * host and this installation may run them.
   */
  advanced?: readonly RuleDefinition[] | null;
}

/**
 * The rule set for this installation: community rules, plus any advanced
 * rules handed in. The one place rules reach an evaluator, so paid delivery
 * changes this function and nothing else.
 */
export function loadRegistry(_home?: string, opts: LoadRegistryOptions = {}): RuleRegistry {
  const advanced = opts.advanced ?? [];
  return advanced.length === 0
    ? new RuleRegistry()
    : new RuleRegistry([...COMMUNITY_RULES, ...advanced]);
}

/**
 * The rule set a given host may run, opening the installation's advanced
 * bundle when the host is allowed advanced rules and one is present. A host
 * that is not, or an installation with no usable bundle, gets the community
 * set: never an error, because detection working is worth more than an
 * advanced rule firing.
 */
export function registryForHost(host: EvaluatorHost, home?: string): RuleRegistry {
  if (!HOST_TIERS[host].includes("advanced")) return loadRegistry(home);
  const result = loadAdvancedRules(home);
  return loadRegistry(home, { advanced: result.rules });
}

export interface EvaluatorOptions {
  host: EvaluatorHost;
  newEventId: () => string;
  /** Defaults to registryForHost(host, home). */
  registry?: RuleRegistry;
  /** OMNODEX_HOME, for the advanced bundle when this host runs one. */
  home?: string;
  /** Recent events kept per session for sequence rules. */
  windowSize?: number;
  /**
   * Workspace roots for a working directory. Defaults to a cached resolver
   * over the cwd, its git checkouts, and configured workspace_roots.
   */
  workspaceRoots?: WorkspaceRootsFn;
  /**
   * Persistent state for machine-scope rules. Without it they fall back to
   * session scope.
   */
  machineState?: MachineState;
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

export interface EvaluateOptions {
  /**
   * Emit findings only for rules of these classes (of the ones this host
   * runs). Stateful rules still take the event in, so their state stays
   * current.
   */
  classes?: readonly EvaluationClass[];
}

export interface Evaluator {
  /** The rules this host runs, in registry order. */
  readonly rules: readonly RuleDefinition[];
  /**
   * Judge one event. tool.invoked may produce findings; risk.detected seeds
   * deduplication; session.ended releases the session's state; anything
   * else is ignored.
   */
  evaluate(event: TraceEvent, options?: EvaluateOptions): RiskDetectedEvent[];
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
  const all = (opts.registry ?? registryForHost(opts.host, opts.home)).getRules();
  const rules = all.filter((r) => allowed.has(classifyRule(r)));
  const order = new Map(rules.map((r, i) => [r.rule_id, i]));

  // Stateless and stateful rules run in separate engines so observe() can
  // warm state without paying for the stateless majority.
  const ruleClass = new Map(rules.map((r) => [r.rule_id, classifyRule(r)]));
  const eventRules = rules.filter((r) => classifyRule(r) === "event");
  const statefulRules = rules.filter((r) => classifyRule(r) !== "event");
  const eventEngine = new RuleEngine(eventRules);
  const statefulEngine = new RuleEngine(statefulRules, { windowSize: opts.windowSize });

  const workspaceRoots = opts.workspaceRoots ?? createWorkspaceResolver();
  const home = os.homedir();
  // How each session's MCP servers are reached, from its session.started.
  const transports = new Map<string, Map<string, McpServerTransport>>();
  const contextFor = (event: ToolInvokedEvent): EvaluationContext => ({
    workspaceRoots: event.cwd ? workspaceRoots(event.cwd) : undefined,
    home,
    machineState: opts.machineState,
    mcpServerTransport: transports.get(event.session_id)?.get(event.mcp_server),
  });
  const noteSession = (event: TraceEvent): void => {
    if (event.event_type === "session.started" && event.mcp_server_transports?.length) {
      transports.set(event.session_id, new Map(event.mcp_server_transports.map((t) => [t.name, t])));
    }
  };

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
    transports.delete(sessionId);
    eventEngine.endSession(sessionId);
    statefulEngine.endSession(sessionId);
  }

  return {
    rules,

    evaluate(event: TraceEvent, options: EvaluateOptions = {}): RiskDetectedEvent[] {
      switch (event.event_type) {
        case "risk.detected":
          seed(event);
          return [];
        case "session.started":
          noteSession(event);
          return [];
        case "session.ended":
          endSession(event.session_id);
          return [];
        case "tool.invoked": {
          stats.evaluated++;
          const context = contextFor(event);
          const wanted = options.classes ? new Set(options.classes) : null;
          const findings = [
            ...(!wanted || wanted.has("event") ? eventEngine.evaluate(event, context) : []),
            ...statefulEngine.evaluate(event, context),
          ].filter((f) => !wanted || wanted.has(ruleClass.get(f.rule_id) ?? "event"));
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
      noteSession(event);
      if (event.event_type === "risk.detected") seed(event);
      else if (event.event_type === "tool.invoked") statefulEngine.evaluate(event, contextFor(event));
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
