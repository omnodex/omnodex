// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- evaluation
 *
 * Runs the rule evaluator over every event the proxy records, so proxied
 * traffic is analyzed as it happens rather than at the next background pass.
 * The proxy is long-lived, so it runs every rule class: per-event rules,
 * session rules (rate, sequence) and machine rules (first MCP server use on
 * this machine, from the shared store in OMNODEX_HOME).
 *
 * Never on the response path. Events are queued and judged on a later tick,
 * one at a time, so the tool call that produced an event has already been
 * forwarded upstream before its rules run. The analyzer itself is loaded on
 * the first tool call, not at startup, so it adds nothing to the time before
 * the proxy answers initialize.
 *
 * Findings are written and pushed exactly like events. An evaluator error is
 * reported once on stderr and otherwise swallowed: detection must never take
 * the proxy down. The background pass re-judges anything missed here.
 */

import type { EmitFn, RiskDetectedEvent, TraceEvent } from "@omnodex/shared";

/** The part of an evaluator the proxy uses. */
export interface ProxyEvaluator {
  evaluate(event: TraceEvent): RiskDetectedEvent[];
}

export type LoadEvaluatorFn = (home: string) => Promise<ProxyEvaluator>;

export interface ProxyEvaluationOptions {
  home: string;
  /** Writes a finding to the event log. */
  emit: EmitFn;
  /** Queues a finding for the live relay. */
  push: (event: TraceEvent) => void;
  /** Evaluator factory. Defaults to the analyzer's proxy host. */
  loadEvaluator?: LoadEvaluatorFn;
  /** Error reporting. Defaults to one stderr line. */
  onError?: (err: unknown) => void;
}

export interface ProxyEvaluation {
  /** Hand over a recorded event. Returns at once. */
  observe(event: TraceEvent): void;
  /** Resolves once every event handed over so far has been judged. */
  drain(): Promise<void>;
}

/** The analyzer's evaluator for a long-lived proxy, with the machine store. */
export const loadProxyEvaluator: LoadEvaluatorFn = async (home) => {
  const analyzer = await import("@omnodex/analyzer");
  const { newEventId } = await import("@omnodex/event-log");
  return analyzer.createEvaluator({
    host: "proxy",
    // Advanced rules, when this installation has a bundle it can open.
    registry: analyzer.registryForHost("proxy", home),
    newEventId,
    machineState: analyzer.openMachineState(home),
  });
};

export function createProxyEvaluation(opts: ProxyEvaluationOptions): ProxyEvaluation {
  const load = opts.loadEvaluator ?? loadProxyEvaluator;
  let reported = false;
  const onError =
    opts.onError ??
    ((err: unknown) => {
      if (reported) return;
      reported = true;
      process.stderr.write(
        `[omnodex-mcp-proxy] rule evaluation failed, continuing without it: ${
          err instanceof Error ? err.message : String(err)
        }\n`,
      );
    });

  // Events before the first tool call (session.started) wait here, so the
  // analyzer is not loaded while the proxy is still starting up.
  const pending: TraceEvent[] = [];
  let started = false;
  let evaluator: Promise<ProxyEvaluator | null> | null = null;
  let tail: Promise<void> = Promise.resolve();

  function getEvaluator(): Promise<ProxyEvaluator | null> {
    evaluator ??= load(opts.home).catch((err: unknown) => {
      onError(err);
      return null;
    });
    return evaluator;
  }

  async function judge(event: TraceEvent): Promise<void> {
    const ev = await getEvaluator();
    if (!ev) return;
    let findings: RiskDetectedEvent[];
    try {
      findings = ev.evaluate(event);
    } catch (err) {
      onError(err);
      return;
    }
    for (const finding of findings) {
      try {
        await opts.emit(finding);
        opts.push(finding);
      } catch (err) {
        onError(err);
      }
    }
  }

  function schedule(events: TraceEvent[]): void {
    tail = tail
      .then(() => new Promise<void>((resolve) => setImmediate(resolve)))
      .then(async () => {
        for (const event of events) await judge(event);
      })
      .catch(onError);
  }

  return {
    observe(event: TraceEvent): void {
      // Findings are this module's own output, not something to judge.
      if (event.event_type === "risk.detected" && event.interceptor === "analyzer") return;
      if (!started && event.event_type !== "tool.invoked") {
        pending.push(event);
        return;
      }
      started = true;
      schedule([...pending.splice(0), event]);
    },

    async drain(): Promise<void> {
      if (!started) return;
      await tail;
    },
  };
}
