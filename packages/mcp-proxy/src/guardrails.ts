// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- guardrails
 *
 * In guardrails enforcement mode the proxy judges each tool call against the
 * per-event rules before forwarding it, and answers a call the user's
 * settings stop with an error result carrying the reason, without ever
 * reaching the upstream. In every other mode it does nothing on the
 * response path: the mode is one small file read, and the analyzer is not
 * loaded.
 *
 * Findings from the decision are handed back to be written right after the
 * call's tool.invoked event, stamped with whether they held the call, and
 * the proxy's later evaluation (evaluation.ts) skips them so nothing is
 * written twice. When the upstream's parameters are
 * redacted in the log, the call is judged on what the agent sent but its
 * findings are left to the later evaluation of the redacted event, so a
 * finding never records what redaction keeps out of the log.
 *
 * Fails open: if the rules cannot judge the call, it is forwarded and a
 * risk.enforcement_error event is written, unless the user chose
 * enforcement.on_error "block".
 */

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { parseEnforcementConfig } from "@omnodex/shared";
import type { RiskDetectedEvent, ToolInvokedEvent, TraceEvent } from "@omnodex/shared";

export interface ProxyDecision {
  /** The call must not be forwarded. */
  blocked: boolean;
  /** What the agent is told, when blocked. */
  reason?: string;
  /** The rules that stopped it, when blocked. */
  ruleIds?: string[];
  /** Findings and enforcement errors to write after the call's tool.invoked event. */
  events: TraceEvent[];
}

export interface ProxyGuardrails {
  /**
   * Decide a call before it is forwarded. `logged` is the event as written
   * to the log, `full` the same call with nothing redacted.
   */
  decide(full: ToolInvokedEvent, logged: ToolInvokedEvent): Promise<ProxyDecision>;
  /** True once for a finding already written when its call was decided. */
  alreadyWritten(finding: RiskDetectedEvent): boolean;
}

export interface ProxyGuardrailsOptions {
  home: string;
  newEventId?: () => string;
  /** Judges the call with the per-event rules. Defaults to the analyzer's judgeCaptured; tests replace it. */
  judge?: (
    events: ToolInvokedEvent[],
    opts: { newEventId: () => string; onError: (err: unknown) => void },
  ) => Promise<RiskDetectedEvent[]>;
  /** Error reporting. Defaults to silence. */
  onError?: (err: unknown) => void;
}

const pass = (): ProxyDecision => ({ blocked: false, events: [] });
const findingKey = (f: Pick<RiskDetectedEvent, "related_event_id" | "rule_id">) => `${f.related_event_id}::${f.rule_id}`;

/** The enforcement mode in OMNODEX_HOME's configuration; unreadable means monitor. */
export function proxyEnforcementMode(home: string): string {
  try {
    const raw = JSON.parse(readFileSync(path.join(home, "omnodex-config.json"), "utf8")) as { enforcement?: unknown };
    return parseEnforcementConfig(raw?.enforcement).mode ?? "monitor";
  } catch {
    return "monitor";
  }
}

export function createProxyGuardrails(opts: ProxyGuardrailsOptions): ProxyGuardrails {
  const written = new Set<string>();
  const onError = opts.onError ?? (() => undefined);

  async function decide(full: ToolInvokedEvent, logged: ToolInvokedEvent): Promise<ProxyDecision> {
    if (proxyEnforcementMode(opts.home) !== "guardrails") return pass();
    try {
      const [{ judgeCaptured, CaptureTimeoutError }, { enforceCapturedCall }, eventLog] = await Promise.all([
        import("@omnodex/analyzer/capture"),
        import("@omnodex/analyzer/stamp"),
        import("@omnodex/event-log"),
      ]);
      const newEventId = opts.newEventId ?? eventLog.newEventId;
      let failure: "timeout" | "error" | undefined;
      const findings = await (opts.judge ?? judgeCaptured)([full], {
        newEventId,
        onError: (err) => {
          failure = err instanceof CaptureTimeoutError ? "timeout" : "error";
          onError(err);
        },
      });
      const result = await enforceCapturedCall(findings, [full], {
        host: "mcp-proxy",
        home: opts.home,
        newEventId,
        failure,
        onError,
      });
      // Findings only when the log holds what they were judged on.
      const events: TraceEvent[] = full === logged ? [...result.findings, ...result.extra] : [...result.extra];
      for (const event of events) {
        if (event.event_type === "risk.detected") written.add(findingKey(event));
      }
      const reason = result.output?.reason;
      if (typeof reason !== "string") return { blocked: false, events };
      const ruleIds = result.findings.filter((f) => f.enforcement?.held).map((f) => f.rule_id);
      return { blocked: true, reason, ruleIds, events };
    } catch (err) {
      // The rules could not even be loaded: the call goes ahead.
      onError(err);
      return pass();
    }
  }

  return {
    decide,
    alreadyWritten(finding) {
      return written.delete(findingKey(finding));
    },
  };
}
