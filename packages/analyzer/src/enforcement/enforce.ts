// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Guardrails at capture time: from a call's findings to the answer its
 * agent host reads from the hook (or the MCP proxy returns).
 *
 * In guardrails mode each finding's verdict is resolved from the user's
 * settings and handed to the guardrails module (module.ts), which decides
 * the call; every finding is stamped with whether it held the call. Without
 * a module that opens, or in any other mode, this is the same as stamping
 * (annotate.ts): the findings are recorded as in shadow mode and the call is
 * left alone.
 *
 * When the rules could not judge the call (a load failure, an error, the
 * time cap), a risk.enforcement_error event records it, and the module
 * decides whether the call still runs (the default) or is stopped
 * (enforcement.on_error "block"). Never throws.
 */

import type {
  BlockingVerdict,
  EnforcementMode,
  RiskDetectedEvent,
  RiskEnforcementErrorEvent,
  ToolInvokedEvent,
  TraceEvent,
} from "@omnodex/shared";
import { loadEnforcement, type LoadedEnforcement } from "./config.js";
import { annotateFindings, enforcementRecord, verdictFor } from "./annotate.js";
import { loadGuardrailsModule, type EnforcementHost, type GuardrailsModule } from "./module.js";
import type { VerdictRule } from "./resolve-verdict.js";
import { appendRuleSignals } from "./signals.js";

export interface EnforceOptions {
  host: EnforcementHost;
  /** OMNODEX_HOME. */
  home?: string;
  newEventId: () => string;
  /** Set when the rules could not judge the call: why. */
  failure?: "timeout" | "error";
  /** Loaded configuration, for tests. Read from the call's working directory when absent. */
  loaded?: LoadedEnforcement;
  /** The guardrails module, for tests. Loaded from OMNODEX_HOME when absent; null means none. */
  module?: GuardrailsModule | null;
  rule?: (id: string) => VerdictRule | undefined;
  onError?: (err: unknown) => void;
}

export interface EnforceResult {
  /** The findings, stamped. */
  findings: RiskDetectedEvent[];
  /** Events to record beside them (a risk.enforcement_error). */
  extra: TraceEvent[];
  /** The host's answer, or null to write nothing. */
  output: Record<string, unknown> | null;
  /** What happened to the call. */
  action: BlockingVerdict;
  /** The mode in force for the call: guardrails without a module acts as shadow. */
  mode: EnforcementMode;
}

/** Decide a captured call. Never throws: on failure the call runs. */
export async function enforceCaptured(
  findings: RiskDetectedEvent[],
  events: readonly TraceEvent[],
  opts: EnforceOptions,
): Promise<EnforceResult> {
  const pass: EnforceResult = { findings, extra: [], output: null, action: "alert_only", mode: "monitor" };
  try {
    const call = events.find((e): e is ToolInvokedEvent => e.event_type === "tool.invoked");
    if (!call) return pass;
    const configured = opts.loaded ?? loadEnforcement({ home: opts.home, cwd: call.cwd });
    let module: GuardrailsModule | null = null;
    if (configured.mode === "guardrails") {
      module = opts.module !== undefined ? opts.module : ((await loadGuardrailsModule(opts.home)).module ?? null);
    }
    // Guardrails without a module that opens: record as shadow mode would.
    const loaded: LoadedEnforcement = configured.mode === "guardrails" && !module ? { ...configured, mode: "shadow" } : configured;
    if (loaded.mode !== "guardrails" || !module) {
      return { ...pass, mode: loaded.mode, findings: annotateFindings(findings, events, { loaded: () => loaded, rule: opts.rule }) };
    }

    if (opts.failure) {
      const decision = module.decide({ host: opts.host, verdicts: [], failure: opts.failure, onError: loaded.on_error });
      const blocked = decision.action !== "alert_only";
      const error: RiskEnforcementErrorEvent = {
        schema_version: call.schema_version,
        event_id: opts.newEventId(),
        session_id: call.session_id,
        occurred_at: new Date().toISOString(),
        recorded_at: new Date().toISOString(),
        interceptor: "analyzer",
        ...(call.platform ? { platform: call.platform } : {}),
        ...(call.agent_id ? { agent_id: call.agent_id } : {}),
        event_type: "risk.enforcement_error",
        related_event_id: call.tool_call_id,
        reason: opts.failure,
        outcome: blocked ? "blocked" : "allowed",
      };
      return { findings, extra: [error], output: decision.output, action: decision.action, mode: "guardrails" };
    }

    const verdicts = findings.map((f) => verdictFor(f, call, loaded, opts.rule));
    const decision = module.decide({ host: opts.host, verdicts, onError: loaded.on_error });
    const held = new Set(decision.held);
    const stamped = findings.map((f, i) => {
      const record = enforcementRecord("guardrails", verdicts[i]!, held.has(f.rule_id));
      return record ? { ...f, enforcement: record } : f;
    });
    return { findings: stamped, extra: [], output: decision.output, action: decision.action, mode: "guardrails" };
  } catch (err) {
    opts.onError?.(err);
    return pass;
  }
}

/** enforceCaptured, then the rule signals for what it stamped. */
export async function enforceAndCount(
  findings: RiskDetectedEvent[],
  events: readonly TraceEvent[],
  opts: EnforceOptions & { home: string },
): Promise<EnforceResult> {
  const result = await enforceCaptured(findings, events, opts);
  if (result.findings !== findings) await appendRuleSignals(opts.home, result.findings);
  return result;
}
