// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Enforcement records at capture time, for the hook shims.
 *
 * Imported statically by the shims, so it loads nothing itself: the
 * enforcement module (configuration, rules) is imported only when a call
 * produced findings. Never rejects; on any failure the findings come back
 * unstamped, because the finding matters more than its enforcement record.
 * Stamped findings that would stop a call are also counted per rule (see
 * signals.ts).
 */

import type { RiskDetectedEvent, TraceEvent } from "@omnodex/shared";
import type { EnforceOptions, EnforceResult } from "./enforce.js";

export interface StampOptions {
  /** OMNODEX_HOME. */
  home: string;
  /** Error reporting. Defaults to silence. */
  onError?: (err: unknown) => void;
}

/** The findings, stamped with what enforcement made of them. */
export async function stampCaptured(
  findings: RiskDetectedEvent[],
  events: readonly TraceEvent[],
  opts: StampOptions,
): Promise<RiskDetectedEvent[]> {
  if (findings.length === 0) return findings;
  try {
    const [{ annotateFindings }, { appendRuleSignals }] = await Promise.all([
      import("./annotate.js"),
      import("./signals.js"),
    ]);
    const stamped = annotateFindings(findings, events, opts);
    if (stamped !== findings) await appendRuleSignals(opts.home, stamped);
    return stamped;
  } catch (err) {
    opts.onError?.(err);
    return findings;
  }
}

/**
 * For a host that can act on the call before it runs: the findings stamped
 * with whether they held it, any enforcement error event, and the decision
 * for the hook's stdout. On any failure loading the enforcement code, the
 * call runs and the findings come back unstamped.
 */
export async function enforceCapturedCall(
  findings: RiskDetectedEvent[],
  events: readonly TraceEvent[],
  opts: EnforceOptions & { home: string },
): Promise<EnforceResult> {
  try {
    const { enforceAndCount } = await import("./enforce.js");
    return await enforceAndCount(findings, events, opts);
  } catch (err) {
    opts.onError?.(err);
    return { findings, extra: [], output: null, action: "alert_only", mode: "monitor" };
  }
}
