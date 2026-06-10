// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * rate_threshold condition evaluator.
 *
 * Stateful condition that fires when the number of tool calls within a
 * sliding time window exceeds a configurable threshold. Designed to detect
 * unbounded consumption patterns: runaway agent loops, recursive tool call
 * storms, and resource exhaustion attacks (OWASP LLM10).
 *
 * The caller (RuleEngine) is responsible for providing and persisting the
 * state object. The evaluator mutates state to record timestamps and prune
 * expired entries.
 *
 * Design notes:
 *   - Uses occurred_at from the event (wall-clock time of the tool call),
 *     not evaluation time, so replay and testing work correctly.
 *   - Window is sliding: expired timestamps are pruned on each evaluation.
 *   - Fires once per threshold crossing, then suppresses until the rate
 *     drops below threshold. Prevents spamming N findings for N calls
 *     above the threshold.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { RateThresholdCondition, MatchContext } from "../types.js";

/**
 * Evaluate a rate_threshold condition against a tool.invoked event.
 *
 * @param condition   The condition definition (window and threshold).
 * @param event       The event being evaluated.
 * @param state       Mutable state for this session+rule: timestamps array
 *                    and whether we are currently in "fired" state.
 *
 * Returns a single-element array (threshold crossed) or empty array.
 */
export function evaluateRateThreshold(
  condition: RateThresholdCondition,
  event: ToolInvokedEvent,
  state: RateThresholdState,
): Partial<MatchContext>[] {
  const now = new Date(event.occurred_at).getTime();
  const windowMs = condition.window_seconds * 1000;
  const cutoff = now - windowMs;

  // Record this event timestamp.
  state.timestamps.push(now);

  // Prune timestamps outside the window (front of array is oldest).
  while (state.timestamps.length > 0 && state.timestamps[0] < cutoff) {
    state.timestamps.shift();
  }

  const count = state.timestamps.length;

  if (count >= condition.threshold) {
    // Threshold exceeded. Fire only on the crossing.
    if (!state.fired) {
      state.fired = true;
      return [{ rate_count: count, rate_window: condition.window_seconds }];
    }
    // Already fired for this burst -- suppress duplicate findings.
    return [];
  }

  // Below threshold -- reset so we can fire again on next spike.
  state.fired = false;
  return [];
}

/**
 * Per-session, per-rule state for rate_threshold evaluation.
 * Managed by the RuleEngine (keyed by session_id + rule_id).
 */
export interface RateThresholdState {
  /** Timestamps (ms since epoch) of events within the current window. */
  timestamps: number[];
  /** Whether we already fired for the current above-threshold burst. */
  fired: boolean;
}

/** Factory for fresh state. */
export function createRateThresholdState(): RateThresholdState {
  return { timestamps: [], fired: false };
}
