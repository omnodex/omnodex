// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * sequence condition evaluator.
 *
 * Matches when an earlier tool.invoked event in the same session, within
 * the condition's bounds, satisfied every one of the condition's "prior"
 * conditions. The rule's other conditions apply to the current event, so a
 * rule reads as "this event, after that one". Yields one context citing the
 * most recent qualifying earlier event, so the finding can name both.
 *
 * The window of earlier events is kept by the engine and supplied here.
 * Prior conditions must be stateless (checked when rules are classified),
 * because they are re-evaluated against events that have already passed.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { Condition, MatchContext, SequenceCondition } from "../types.js";

/** Evaluates one stateless condition against one event. */
export type StatelessConditionFn = (
  condition: Condition,
  event: ToolInvokedEvent,
) => Partial<MatchContext>[];

export function evaluateSequence(
  condition: SequenceCondition,
  event: ToolInvokedEvent,
  window: readonly ToolInvokedEvent[],
  evaluate: StatelessConditionFn,
): Partial<MatchContext>[] {
  const now = Date.parse(event.occurred_at);
  const limit = condition.within_events ?? window.length;
  const earliest = Math.max(0, window.length - limit);

  // Most recent first, so the finding cites the nearest earlier step.
  for (let i = window.length - 1; i >= earliest; i--) {
    const prior = window[i];
    if (condition.within_seconds !== undefined) {
      const age = (now - Date.parse(prior.occurred_at)) / 1000;
      if (!(age <= condition.within_seconds)) break;
    }
    if (condition.prior.every((c) => evaluate(c, prior).length > 0)) {
      return [{ related_event_ids: [prior.tool_call_id] }];
    }
  }
  return [];
}
