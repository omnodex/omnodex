// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * destination_first_seen condition evaluator.
 *
 * Matches a call that reaches an external host no call from this machine
 * had reached before, from the machine state's record of destinations. It
 * only reads that record: the evaluator records every call's hosts after
 * all rules have judged it, so a host counts as seen whether or not any
 * rule looked at the call, and the call that first reaches it still reads
 * as new to every rule.
 *
 * Without a machine state there is no history to compare against, and the
 * condition never matches.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { reachedHosts } from "../machine-state.js";
import type { EvaluationContext, MatchContext } from "../types.js";

export function evaluateDestinationFirstSeen(
  event: ToolInvokedEvent,
  context: EvaluationContext,
): Partial<MatchContext>[] {
  const state = context.machineState;
  if (!state) return [];
  const host = reachedHosts(event).find((h) => !state.knowsDestination(h));
  return host ? [{ matched_destination: host, first_seen_destination: true }] : [];
}
