// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * staging condition evaluator.
 *
 * Matches a call that archives, encodes, encrypts or copies data to the
 * clipboard, as the normalized action reads it from the command. Yields one
 * context per staging step, naming the file it wrote when the command says.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { normalizeAction } from "../action.js";
import type { MatchContext, StagingCondition } from "../types.js";

export function evaluateStaging(
  condition: StagingCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const steps = normalizeAction(event).staging.filter((s) => !condition.ops || condition.ops.includes(s.op));
  return steps.map((s) => ({ matched_label: s.op, ...(s.output ? { staging_output: s.output } : {}) }));
}
