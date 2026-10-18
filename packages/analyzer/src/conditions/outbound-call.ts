// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * outbound_call condition evaluator.
 *
 * Detects whether a tool.invoked event represents an outbound HTTP call to
 * an external host. Acts as a guard: returns one MatchContext when the event
 * looks outbound (naming its destination when known), or nothing when it
 * does not. The parsing lives in the normalized action (../action.ts).
 *
 * Detection logic:
 *   1. If URL parameters are present, use them exclusively:
 *      outbound iff at least one URL resolves to a non-localhost host.
 *      This prevents false positives when a "fetch" tool calls localhost.
 *   2. If no URL parameters, fall back to heuristics:
 *      a. Tool name contains "fetch", "http", or "request".
 *      b. Bash command contains curl, wget, http, or httpie.
 *
 * A write tool is never outbound on the strength of its parameters alone: a
 * URL inside content being written to a file is a string in a file, not a
 * call to that URL.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { normalizeAction } from "../action.js";
import type { MatchContext } from "../types.js";

/**
 * Returns true if the event looks like an outbound HTTP call to an external host.
 */
export function isOutboundCall(event: ToolInvokedEvent): boolean {
  return normalizeAction(event).outbound;
}

/**
 * Evaluate an outbound_call condition against a tool.invoked event.
 *
 * Returns a single partial context when the call is outbound, naming the
 * destination when one can be read from the call ({{matched_destination}}),
 * or an empty array when it is not.
 */
export function evaluateOutboundCall(
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const action = normalizeAction(event);
  if (!action.outbound) return [];
  const external = action.destinations.find((d) => d.ipClass !== "loopback");
  return [external ? { matched_destination: external.host } : {}];
}
