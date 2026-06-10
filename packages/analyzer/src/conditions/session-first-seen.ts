// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * session_first_seen condition evaluator.
 *
 * Stateful condition that fires the FIRST time a tracked field value is
 * seen within a session. Primary use case: detect MCP servers that appear
 * mid-session and were not present at session start, which may indicate
 * dynamic plugin injection or prompt injection adding a malicious server.
 *
 * The caller (RuleEngine) is responsible for providing and persisting the
 * seen Set. The evaluator mutates the Set to record newly observed values.
 * Mutation happens before the return, so the value is recorded even if a
 * subsequent condition in the same rule fails.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { SessionFirstSeenCondition, MatchContext } from "../types.js";

/**
 * Evaluate a session_first_seen condition against a tool.invoked event.
 *
 * @param condition  The condition definition.
 * @param event      The event being evaluated.
 * @param seen       Mutable Set of values already observed in this session
 *                   for the tracked field. The evaluator adds new values to
 *                   this Set on first occurrence.
 *
 * Returns a single-element array (first occurrence) or empty array (already
 * seen, or excluded value).
 */
export function evaluateSessionFirstSeen(
  condition: SessionFirstSeenCondition,
  event: ToolInvokedEvent,
  seen: Set<string>,
): Partial<MatchContext>[] {
  const value =
    condition.track === "mcp_server" ? event.mcp_server : event.tool_name;

  // Skip excluded values -- they are never recorded or reported.
  if (condition.exclude?.includes(value)) return [];

  if (seen.has(value)) return [];

  // Record before returning so the value is marked seen regardless of
  // whether other conditions in the same rule subsequently fail.
  seen.add(value);
  return [{}];
}
