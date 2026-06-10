// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * tool_name_match condition evaluator.
 *
 * Checks whether the event's tool_name and/or mcp_server fields match any
 * of the supplied patterns. Used to detect structural tool identity attacks
 * such as tool name shadowing, where a malicious MCP server registers a tool
 * with the same name as a Claude Code built-in.
 *
 * Returns a single-element array with the label of the first matching pattern,
 * or an empty array when no patterns match.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { ToolNameMatchCondition, MatchContext } from "../types.js";

/**
 * Evaluate a tool_name_match condition against a tool.invoked event.
 *
 * Patterns are evaluated in order; the first matching pattern determines the
 * returned label. If a pattern specifies both tool_name_regex and
 * mcp_server_regex, both must match for the pattern to fire.
 */
export function evaluateToolNameMatch(
  condition: ToolNameMatchCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  for (const pattern of condition.patterns) {
    const toolOk =
      pattern.tool_name_regex === undefined ||
      new RegExp(pattern.tool_name_regex).test(event.tool_name);

    const serverOk =
      pattern.mcp_server_regex === undefined ||
      new RegExp(pattern.mcp_server_regex).test(event.mcp_server);

    if (toolOk && serverOk) {
      return [{ matched_label: pattern.label }];
    }
  }
  return [];
}
