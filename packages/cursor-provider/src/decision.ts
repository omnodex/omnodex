// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What each Cursor hook reads from the guardrails answer. The module answers
 * with both shapes (see the guardrails module header); this prints the one
 * the event reads and nothing else, so an unrelated field never reaches
 * Cursor.
 *
 *   beforeShellExecution, beforeMCPExecution, beforeReadFile
 *       { permission: "deny" | "ask", user_message, agent_message }
 *   preToolUse
 *       { decision: "deny", reason }. Cursor does not enforce "ask" here.
 *
 * A tool that has its own permission hook (a shell command, an MCP call, a
 * file read) is left to that hook when the verdict is "ask": preToolUse then
 * prints nothing, and the permission hook raises the prompt.
 */

export type CursorDecisionEvent = "preToolUse" | "beforeShellExecution" | "beforeMCPExecution" | "beforeReadFile";

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

export function cursorDecision(
  event: CursorDecisionEvent,
  output: Record<string, unknown> | null,
  opts: { hasPermissionHook?: boolean } = {},
): Record<string, unknown> | undefined {
  if (!output) return undefined;
  const asks = output.permission === "ask";
  if (event === "preToolUse") {
    if (asks && opts.hasPermissionHook) return undefined;
    const reason = str(output.reason);
    return { decision: "deny", ...(reason ? { reason } : {}) };
  }
  const permission = asks ? "ask" : "deny";
  const user = str(output.user_message);
  const agent = str(output.agent_message);
  return { permission, ...(user ? { user_message: user } : {}), ...(agent ? { agent_message: agent } : {}) };
}
