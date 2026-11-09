// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The envelopes the OpenCode plugin sends (see plugin-source.ts), normalized,
 * and a mapper from them to TraceEvents. The envelope is Omnodex's own, so
 * its shape does not depend on OpenCode's event objects; only the plugin
 * knows those.
 *
 * OpenCode's tool names are lowercase (`bash`, `read`, `edit`) and its
 * arguments camelCase (`filePath`, `oldString`). They are mapped to the
 * Claude Code names and fields the shared mapper and the rules read. A tool
 * with any other name (an MCP tool or a custom tool) keeps its name.
 */

import type { TraceEvent } from "@omnodex/shared";
import { mapClaudeCodePayload, type ClaudeCodeHookPayload } from "@omnodex/hooks-provider";

export type OpenCodeEventName =
  | "session.start"
  | "session.end"
  | "prompt"
  | "tool.before"
  | "tool.after"
  | "tool.error"
  | "subagent.start"
  | "subagent.stop";

const KNOWN_EVENTS: ReadonlySet<string> = new Set<OpenCodeEventName>([
  "session.start", "session.end", "prompt", "tool.before", "tool.after", "tool.error", "subagent.start", "subagent.stop",
]);

export interface OpenCodePayload {
  event: OpenCodeEventName;
  /** The root session; a subagent's own session is `agentId`. */
  sessionId: string;
  agentId?: string;
  agentType?: string;
  cwd?: string;
  timestamp?: string;
  model?: string;
  prompt?: string;
  toolName?: string;
  callId?: string;
  toolInput: Record<string, unknown>;
  toolResult?: unknown;
  durationMs?: number;
  error?: string;
  reason?: string;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function isoOf(value: unknown): string | undefined {
  const ms = typeof value === "string" ? Date.parse(value) : NaN;
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

/** The envelope in one shape, or null when it is not one we handle. */
export function normalizeOpenCodePayload(input: unknown): OpenCodePayload | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const raw = input as Record<string, unknown>;
  const event = str(raw.event);
  const sessionId = str(raw.session_id);
  if (!event || !KNOWN_EVENTS.has(event) || !sessionId) return null;
  const args = raw.args && typeof raw.args === "object" && !Array.isArray(raw.args) ? (raw.args as Record<string, unknown>) : {};
  const duration = typeof raw.duration_ms === "number" && Number.isFinite(raw.duration_ms) && raw.duration_ms >= 0 ? raw.duration_ms : undefined;
  return {
    event: event as OpenCodeEventName,
    sessionId,
    agentId: str(raw.agent_id),
    agentType: str(raw.agent_type),
    cwd: str(raw.cwd),
    timestamp: isoOf(raw.ts),
    model: str(raw.model),
    prompt: typeof raw.prompt === "string" ? raw.prompt : undefined,
    toolName: str(raw.tool),
    callId: str(raw.call_id),
    toolInput: args,
    toolResult: raw.output,
    durationMs: duration,
    error: typeof raw.error === "string" ? raw.error : undefined,
    reason: str(raw.reason),
  };
}

const RENAMES: Readonly<Record<string, string>> = {
  filePath: "file_path",
  oldString: "old_string",
  newString: "new_string",
  include: "glob",
};

/** OpenCode's tool name and arguments as Claude Code's. */
export function claudeTool(toolName: string, input: Record<string, unknown>): { name: string; input: Record<string, unknown> } {
  const mapped: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) mapped[RENAMES[k] ?? k] = v;
  switch (toolName) {
    case "bash": return { name: "Bash", input: mapped };
    case "read": return { name: "Read", input: mapped };
    case "write": return { name: "Write", input: mapped };
    case "edit": return { name: "Edit", input: mapped };
    case "glob": return { name: "Glob", input: mapped };
    case "grep": return { name: "Grep", input: mapped };
    case "task": return { name: "Task", input: mapped };
    case "webfetch": return { name: "WebFetch", input: mapped };
    default: return { name: toolName, input: mapped };
  }
}

export interface OpenCodeMapperOptions {
  newEventId: () => string;
  nowIso?: () => string;
  /** The id of this call when the plugin sent none. */
  callId?: string;
}

/** How a session end reads as ours. */
export function sessionEndStatus(reason: string | undefined): "completed" | "errored" | "interrupted" {
  if (reason === "error") return "errored";
  if (reason === "aborted" || reason === "interrupted") return "interrupted";
  return "completed";
}

/** Map one envelope to zero or more TraceEvents, all labeled as OpenCode's. */
export function mapOpenCodePayload(payload: OpenCodePayload, options: OpenCodeMapperOptions): TraceEvent[] {
  const callId = payload.callId ?? options.callId ?? "";
  const sub = payload.event === "subagent.start" || payload.event === "subagent.stop";
  const base = {
    session_id: payload.sessionId,
    cwd: payload.cwd,
    ...(payload.agentId ? { agent_id: payload.agentId } : {}),
    ...(sub && payload.agentType ? { agent_type: payload.agentType } : {}),
  };

  let claude: ClaudeCodeHookPayload;
  switch (payload.event) {
    case "session.start":
      claude = { ...base, hook_event_name: "SessionStart", user: "opencode" };
      break;
    case "session.end":
      claude = { ...base, hook_event_name: "SessionEnd", reason: sessionEndStatus(payload.reason) };
      break;
    case "prompt":
      claude = { ...base, hook_event_name: "UserPromptSubmit", prompt: payload.prompt ?? "" };
      break;
    case "tool.before": {
      if (!payload.toolName) return [];
      const tool = claudeTool(payload.toolName, payload.toolInput);
      claude = { ...base, hook_event_name: "PreToolUse", tool_name: tool.name, tool_input: tool.input, tool_use_id: callId };
      break;
    }
    case "tool.after": {
      if (!payload.toolName) return [];
      const tool = claudeTool(payload.toolName, payload.toolInput);
      claude = {
        ...base, hook_event_name: "PostToolUse", tool_name: tool.name, tool_input: tool.input,
        tool_response: payload.toolResult, tool_use_id: callId, duration_ms: payload.durationMs,
      };
      break;
    }
    case "tool.error": {
      if (!payload.toolName) return [];
      const tool = claudeTool(payload.toolName, payload.toolInput);
      claude = {
        ...base, hook_event_name: "PostToolUseFailure", tool_name: tool.name, tool_input: tool.input,
        tool_use_id: callId, error: payload.error ?? "tool call failed", duration_ms: payload.durationMs,
      };
      break;
    }
    case "subagent.start":
      if (!payload.agentId) return [];
      claude = { ...base, hook_event_name: "SubagentStart", agent_id: payload.agentId };
      break;
    case "subagent.stop":
      if (!payload.agentId) return [];
      claude = { ...base, hook_event_name: "SubagentStop", agent_id: payload.agentId };
      break;
  }

  return mapClaudeCodePayload(claude, { newEventId: options.newEventId, nowIso: options.nowIso }).map((event) => ({
    ...event,
    interceptor: "opencode-plugin" as const,
    platform: "opencode" as const,
    ...(payload.timestamp ? { occurred_at: payload.timestamp } : {}),
  })) as TraceEvent[];
}
