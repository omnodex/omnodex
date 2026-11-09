// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Cursor hook payloads, normalized, and a mapper from them to TraceEvents.
 *
 * Every Cursor hook payload carries `conversation_id` (the session),
 * `generation_id` (one agent turn), `hook_event_name`, `workspace_roots`,
 * `transcript_path`, `model` and the signed-in user's `user_email`. The email
 * is never read here: the normalized payload has no field for it, so it
 * cannot reach an event, the log or a sync.
 *
 * Which events record what:
 *
 *   sessionStart, sessionEnd, beforeSubmitPrompt, subagentStart,
 *   subagentStop, preToolUse, postToolUse, postToolUseFailure
 *       recorded. preToolUse and its post-hooks fire for every tool, shell
 *       commands, MCP calls and file reads included, and carry `tool_use_id`,
 *       so they are the only source of tool calls.
 *   beforeShellExecution, beforeMCPExecution, beforeReadFile
 *       judged for guardrails only (they can raise Cursor's own prompt) and
 *       never recorded, so a call is not recorded twice.
 *   afterShellExecution, afterMCPExecution, afterFileEdit, stop and the rest
 *       not subscribed.
 *
 * Cursor's tool names are mapped to the Claude Code names the shared mapper
 * and the rules know: Shell is Bash, StrReplace is Edit, an MCP tool is
 * `mcp__<server>__<tool>`.
 */

import type { TraceEvent } from "@omnodex/shared";
import { mapClaudeCodePayload, type ClaudeCodeHookPayload } from "@omnodex/hooks-provider";

export type CursorHookEventName =
  | "sessionStart"
  | "sessionEnd"
  | "beforeSubmitPrompt"
  | "preToolUse"
  | "postToolUse"
  | "postToolUseFailure"
  | "subagentStart"
  | "subagentStop"
  | "beforeShellExecution"
  | "beforeMCPExecution"
  | "beforeReadFile";

const KNOWN_EVENTS: ReadonlySet<string> = new Set<CursorHookEventName>([
  "sessionStart", "sessionEnd", "beforeSubmitPrompt", "preToolUse", "postToolUse", "postToolUseFailure",
  "subagentStart", "subagentStop", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile",
]);

/** The hooks that only judge a call, for Cursor's own prompt. */
export const PERMISSION_EVENTS: ReadonlySet<CursorHookEventName> = new Set<CursorHookEventName>([
  "beforeShellExecution", "beforeMCPExecution", "beforeReadFile",
]);

/** The tools whose calls also pass a permission hook. */
const PERMISSION_TOOLS = /^(Shell|Read|MCP(:.*)?)$/;

/** True for a preToolUse tool that has its own permission hook (a shell command, an MCP call, a file read). */
export function hasPermissionHook(toolName: string | undefined): boolean {
  return !!toolName && PERMISSION_TOOLS.test(toolName);
}

/** A Cursor hook payload in one shape. No field holds the user's email. */
export interface CursorPayload {
  event: CursorHookEventName;
  /** Cursor's conversation id. */
  sessionId: string;
  generationId?: string;
  model?: string;
  /** The first workspace root: the project. */
  cwd?: string;
  toolName?: string;
  toolInput: Record<string, unknown>;
  toolResult?: unknown;
  error?: string;
  /** Cursor's id for the call, on preToolUse and its post-hooks. */
  callId?: string;
  durationMs?: number;
  prompt?: string;
  /** Why a session ended. */
  reason?: string;
  subagentId?: string;
  subagentType?: string;
  /** What a subagent returned, on subagentStop. */
  summary?: string;
  /** beforeMCPExecution: the MCP server's name. */
  server?: string;
  /** beforeShellExecution: the command. */
  command?: string;
  /** beforeReadFile: the file. */
  filePath?: string;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : undefined);

/** Tool input arrives as an object, or as a JSON string that holds one. */
function asObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value === "string" && value.trim().startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(value);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      // not JSON
    }
  }
  return {};
}

/** The payload in one shape, or null when it is not a Cursor hook payload we handle. */
export function normalizeCursorPayload(input: unknown): CursorPayload | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const raw = input as Record<string, unknown>;
  const named = str(raw.hook_event_name);
  if (!named || !KNOWN_EVENTS.has(named)) return null;
  const sessionId = str(raw.conversation_id) ?? str(raw.session_id);
  if (!sessionId) return null;
  const roots = Array.isArray(raw.workspace_roots) ? raw.workspace_roots : [];
  const err = raw.error_message ?? raw.error;
  const toolInput = asObject(raw.tool_input);
  const result = raw.tool_output ?? raw.result_json ?? raw.tool_response;
  return {
    event: named as CursorHookEventName,
    sessionId,
    generationId: str(raw.generation_id),
    model: str(raw.model),
    cwd: str(raw.cwd) ?? str(roots[0]),
    toolName: str(raw.tool_name),
    toolInput,
    toolResult: result,
    error: typeof err === "string" ? err : err && typeof err === "object" ? str((err as Record<string, unknown>).message) : undefined,
    callId: str(raw.tool_use_id),
    durationMs: num(raw.duration) ?? num(raw.duration_ms),
    prompt: typeof raw.prompt === "string" ? raw.prompt : undefined,
    reason: str(raw.reason),
    subagentId: str(raw.subagent_id),
    subagentType: str(raw.subagent_type),
    summary: str(raw.summary) ?? str(raw.result),
    server: str(raw.server),
    command: typeof raw.command === "string" ? raw.command : undefined,
    filePath: str(raw.file_path),
  };
}

/** Cursor's tool name and input as Claude Code's, which the mapper and the rules read. */
export function claudeTool(
  toolName: string,
  input: Record<string, unknown>,
  server?: string,
): { name: string; input: Record<string, unknown> } {
  if (toolName.startsWith("MCP:")) return { name: `mcp__${server ?? "cursor"}__${toolName.slice(4)}`, input };
  const filePath = input.file_path ?? input.path ?? input.target_file;
  const withPath = filePath !== undefined && input.file_path === undefined ? { ...input, file_path: filePath } : input;
  switch (toolName) {
    case "Shell":
      return { name: "Bash", input };
    case "Write": {
      const content = input.content ?? input.contents;
      return { name: "Write", input: content !== undefined && input.content === undefined ? { ...withPath, content } : withPath };
    }
    case "StrReplace":
    case "Edit":
      return { name: "Edit", input: withPath };
    case "Read":
    case "Grep":
    case "Glob":
      return { name: toolName, input: withPath };
    case "Task":
      return { name: "Task", input };
    default:
      return { name: toolName, input: withPath };
  }
}

export interface CursorMapperOptions {
  newEventId: () => string;
  nowIso?: () => string;
  /** The id of this call when the payload had none. */
  callId?: string;
}

/** Map one Cursor hook payload to zero or more TraceEvents, all labeled as Cursor's. */
export function mapCursorPayload(payload: CursorPayload, options: CursorMapperOptions): TraceEvent[] {
  const callId = payload.callId ?? options.callId ?? "";
  const sub = payload.event === "subagentStart" || payload.event === "subagentStop";
  const base = {
    session_id: payload.sessionId,
    cwd: payload.cwd,
    ...(sub && payload.subagentId ? { agent_id: payload.subagentId } : {}),
    ...(sub && payload.subagentType ? { agent_type: payload.subagentType } : {}),
  };

  let claude: ClaudeCodeHookPayload;
  switch (payload.event) {
    case "sessionStart":
      claude = { ...base, hook_event_name: "SessionStart", user: "cursor" };
      break;
    case "sessionEnd":
      claude = { ...base, hook_event_name: "SessionEnd", reason: sessionEndStatus(payload.reason) };
      break;
    case "beforeSubmitPrompt":
      claude = { ...base, hook_event_name: "UserPromptSubmit", prompt: payload.prompt ?? "" };
      break;
    case "preToolUse":
    case "beforeShellExecution":
    case "beforeMCPExecution":
    case "beforeReadFile": {
      const tool = permissionTool(payload);
      if (!tool) return [];
      claude = { ...base, hook_event_name: "PreToolUse", tool_name: tool.name, tool_input: tool.input, tool_use_id: callId };
      break;
    }
    case "postToolUse": {
      if (!payload.toolName) return [];
      const tool = claudeTool(payload.toolName, payload.toolInput, payload.server);
      claude = {
        ...base, hook_event_name: "PostToolUse", tool_name: tool.name, tool_input: tool.input,
        tool_response: payload.toolResult, tool_use_id: callId, duration_ms: payload.durationMs,
      };
      break;
    }
    case "postToolUseFailure": {
      if (!payload.toolName) return [];
      const tool = claudeTool(payload.toolName, payload.toolInput, payload.server);
      claude = {
        ...base, hook_event_name: "PostToolUseFailure", tool_name: tool.name, tool_input: tool.input,
        tool_use_id: callId, error: payload.error ?? "tool call failed", duration_ms: payload.durationMs,
      };
      break;
    }
    case "subagentStart":
      if (!payload.subagentId) return [];
      claude = { ...base, hook_event_name: "SubagentStart", agent_id: payload.subagentId };
      break;
    case "subagentStop":
      if (!payload.subagentId) return [];
      claude = {
        ...base, hook_event_name: "SubagentStop", agent_id: payload.subagentId,
        ...(payload.summary ? { last_assistant_message: payload.summary } : {}),
      };
      break;
  }

  return mapClaudeCodePayload(claude, { newEventId: options.newEventId, nowIso: options.nowIso }).map((event) => ({
    ...event,
    interceptor: "cursor-hook" as const,
    platform: "cursor" as const,
  })) as TraceEvent[];
}

/** The tool a call event describes, in Claude Code's terms. */
function permissionTool(payload: CursorPayload): { name: string; input: Record<string, unknown> } | null {
  switch (payload.event) {
    case "beforeShellExecution":
      return payload.command === undefined ? null : { name: "Bash", input: { command: payload.command } };
    case "beforeReadFile":
      return payload.filePath ? { name: "Read", input: { file_path: payload.filePath } } : null;
    case "beforeMCPExecution":
      return payload.toolName ? claudeTool(`MCP:${payload.toolName}`, payload.toolInput, payload.server) : null;
    default:
      return payload.toolName ? claudeTool(payload.toolName, payload.toolInput, payload.server) : null;
  }
}

/** How a Cursor session end reads as ours. */
export function sessionEndStatus(reason: string | undefined): "completed" | "errored" | "interrupted" {
  if (reason === "error") return "errored";
  if (reason === "aborted" || reason === "window_close" || reason === "user_close") return "interrupted";
  return "completed";
}
