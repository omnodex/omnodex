// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Claude Code hook payload schema (as verified against the live docs
 * at https://code.claude.com/docs/en/hooks on 2026-04-11) plus a pure
 * function that maps a payload into zero or more Omnodex `TraceEvent`s.
 *
 * Keeping the mapper as a pure function (no fs, no event log, no clock
 * except `nowIso`) makes it trivially unit-testable. The shim CLI and
 * the `ClaudeCodeInterceptor` both import it and are the only places
 * that know about Claude Code specifics.
 *
 * NOTE: several assumptions in the original design turned out to be
 * wrong. The real schema is summarized in
 * docs/claude-code-hook-integration.md, section "Findings".
 */

import type {
  FileReadEvent,
  FileWrittenEvent,
  PermissionDeniedEvent,
  PermissionRequestedEvent,
  PromptSubmittedEvent,
  SessionEndedEvent,
  SessionStartedEvent,
  ToolCompletedEvent,
  ToolInvokedEvent,
  SubagentStartedEvent,
  SubagentStoppedEvent,
  TraceEvent,
} from "@omnodex/shared";
import { SCHEMA_VERSION, splitMcpToolName } from "@omnodex/shared";

// Kept as a compatibility export for consumers that previously imported the
// parser from this package. New code should import it from @omnodex/shared.
export { splitMcpToolName } from "@omnodex/shared";

/**
 * The hook event names we subscribe to from Claude Code.
 *
 * Core events: SessionStart, SessionEnd, PreToolUse, PostToolUse,
 * PostToolUseFailure.
 *
 * Extended events: SubagentStart, SubagentStop, UserPromptSubmit,
 * PermissionRequest and PermissionDenied, mapped to subagent.started,
 * subagent.stopped, prompt.submitted, permission.requested and
 * permission.denied. Field names were read from the Claude Code build that
 * sends them (2.1.287).
 */
export type ClaudeCodeHookEventName =
  | "SessionStart"
  | "SessionEnd"
  | "PreToolUse"
  | "PostToolUse"
  | "PostToolUseFailure"
  | "SubagentStart"
  | "SubagentStop"
  | "UserPromptSubmit"
  | "PermissionRequest"
  | "PermissionDenied";

/** Shared fields Claude Code passes on every hook invocation. */
export interface ClaudeCodeHookBase {
  session_id: string;
  transcript_path?: string;
  cwd?: string;
  permission_mode?: string;
  hook_event_name: ClaudeCodeHookEventName;
  /**
   * The subagent the hook fired in; absent in the main thread. On
   * SubagentStart and SubagentStop it is the subagent itself.
   */
  agent_id?: string;
  /** The subagent's type, or the --agent the session runs as. */
  agent_type?: string;
  /** Prompt identifier for multi-turn tracking (added in Claude Code 2026-07). */
  prompt_id?: string;
}

export interface ClaudeCodeSessionStartPayload extends ClaudeCodeHookBase {
  hook_event_name: "SessionStart";
  /** Optional. Present in some Claude Code builds. */
  user?: string;
  /** Optional. List of MCP servers registered at session start. */
  mcp_servers?: string[];
}

export interface ClaudeCodeSessionEndPayload extends ClaudeCodeHookBase {
  hook_event_name: "SessionEnd";
  /** How the session ended. Present in recent builds. */
  reason?: "completed" | "errored" | "interrupted";
  duration_ms?: number;
}

export interface ClaudeCodePreToolUsePayload extends ClaudeCodeHookBase {
  hook_event_name: "PreToolUse";
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_use_id: string;
}

export interface ClaudeCodePostToolUsePayload extends ClaudeCodeHookBase {
  hook_event_name: "PostToolUse";
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response: unknown;
  tool_use_id: string;
  /** Optional duration in ms, if Claude Code provides it. */
  duration_ms?: number;
}

export interface ClaudeCodePostToolUseFailurePayload extends ClaudeCodeHookBase {
  hook_event_name: "PostToolUseFailure";
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_use_id: string;
  error: string;
  is_interrupt?: boolean;
  duration_ms?: number;
}

export interface ClaudeCodeSubagentStartPayload extends ClaudeCodeHookBase {
  hook_event_name: "SubagentStart";
  /** Identifier of the subagent being started. */
  agent_id: string;
  /** Subagent type (Explore, Plan, general-purpose, a custom agent). */
  agent_type?: string;
}

export interface ClaudeCodeSubagentStopPayload extends ClaudeCodeHookBase {
  hook_event_name: "SubagentStop";
  agent_id: string;
  agent_type?: string;
  /** The subagent's own transcript. */
  agent_transcript_path?: string;
  /** The subagent's final response. Only its size is recorded. */
  last_assistant_message?: string;
  stop_hook_active?: boolean;
  /** Not sent by Claude Code; the shim measures it from SubagentStart. */
  duration_ms?: number;
}

export interface ClaudeCodeUserPromptSubmitPayload extends ClaudeCodeHookBase {
  hook_event_name: "UserPromptSubmit";
  /** The user's prompt text. */
  prompt: string;
  /** The session's title at the time, when it has one. */
  session_title?: string;
}

/**
 * Claude Code is about to ask the user to allow a tool call. Not every call
 * asks: whether one does depends on the session's permission settings.
 */
export interface ClaudeCodePermissionRequestPayload extends ClaudeCodeHookBase {
  hook_event_name: "PermissionRequest";
  tool_name: string;
  tool_input: Record<string, unknown>;
  /** Rules the user could add to stop being asked. Not recorded. */
  permission_suggestions?: unknown;
  /** The MCP server that owns the tool, when it is an MCP tool. */
  mcp_server?: string;
}

/** A tool call was refused, by the user, a rule or the permission classifier. */
export interface ClaudeCodePermissionDeniedPayload extends ClaudeCodeHookBase {
  hook_event_name: "PermissionDenied";
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_use_id?: string;
  reason?: string;
  mcp_server?: string;
}

export type ClaudeCodeHookPayload =
  | ClaudeCodeSessionStartPayload
  | ClaudeCodeSessionEndPayload
  | ClaudeCodePreToolUsePayload
  | ClaudeCodePostToolUsePayload
  | ClaudeCodePostToolUseFailurePayload
  | ClaudeCodeSubagentStartPayload
  | ClaudeCodeSubagentStopPayload
  | ClaudeCodeUserPromptSubmitPayload
  | ClaudeCodePermissionRequestPayload
  | ClaudeCodePermissionDeniedPayload;

/**
 * Single-file read tools: the tool_input carries a specific file path.
 * Multi-file read tools: the tool_input carries a glob pattern or search
 * pattern, not a file path. Grep's `path` parameter is the search root
 * directory (not a file), so it is excluded from path extraction.
 */
const SINGLE_FILE_READ_TOOLS = new Set(["Read", "NotebookRead"]);
const MULTI_FILE_READ_TOOLS = new Set(["Glob", "Grep"]);
/** Union used externally (e.g. mock interceptor) to check if a tool is a read. */
export const FILE_READ_TOOLS = new Set([...SINGLE_FILE_READ_TOOLS, ...MULTI_FILE_READ_TOOLS]);
const FILE_WRITE_TOOLS = new Set(["Write", "Edit", "NotebookEdit"]);

/**
 * The input key that holds the file-pattern for each multi-file read tool.
 * Grep uses "glob" (e.g. "**\/*.md"); Glob uses "pattern" (e.g. "src/**\/*.ts").
 * Neither uses "path" as a file path — for Grep, "path" is a directory root.
 */
const MULTI_FILE_PATTERN_KEY: Record<string, string> = {
  Grep: "glob",
  Glob: "pattern",
};

/**
 * Options accepted by the mapper. The clock is injectable so tests can
 * produce deterministic `recorded_at` timestamps.
 */
export interface MapperOptions {
  /** Called once per emitted event to produce a unique id. */
  newEventId: () => string;
  /** Returns the current wall-clock time as ISO 8601. */
  nowIso?: () => string;
}

/**
 * Map a single Claude Code hook payload into zero or more TraceEvents.
 *
 * Conventions:
 *
 * 1. Every TraceEvent produced has `interceptor = "claude-code-hook"`.
 * 2. `occurred_at` is the clock read by the mapper, because Claude Code
 *    does not publish a per-event timestamp in its payload. Since the
 *    shim runs synchronously with the hook firing, the drift is bounded
 *    by subprocess startup cost.
 * 3. A PreToolUse for a Read / Glob / Grep call emits both a
 *    `tool.invoked` event and, only once we know the response on
 *    PostToolUse, a `file.read` event. That is why PreToolUse alone
 *    emits only `tool.invoked`.
 * 4. A PostToolUse for Write / Edit emits `tool.completed` and then
 *    `file.written` if the tool_input carries a file path.
 * 5. PostToolUseFailure emits `tool.completed` with status=error.
 */
export function mapClaudeCodePayload(
  payload: ClaudeCodeHookPayload,
  options: MapperOptions,
): TraceEvent[] {
  const now = (options.nowIso ?? (() => new Date().toISOString()))();
  const base = {
    schema_version: SCHEMA_VERSION,
    session_id: payload.session_id,
    occurred_at: now,
    recorded_at: now,
    interceptor: "claude-code-hook" as const,
    // Work done inside a subagent is attributed to it.
    ...(payload.agent_id ? { agent_id: payload.agent_id } : {}),
  };

  switch (payload.hook_event_name) {
    case "SessionStart": {
      const event: SessionStartedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.started",
        user: payload.user ?? payload.agent_id ?? "unknown",
        project_path: payload.cwd ?? "unknown",
        mcp_servers: payload.mcp_servers ?? [],
      };
      return [event];
    }

    case "SessionEnd": {
      const event: SessionEndedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.ended",
        duration_ms: payload.duration_ms ?? 0,
        status: payload.reason ?? "completed",
      };
      return [event];
    }

    case "PreToolUse": {
      const event: ToolInvokedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "tool.invoked",
        tool_call_id: payload.tool_use_id,
        tool_name: payload.tool_name,
        mcp_server: mcpServerFor(payload.tool_name),
        parameters: payload.tool_input,
        cwd: payload.cwd,
      };
      return [event];
    }

    case "PostToolUse": {
      const out: TraceEvent[] = [];
      const completed: ToolCompletedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "tool.completed",
        tool_call_id: payload.tool_use_id,
        duration_ms: payload.duration_ms ?? 0,
        status: "success",
        response_bytes: estimateResponseBytes(payload.tool_response),
      };
      out.push(completed);

      const fsEvent = maybeFilesystemEvent(
        payload.tool_name,
        payload.tool_input,
        payload.tool_response,
        base,
        options.newEventId,
      );
      if (fsEvent) out.push(fsEvent);
      return out;
    }

    case "PostToolUseFailure": {
      const completed: ToolCompletedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "tool.completed",
        tool_call_id: payload.tool_use_id,
        duration_ms: payload.duration_ms ?? 0,
        status: "error",
        response_bytes: 0,
        error_message: payload.error,
      };
      return [completed];
    }

    case "UserPromptSubmit": {
      if (typeof payload.prompt !== "string") return [];
      const event: PromptSubmittedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "prompt.submitted",
        prompt: payload.prompt,
        ...(payload.prompt_id ? { prompt_id: payload.prompt_id } : {}),
      };
      return [event];
    }

    case "PermissionRequest": {
      if (typeof payload.tool_name !== "string" || !payload.tool_name) return [];
      const event: PermissionRequestedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "permission.requested",
        tool_name: payload.tool_name,
        mcp_server: payload.mcp_server || mcpServerFor(payload.tool_name),
        parameters: payload.tool_input ?? {},
      };
      return [event];
    }

    case "PermissionDenied": {
      if (typeof payload.tool_name !== "string" || !payload.tool_name) return [];
      const event: PermissionDeniedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "permission.denied",
        tool_name: payload.tool_name,
        mcp_server: payload.mcp_server || mcpServerFor(payload.tool_name),
        parameters: payload.tool_input ?? {},
        ...(payload.tool_use_id ? { tool_call_id: payload.tool_use_id } : {}),
        ...(payload.reason ? { reason: payload.reason } : {}),
      };
      return [event];
    }

    case "SubagentStart": {
      if (!payload.agent_id) return [];
      const event: SubagentStartedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "subagent.started",
        agent_id: payload.agent_id,
        ...(payload.agent_type ? { agent_type: payload.agent_type } : {}),
      };
      return [event];
    }

    case "SubagentStop": {
      if (!payload.agent_id) return [];
      const event: SubagentStoppedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "subagent.stopped",
        agent_id: payload.agent_id,
        ...(payload.agent_type ? { agent_type: payload.agent_type } : {}),
        ...(payload.duration_ms !== undefined ? { duration_ms: payload.duration_ms } : {}),
        ...(typeof payload.last_assistant_message === "string"
          ? { response_bytes: Buffer.byteLength(payload.last_assistant_message, "utf8") }
          : {}),
      };
      return [event];
    }
  }
}

/**
 * Heuristic mapping from a tool name to its logical "MCP server".
 * Built-in tools do not belong to an MCP, but downstream queries are much
 * cleaner if they all carry a non-empty mcp_server field.
 */
function mcpServerFor(toolName: string): string {
  return splitMcpToolName(toolName)?.mcpServer ?? "builtin";
}

/** Best-effort byte count of the tool response for the read model. */
function estimateResponseBytes(response: unknown): number {
  if (response === undefined || response === null) return 0;
  try {
    return Buffer.byteLength(JSON.stringify(response), "utf8");
  } catch {
    return 0;
  }
}

/**
 * Produce a `file.read` or `file.written` event from a tool call if the
 * tool is one of the built-in filesystem tools.
 *
 * Single-file reads (Read, NotebookRead): path comes from file_path / path /
 * filePath in tool_input; bytes estimated from tool_response content.
 *
 * Multi-file reads (Grep, Glob): path is the glob/pattern being searched,
 * NOT the optional "path" directory root that Grep sometimes includes.
 * One file.read event is emitted per invocation. The byte count covers the
 * response (matched results), not the individual files scanned. This is a
 * known approximation — the hook layer cannot observe how many files were
 * actually opened. See integration doc open item 8 for full rationale.
 *
 * Writes (Write, Edit, NotebookEdit): path from file_path / path / filePath;
 * bytes from the write content in tool_input, falling back to response size.
 */
function maybeFilesystemEvent(
  toolName: string,
  toolInput: Record<string, unknown>,
  toolResponse: unknown,
  base: Omit<TraceEvent, "event_id" | "event_type">,
  newEventId: () => string,
): FileReadEvent | FileWrittenEvent | null {
  if (SINGLE_FILE_READ_TOOLS.has(toolName)) {
    const path = firstString(toolInput, ["file_path", "path", "filePath"]);
    if (!path) return null;
    return {
      ...base,
      event_id: newEventId(),
      event_type: "file.read",
      path,
      bytes: estimateResponseBytes(toolResponse),
    };
  }

  if (MULTI_FILE_READ_TOOLS.has(toolName)) {
    const patternKey = MULTI_FILE_PATTERN_KEY[toolName];
    const path = patternKey ? firstString(toolInput, [patternKey]) : null;
    if (!path) return null;
    return {
      ...base,
      event_id: newEventId(),
      event_type: "file.read",
      path,
      bytes: estimateResponseBytes(toolResponse),
    };
  }

  if (FILE_WRITE_TOOLS.has(toolName)) {
    const path = firstString(toolInput, ["file_path", "path", "filePath"]);
    if (!path) return null;
    return {
      ...base,
      event_id: newEventId(),
      event_type: "file.written",
      path,
      bytes: responseBytesHeuristic(toolInput, toolResponse),
    };
  }

  return null;
}

function firstString(
  obj: Record<string, unknown>,
  keys: readonly string[],
): string | null {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === "string") return value;
  }
  return null;
}

function responseBytesHeuristic(
  toolInput: Record<string, unknown>,
  toolResponse: unknown,
): number {
  // For Write, the written content lives in "content".
  // For Edit / NotebookEdit, the replacement lives in "new_string".
  // Fall back to the JSON size of the tool response for anything else.
  const content = toolInput.content ?? toolInput.new_string;
  if (typeof content === "string") {
    return Buffer.byteLength(content, "utf8");
  }
  return estimateResponseBytes(toolResponse);
}
