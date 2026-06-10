// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Codex hook payload schema (from https://developers.openai.com/codex/hooks,
 * captured 2026-05-14) plus a pure mapper from payloads to TraceEvents.
 *
 * Coverage notes (Codex hooks are "Work in progress" as of 2026-05-14):
 *
 *   - PreToolUse/PostToolUse only fire for Bash today. Apply_patch (file
 *     writes), MCP tools, WebSearch, and unified_exec are NOT intercepted.
 *   - No PostToolUseFailure event in Codex.
 *   - Stop is the closest analog to Claude Code's SessionEnd.
 *   - UserPromptSubmit fires before each user turn. No TraceEvent type exists
 *     for it yet, so the mapper returns [] and the shim discards it cleanly.
 *
 * When Codex expands hook coverage, add the new tool names to the appropriate
 * sets below and add file.read / file.written mapping in maybeFilesystemEvent.
 *
 * Keeping the mapper as a pure function makes it trivially unit-testable.
 */

import type {
  SessionEndedEvent,
  SessionStartedEvent,
  ToolCompletedEvent,
  ToolInvokedEvent,
  TraceEvent,
} from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

export type CodexHookEventName =
  | "SessionStart"
  | "PreToolUse"
  | "PostToolUse"
  | "UserPromptSubmit"
  | "Stop";

/** Fields present on every Codex hook invocation. */
export interface CodexHookBase {
  session_id: string;
  transcript_path?: string | null;
  cwd: string;
  hook_event_name: CodexHookEventName;
  /** Active model slug, e.g. "codex-1". */
  model?: string;
}

export interface CodexSessionStartPayload extends CodexHookBase {
  hook_event_name: "SessionStart";
  /** "startup" for a fresh session, "resume" for a resumed one. */
  source?: "startup" | "resume";
}

export interface CodexPreToolUsePayload extends CodexHookBase {
  hook_event_name: "PreToolUse";
  /** Codex-specific turn identifier. */
  turn_id?: string;
  /** Tool name. Currently always "Bash" in Codex. */
  tool_name: string;
  tool_use_id: string;
  /** For Bash: { command: string }. Typed loosely for future tool expansion. */
  tool_input: Record<string, unknown>;
}

export interface CodexPostToolUsePayload extends CodexHookBase {
  hook_event_name: "PostToolUse";
  turn_id?: string;
  tool_name: string;
  tool_use_id: string;
  tool_input: Record<string, unknown>;
  tool_response: unknown;
  /** Not sent by Codex; injected by the shim via wall-clock timing. */
  duration_ms?: number;
}

export interface CodexUserPromptSubmitPayload extends CodexHookBase {
  hook_event_name: "UserPromptSubmit";
  turn_id?: string;
  prompt: string;
}

export interface CodexStopPayload extends CodexHookBase {
  hook_event_name: "Stop";
  turn_id?: string;
  /** True if this turn was already continued by a Stop hook. */
  stop_hook_active?: boolean;
  last_assistant_message?: string | null;
}

export type CodexHookPayload =
  | CodexSessionStartPayload
  | CodexPreToolUsePayload
  | CodexPostToolUsePayload
  | CodexUserPromptSubmitPayload
  | CodexStopPayload;

// ---------------------------------------------------------------------------
// Mapper options
// ---------------------------------------------------------------------------

export interface MapperOptions {
  newEventId: () => string;
  nowIso?: () => string;
}

// ---------------------------------------------------------------------------
// Tool classification (extend when Codex expands hook coverage)
// ---------------------------------------------------------------------------

/**
 * Tools that Codex currently intercepts via hooks.
 * Today this is only "Bash". Apply_patch, MCP tools, and WebSearch are
 * not yet intercepted (documented gap, see issue #20204).
 */
export const CODEX_INTERCEPTED_TOOLS = new Set(["Bash"]);

// ---------------------------------------------------------------------------
// Mapper
// ---------------------------------------------------------------------------

/**
 * Map a single Codex hook payload into zero or more Omnodex TraceEvents.
 *
 * Conventions:
 *   1. Every event has `interceptor = "codex-hook"`.
 *   2. `occurred_at` is the mapper clock because Codex does not publish
 *      per-event timestamps in its payload.
 *   3. PreToolUse emits `tool.invoked`.
 *   4. PostToolUse emits `tool.completed` (+ file events in the future).
 *   5. Stop maps to `session.ended` with status "completed".
 *   6. UserPromptSubmit returns [] — no TraceEvent type yet.
 */
export function mapCodexPayload(
  payload: CodexHookPayload,
  options: MapperOptions,
): TraceEvent[] {
  const now = (options.nowIso ?? (() => new Date().toISOString()))();
  const base = {
    schema_version: SCHEMA_VERSION,
    session_id: payload.session_id,
    occurred_at: now,
    recorded_at: now,
    interceptor: "codex-hook" as const,
  };

  switch (payload.hook_event_name) {
    case "SessionStart": {
      const event: SessionStartedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.started",
        user: "codex",
        project_path: payload.cwd,
        mcp_servers: [],
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
      const completed: ToolCompletedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "tool.completed",
        tool_call_id: payload.tool_use_id,
        duration_ms: payload.duration_ms ?? 0,
        status: "success",
        response_bytes: estimateResponseBytes(payload.tool_response),
      };
      return [completed];
      // TODO: add file.read / file.written here when Codex expands
      // hook coverage to apply_patch and other file tools.
    }

    case "Stop": {
      const event: SessionEndedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.ended",
        duration_ms: 0,
        status: "completed",
      };
      return [event];
    }

    case "UserPromptSubmit":
      // No TraceEvent type for user prompts yet. Discard cleanly.
      return [];
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mcpServerFor(toolName: string): string {
  // Codex may encode MCP tools with a similar prefix in the future.
  const match = toolName.match(/^mcp__([^_]+)__/);
  if (match) return match[1];
  return "builtin";
}

function estimateResponseBytes(response: unknown): number {
  if (response === undefined || response === null) return 0;
  try {
    return Buffer.byteLength(JSON.stringify(response), "utf8");
  } catch {
    return 0;
  }
}
