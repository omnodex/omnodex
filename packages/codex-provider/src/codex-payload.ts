// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Codex hook payload schema (from https://developers.openai.com/codex/hooks,
 * verified against Codex Desktop on 2026-09-21) plus a pure mapper from
 * payloads to TraceEvents.
 *
 * Coverage notes:
 *
 *   - Local Bash/unified-exec, apply_patch, MCP and function tools are visible.
 *     Hosted tools are not visible to local hooks.
 *   - Current SessionEnd payloads report reason "other".
 *   - Codex has no PostToolUseFailure event. In live failure captures, failed
 *     apply_patch, MCP and local function calls emitted PreToolUse only. A
 *     nonzero Bash call emitted PostToolUse without an exit code. The mapper
 *     therefore does not invent error completions from unreliable evidence.
 *   - Stop also maps to session.ended (Codex fires both; duplicates are harmless).
 *   - UserPromptSubmit fires before each user turn. No TraceEvent type exists
 *     for it yet, so the mapper returns [] and the shim discards it cleanly.
 *   - SubagentStart/SubagentStop fire on subagent lifecycle (added 2026-07).
 *     No TraceEvent type yet; mapper returns [].
 *   - PermissionRequest, PreCompact, PostCompact and Interrupt have no
 *     TraceEvent types yet; the mapper returns [].
 *   - Hooks are enabled by default in recent versions (no config.toml toggle needed).
 *
 * When Codex expands hook coverage, add the new tool names to the appropriate
 * sets below and add file.read / file.written mapping in maybeFilesystemEvent.
 *
 * Keeping the mapper as a pure function makes it trivially unit-testable.
 */

import type {
  FileWrittenEvent,
  SessionEndedEvent,
  SessionStartedEvent,
  ToolCompletedEvent,
  ToolInvokedEvent,
  TraceEvent,
} from "@omnodex/shared";
import { SCHEMA_VERSION, splitMcpToolName } from "@omnodex/shared";

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

export type CodexHookEventName =
  | "SessionStart"
  | "SessionEnd"
  | "PreToolUse"
  | "PostToolUse"
  | "UserPromptSubmit"
  | "Stop"
  | "SubagentStart"
  | "SubagentStop"
  | "PermissionRequest"
  | "PreCompact"
  | "PostCompact"
  | "Interrupt";

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

export interface CodexSessionEndPayload extends CodexHookBase {
  hook_event_name: "SessionEnd";
  /** Codex currently reports "other" for every session end. */
  reason?: "other";
  duration_ms?: number;
}

export interface CodexPreToolUsePayload extends CodexHookBase {
  hook_event_name: "PreToolUse";
  /** Codex-specific turn identifier. */
  turn_id?: string;
  /** Local tool name, including Bash, apply_patch, MCP and local functions. */
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

export interface CodexSubagentStartPayload extends CodexHookBase {
  hook_event_name: "SubagentStart";
  /** Identifier of the subagent being spawned. */
  subagent_id: string;
  /** Type of subagent. */
  subagent_type?: string;
  prompt?: string;
}

export interface CodexSubagentStopPayload extends CodexHookBase {
  hook_event_name: "SubagentStop";
  subagent_id: string;
  reason?: "completed" | "errored" | "interrupted";
  duration_ms?: number;
}

export interface CodexPermissionRequestPayload extends CodexHookBase {
  hook_event_name: "PermissionRequest";
  turn_id?: string;
  /** The tool or action requesting permission. */
  tool_name?: string;
  /** The permission being requested (e.g. "execute", "write"). */
  permission_type?: string;
}

export interface CodexPreCompactPayload extends CodexHookBase {
  hook_event_name: "PreCompact";
  trigger?: "manual" | "auto";
}

export interface CodexPostCompactPayload extends CodexHookBase {
  hook_event_name: "PostCompact";
  trigger?: "manual" | "auto";
}

export interface CodexInterruptPayload extends CodexHookBase {
  hook_event_name: "Interrupt";
}

export type CodexHookPayload =
  | CodexSessionStartPayload
  | CodexSessionEndPayload
  | CodexPreToolUsePayload
  | CodexPostToolUsePayload
  | CodexUserPromptSubmitPayload
  | CodexStopPayload
  | CodexSubagentStartPayload
  | CodexSubagentStopPayload
  | CodexPermissionRequestPayload
  | CodexPreCompactPayload
  | CodexPostCompactPayload
  | CodexInterruptPayload;

// ---------------------------------------------------------------------------
// Mapper options
// ---------------------------------------------------------------------------

export interface MapperOptions {
  newEventId: () => string;
  nowIso?: () => string;
}

// ---------------------------------------------------------------------------
// Tool coverage
// ---------------------------------------------------------------------------

/**
 * Local tool families observed in real Codex Desktop hook payloads. This is
 * documentation, not an allowlist: arbitrary local function names also pass
 * through the wildcard tool hooks.
 */
export const CODEX_INTERCEPTED_TOOL_FAMILIES = [
  "Bash and unified exec",
  "apply_patch",
  "MCP tools",
  "local functions",
] as const;

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
      out.push(...applyPatchFileEvents(payload, base, options.newEventId));
      return out;
    }

    case "SessionEnd": {
      const event: SessionEndedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.ended",
        duration_ms: payload.duration_ms ?? 0,
        // Current Codex payloads only expose reason "other", which cannot
        // distinguish success, error or interruption.
        status: "completed",
      };
      return [event];
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
    case "SubagentStart":
    case "SubagentStop":
    case "PermissionRequest":
    case "PreCompact":
    case "PostCompact":
    case "Interrupt":
      // No TraceEvent types for these yet. Capture the payload so the
      // shim does not warn, but emit nothing until the shared schema
      // gains subagent, prompt, and permission event types.
      return [];
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mcpServerFor(toolName: string): string {
  return splitMcpToolName(toolName)?.mcpServer ?? "builtin";
}

function applyPatchFileEvents(
  payload: CodexPostToolUsePayload,
  base: Omit<TraceEvent, "event_id" | "event_type">,
  newEventId: () => string,
): FileWrittenEvent[] {
  if (payload.tool_name !== "apply_patch") return [];
  const patch = payload.tool_input.command;
  if (typeof patch !== "string") return [];

  const events: FileWrittenEvent[] = [];
  const header = /^\*\*\* (?:Add|Update) File: (.+)$/gm;
  for (const match of patch.matchAll(header)) {
    const filePath = match[1]?.trim();
    if (!filePath) continue;
    events.push({
      ...base,
      event_id: newEventId(),
      event_type: "file.written",
      path: filePath,
      // The patch result does not report bytes written. Zero is explicit
      // unknown data rather than a response-size proxy.
      bytes: 0,
    });
  }
  return events;
}

function estimateResponseBytes(response: unknown): number {
  if (response === undefined || response === null) return 0;
  try {
    return Buffer.byteLength(JSON.stringify(response), "utf8");
  } catch {
    return 0;
  }
}
