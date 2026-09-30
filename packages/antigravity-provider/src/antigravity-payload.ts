// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Antigravity hook payload schema and pure mapper from payloads to TraceEvents.
 *
 * Antigravity 2.0 (launched 2026-05-19) has its own hooks system documented at
 * https://antigravity.google/docs/hooks . Unlike our Codex integration, the
 * Antigravity payload schema uses camelCase fields and nests tool data under
 * a `toolCall` object.
 *
 * Supported events: PreInvocation, PostInvocation, PreToolUse, PostToolUse, Stop.
 * The first observed invocation starts capture; model calls never end it.
 * Only an idle Stop marks execution complete, not conversation deletion.
 *
 * Key differences from Codex:
 *   - Config directory is `.agents/` (not `.codex/`).
 *   - The binary is `agy` (Go-based, closed-source).
 *   - All Antigravity surfaces (CLI, Desktop, IDE) share a single
 *     "Shared Agent Harness" so hooks registered once apply everywhere.
 *   - Payload uses `conversationId` (not `session_id`).
 *   - PreToolUse nests tool info under `toolCall.name` / `toolCall.args`.
 *   - PostToolUse includes `toolCall`, `stepIdx`, and `error`, but no response.
 *   - Stop receives `executionNum`, `terminationReason`, `fullyIdle`.
 *   - Common fields: conversationId, workspacePaths, transcriptPath,
 *     artifactDirectoryPath.
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
import { SCHEMA_VERSION, splitMcpToolName } from "@omnodex/shared";

// ---------------------------------------------------------------------------
// Event names
// ---------------------------------------------------------------------------

export type AntigravityHookEventName =
  | "PreInvocation"
  | "PostInvocation"
  | "PreToolUse"
  | "PostToolUse"
  | "Stop";

// ---------------------------------------------------------------------------
// Common fields sent by Antigravity on every hook invocation
// ---------------------------------------------------------------------------

export interface AntigravityCommonFields {
  conversationId: string;
  workspacePaths: string[];
  transcriptPath: string;
  artifactDirectoryPath: string;
  modelName?: string;
}

// ---------------------------------------------------------------------------
// Per-event payload types (matching Antigravity's actual stdin schema)
// ---------------------------------------------------------------------------

export interface AntigravityPreInvocationPayload extends AntigravityCommonFields {
  invocationNum: number;
  initialNumSteps: number;
}

export interface AntigravityPostInvocationPayload extends AntigravityCommonFields {
  invocationNum: number;
  initialNumSteps: number;
}

export interface AntigravityPreToolUsePayload extends AntigravityCommonFields {
  toolCall: {
    name: string;
    args: Record<string, unknown>;
  };
  stepIdx: number;
}

export interface AntigravityPostToolUsePayload extends AntigravityCommonFields {
  toolCall?: AntigravityPreToolUsePayload["toolCall"];
  stepIdx: number;
  error?: string;
}

export interface AntigravityStopPayload extends AntigravityCommonFields {
  executionNum: number;
  terminationReason: string;
  error?: string;
  fullyIdle: boolean;
}

export type AntigravityHookPayload =
  | AntigravityPreInvocationPayload
  | AntigravityPostInvocationPayload
  | AntigravityPreToolUsePayload
  | AntigravityPostToolUsePayload
  | AntigravityStopPayload;

// ---------------------------------------------------------------------------
// Mapper options
// ---------------------------------------------------------------------------

export interface MapperOptions {
  newEventId: () => string;
  nowIso?: () => string;
  /** The shim deduplicates starts across processes, including resumed captures. */
  emitSessionStart?: boolean;
  sessionStartedAt?: string;
}

/**
 * Correlated data the shim provides for PostToolUse events by looking up
 * state saved during the preceding PreToolUse (keyed by stepIdx).
 */
export interface PostToolUseCorrelation {
  toolName: string | null;
  toolCallId: string | null;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Mapper
// ---------------------------------------------------------------------------

/**
 * Map a single Antigravity hook payload into zero or more Omnodex TraceEvents.
 *
 * Conventions:
 *   1. Every event has `interceptor = "antigravity-hook"`.
 *   2. `occurred_at` is the mapper clock because Antigravity does not
 *      publish per-event timestamps in its payload.
 *   3. Only the first invocation emits `session.started` by default.
 *   4. PostInvocation is a model-call signal and emits no session events.
 *   5. PreToolUse emits `tool.invoked`.
 *   6. PostToolUse emits `tool.completed` (tool name provided via correlation).
 *   7. Only a fully idle Stop maps to `session.ended`.
 */
export function mapAntigravityPayload(
  eventName: AntigravityHookEventName,
  payload: AntigravityHookPayload,
  options: MapperOptions,
  correlation?: PostToolUseCorrelation,
): TraceEvent[] {
  const now = (options.nowIso ?? (() => new Date().toISOString()))();
  const sessionId = (payload as AntigravityCommonFields).conversationId ?? "unknown";
  const base = {
    schema_version: SCHEMA_VERSION,
    session_id: sessionId,
    occurred_at: now,
    recorded_at: now,
    interceptor: "antigravity-hook" as const,
    platform: "antigravity" as const,
  };

  switch (eventName) {
    case "PreInvocation": {
      const p = payload as AntigravityPreInvocationPayload;
      if (!(options.emitSessionStart ?? (p.invocationNum === 0))) return [];
      const event: SessionStartedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.started",
        user: "antigravity",
        project_path: p.workspacePaths?.[0] ?? "unknown",
        mcp_servers: [],
      };
      return [event];
    }

    case "PostInvocation":
      return [];

    case "PreToolUse": {
      const p = payload as AntigravityPreToolUsePayload;
      const toolName = p.toolCall?.name ?? "unknown";
      const event: ToolInvokedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "tool.invoked",
        tool_call_id: antigravityToolCallId(sessionId, p.stepIdx),
        tool_name: toolName,
        mcp_server: mcpServerFor(toolName),
        parameters: p.toolCall?.args ?? {},
        cwd: p.workspacePaths?.[0] ?? "",
      };
      return [event];
    }

    case "PostToolUse": {
      const p = payload as AntigravityPostToolUsePayload;
      // Installed hooks observe after execution to avoid permission decisions.
      // Older PreToolUse hooks can still supply timing through correlation.
      const invoked = !correlation?.toolCallId && p.toolCall
        ? mapAntigravityPayload("PreToolUse", { ...p, toolCall: p.toolCall }, options)
        : [];
      const completed: ToolCompletedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "tool.completed",
        tool_call_id: correlation?.toolCallId ?? antigravityToolCallId(sessionId, p.stepIdx),
        duration_ms: correlation?.durationMs ?? 0,
        status: p.error ? "error" : "success",
        response_bytes: 0,
      };
      return [...invoked, completed];
    }

    case "Stop": {
      const p = payload as AntigravityStopPayload;
      if (p.fullyIdle !== true) return [];
      const elapsed = options.sessionStartedAt
        ? Date.parse(now) - Date.parse(options.sessionStartedAt)
        : 0;
      const event: SessionEndedEvent = {
        ...base,
        event_id: options.newEventId(),
        event_type: "session.ended",
        duration_ms: Number.isFinite(elapsed) ? Math.max(0, elapsed) : 0,
        status: p.error || p.terminationReason === "error" ? "errored" : "completed",
      };
      return [event];
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mcpServerFor(toolName: string): string {
  return splitMcpToolName(toolName)?.mcpServer ?? "builtin";
}

/** Read models key calls globally, while stepIdx is only conversation-local. */
export function antigravityToolCallId(conversationId: string, stepIdx: number): string {
  return `antigravity-${conversationId}-step-${stepIdx}`;
}
