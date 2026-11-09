// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Copilot hook payloads, normalized, and a mapper from them to TraceEvents.
 *
 * Omnodex registers its hooks under PascalCase event names. Copilot answers
 * a PascalCase name with the VS Code compatible payload: snake_case fields
 * (`session_id`, `tool_name`, `tool_input`, `tool_result`), an ISO timestamp
 * and Claude Code's tool names (`Bash`, `Read`, `Edit`). That is the shape
 * the Claude Code mapper already reads, so this file turns Copilot's fields
 * into that shape and reuses the mapper, then labels the events as Copilot's.
 * The camelCase form (`sessionId`, `toolName`, `toolArgs`) is accepted too,
 * for a hook registered under a camelCase name.
 *
 * Not recorded: `Stop` (the end of a turn, not of the session),
 * notifications and compaction. Copilot sends no model name and no call id;
 * see tool-ids.ts for the call id.
 */

import type { TraceEvent } from "@omnodex/shared";
import { mapClaudeCodePayload, type ClaudeCodeHookPayload } from "@omnodex/hooks-provider";

export type CopilotHookEventName =
  | "SessionStart"
  | "SessionEnd"
  | "UserPromptSubmit"
  | "PreToolUse"
  | "PostToolUse"
  | "PostToolUseFailure"
  | "PermissionRequest"
  | "SubagentStart"
  | "SubagentStop"
  | "Stop";

const KNOWN_EVENTS: ReadonlySet<string> = new Set<CopilotHookEventName>([
  "SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse",
  "PostToolUseFailure", "PermissionRequest", "SubagentStart", "SubagentStop", "Stop",
]);

/** camelCase names, for a payload that arrives without `hook_event_name`. */
const CAMEL_EVENTS: Readonly<Record<string, CopilotHookEventName>> = {
  sessionStart: "SessionStart",
  sessionEnd: "SessionEnd",
  userPromptSubmitted: "UserPromptSubmit",
  preToolUse: "PreToolUse",
  postToolUse: "PostToolUse",
  postToolUseFailure: "PostToolUseFailure",
  permissionRequest: "PermissionRequest",
  subagentStart: "SubagentStart",
  subagentStop: "SubagentStop",
  agentStop: "Stop",
};

/** A Copilot hook payload in one field naming, whichever Copilot sent. */
export interface CopilotPayload {
  event: CopilotHookEventName;
  sessionId: string;
  cwd?: string;
  /** ISO 8601, when the payload carried a usable timestamp. */
  timestamp?: string;
  toolName?: string;
  toolInput: Record<string, unknown>;
  toolResult?: unknown;
  error?: string;
  prompt?: string;
  /** How a session ended: complete, error, abort, timeout or user_exit. */
  reason?: string;
  source?: string;
  agentId?: string;
  agentType?: string;
  agentName?: string;
  lastAssistantMessage?: string;
  transcriptPath?: string;
  /** Call id Copilot sent, if it sent one. */
  callId?: string;
  /** Fields as received, for the double-capture check. */
  raw: Record<string, unknown>;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function pick(raw: Record<string, unknown>, ...keys: string[]): unknown {
  for (const k of keys) if (raw[k] !== undefined) return raw[k];
  return undefined;
}

/** Tool input arrives as an object, or as a JSON string that holds one. */
function asObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value === "string" && value.trim().startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(value);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      // not JSON: keep it as the command text below
    }
  }
  if (typeof value === "string") return { command: value };
  return {};
}

function isoOf(value: unknown): string | undefined {
  const ms = typeof value === "number" ? value : typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isFinite(ms)) return undefined;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** The payload in one naming, or null when it is not a Copilot hook payload we record. */
export function normalizeCopilotPayload(input: unknown): CopilotPayload | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const raw = input as Record<string, unknown>;
  const named = str(raw.hook_event_name) ?? str(raw.hookEventName) ?? str(raw.event) ?? str(raw.eventName);
  const event = named && KNOWN_EVENTS.has(named) ? (named as CopilotHookEventName) : named ? CAMEL_EVENTS[named] : undefined;
  const sessionId = str(pick(raw, "session_id", "sessionId"));
  if (!event || !sessionId) return null;

  const result = pick(raw, "tool_result", "toolResult", "tool_response", "toolResponse");
  const err = pick(raw, "error");
  const errorText = typeof err === "string" ? err : err && typeof err === "object" ? str((err as Record<string, unknown>).message) : undefined;
  return {
    event,
    sessionId,
    cwd: str(raw.cwd),
    timestamp: isoOf(raw.timestamp),
    toolName: str(pick(raw, "tool_name", "toolName")),
    toolInput: asObject(pick(raw, "tool_input", "toolInput", "toolArgs", "tool_args")),
    toolResult: result,
    error: errorText,
    prompt: typeof raw.prompt === "string" ? raw.prompt : undefined,
    reason: str(raw.reason),
    source: str(raw.source),
    agentId: str(pick(raw, "agent_id", "agentId")),
    agentType: str(pick(raw, "agent_type", "agentType")),
    agentName: str(pick(raw, "agent_name", "agentName")),
    lastAssistantMessage: str(pick(raw, "last_assistant_message", "response")),
    transcriptPath: str(pick(raw, "transcript_path", "transcriptPath")),
    callId: str(pick(raw, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId")),
    raw,
  };
}

export interface CopilotMapperOptions {
  newEventId: () => string;
  nowIso?: () => string;
  /**
   * The id of this tool call. The shim supplies Copilot's own when it sent
   * one, otherwise the id it made on the matching pre-hook.
   */
  callId?: string;
  /** Measured duration of the call, for the post-hooks. */
  durationMs?: number;
}

/** How a Copilot session end reads as ours. */
export function sessionEndStatus(reason: string | undefined): "completed" | "errored" | "interrupted" {
  if (reason === "error" || reason === "timeout") return "errored";
  if (reason === "abort" || reason === "user_exit") return "interrupted";
  return "completed";
}

/** Map one Copilot hook payload to zero or more TraceEvents, all labeled as Copilot's. */
export function mapCopilotPayload(payload: CopilotPayload, options: CopilotMapperOptions): TraceEvent[] {
  // A turn ending is not the session ending.
  if (payload.event === "Stop") return [];

  const sub = payload.event === "SubagentStart" || payload.event === "SubagentStop";
  const agentId = payload.agentId ?? (sub ? payload.agentName : undefined);
  const callId = options.callId ?? payload.callId ?? "";
  const base = {
    session_id: payload.sessionId,
    cwd: payload.cwd,
    ...(agentId ? { agent_id: agentId } : {}),
    ...((payload.agentType ?? payload.agentName) ? { agent_type: payload.agentType ?? payload.agentName } : {}),
  };

  let claude: ClaudeCodeHookPayload;
  switch (payload.event) {
    case "SessionStart":
      claude = { ...base, hook_event_name: "SessionStart", user: "copilot" };
      break;
    case "SessionEnd":
      claude = { ...base, hook_event_name: "SessionEnd", reason: sessionEndStatus(payload.reason) };
      break;
    case "UserPromptSubmit":
      claude = { ...base, hook_event_name: "UserPromptSubmit", prompt: payload.prompt ?? "" };
      break;
    case "PreToolUse":
      if (!payload.toolName) return [];
      claude = { ...base, hook_event_name: "PreToolUse", tool_name: payload.toolName, tool_input: payload.toolInput, tool_use_id: callId };
      break;
    case "PostToolUse":
      if (!payload.toolName) return [];
      claude = {
        ...base, hook_event_name: "PostToolUse", tool_name: payload.toolName, tool_input: payload.toolInput,
        tool_response: payload.toolResult, tool_use_id: callId, duration_ms: options.durationMs,
      };
      break;
    case "PostToolUseFailure":
      if (!payload.toolName) return [];
      claude = {
        ...base, hook_event_name: "PostToolUseFailure", tool_name: payload.toolName, tool_input: payload.toolInput,
        tool_use_id: callId, error: payload.error ?? "tool call failed", duration_ms: options.durationMs,
      };
      break;
    case "PermissionRequest":
      if (!payload.toolName) return [];
      claude = { ...base, hook_event_name: "PermissionRequest", tool_name: payload.toolName, tool_input: payload.toolInput };
      break;
    case "SubagentStart":
      if (!agentId) return [];
      claude = { ...base, hook_event_name: "SubagentStart", agent_id: agentId };
      break;
    case "SubagentStop":
      if (!agentId) return [];
      claude = {
        ...base, hook_event_name: "SubagentStop", agent_id: agentId,
        ...(payload.lastAssistantMessage ? { last_assistant_message: payload.lastAssistantMessage } : {}),
      };
      break;
  }

  return mapClaudeCodePayload(claude, { newEventId: options.newEventId, nowIso: options.nowIso }).map((event) => ({
    ...event,
    interceptor: "copilot-hook" as const,
    platform: "copilot" as const,
    ...(payload.timestamp ? { occurred_at: payload.timestamp } : {}),
  })) as TraceEvent[];
}
