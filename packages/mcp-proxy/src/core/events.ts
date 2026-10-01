// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- core/events
 *
 * The TraceEvents a proxy records around a session and each tool call.
 * Building them here keeps every proxy, whatever its transport or runtime,
 * writing the same shapes.
 *
 * Runtime-neutral: no Node APIs. IDs come from globalThis.crypto.
 */

import {
  SCHEMA_VERSION,
  type McpServerTransport,
  type PlatformKind,
  type SessionEndedEvent,
  type SessionStartedEvent,
  type ToolCompletedEvent,
  type ToolInvokedEvent,
} from "@omnodex/shared";

const PLATFORMS: readonly PlatformKind[] = ["claude-code", "codex", "cowork", "web", "antigravity", "copilot"];

/** The value as a PlatformKind, or undefined when it names no known platform. */
export function asPlatform(value: string | undefined): PlatformKind | undefined {
  return PLATFORMS.find((p) => p === value?.trim().toLowerCase());
}

/**
 * The runtime an MCP client's initialize name identifies, when it is one we
 * have captured. Anything else maps to nothing and is recorded by name only.
 * A name listed here wins over a launcher's OMNODEX_PLATFORM, which applies
 * only to names that do not settle it: the Claude desktop app, for one,
 * names itself "claude-ai" for both chat and Cowork.
 */
const CLIENT_PLATFORMS: Readonly<Record<string, PlatformKind>> = {
  "claude-code": "claude-code",
  "codex-mcp-client": "codex",
  "antigravity-client": "antigravity",
};

export function platformForClient(name: string | undefined): PlatformKind | undefined {
  return name ? CLIENT_PLATFORMS[name.trim().toLowerCase()] : undefined;
}

/** Replaces parameter values when redaction is on. */
export const REDACTED_SENTINEL = "[REDACTED]";

function newEventId(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * Replaces every value in the args object with the redaction sentinel.
 * Keys are preserved so rule matchers can still see which parameters were
 * passed, even if their content is hidden.
 */
export function redactParameters(args: Record<string, unknown>): Record<string, unknown> {
  const redacted: Record<string, unknown> = {};
  for (const key of Object.keys(args)) {
    redacted[key] = REDACTED_SENTINEL;
  }
  return redacted;
}

export function buildSessionStartedEvent(fields: {
  sessionId: string;
  at: string;
  user: string;
  projectPath: string;
  servers: McpServerTransport[];
  /** The agent runtime, when the launcher or the client's name says. */
  platform?: PlatformKind;
  /** The MCP client, as it named itself in initialize. */
  mcpClient?: { name: string; version?: string };
}): SessionStartedEvent {
  return {
    schema_version: SCHEMA_VERSION,
    event_id: newEventId(),
    session_id: fields.sessionId,
    occurred_at: fields.at,
    recorded_at: fields.at,
    interceptor: "mcp-proxy",
    event_type: "session.started",
    user: fields.user,
    project_path: fields.projectPath,
    mcp_servers: fields.servers.map((s) => s.name),
    mcp_server_transports: fields.servers,
    ...(fields.platform ? { platform: fields.platform } : {}),
    ...(fields.mcpClient ? { mcp_client: fields.mcpClient } : {}),
  };
}

export function buildSessionEndedEvent(fields: {
  sessionId: string;
  at: string;
  durationMs: number;
}): SessionEndedEvent {
  return {
    schema_version: SCHEMA_VERSION,
    event_id: newEventId(),
    session_id: fields.sessionId,
    occurred_at: fields.at,
    recorded_at: fields.at,
    interceptor: "mcp-proxy",
    event_type: "session.ended",
    duration_ms: fields.durationMs,
    status: "completed",
  };
}

export function buildToolInvokedEvent(fields: {
  sessionId: string;
  toolCallId: string;
  at: string;
  toolName: string;
  mcpServer: string;
  args: Record<string, unknown>;
  redact: boolean;
}): ToolInvokedEvent {
  return {
    schema_version: SCHEMA_VERSION,
    event_id: newEventId(),
    session_id: fields.sessionId,
    occurred_at: fields.at,
    recorded_at: fields.at,
    interceptor: "mcp-proxy",
    event_type: "tool.invoked",
    tool_call_id: fields.toolCallId,
    tool_name: fields.toolName,
    mcp_server: fields.mcpServer,
    parameters: fields.redact ? redactParameters(fields.args) : fields.args,
  };
}

export function buildToolCompletedEvent(fields: {
  sessionId: string;
  toolCallId: string;
  at: string;
  durationMs: number;
  status: "success" | "error";
  responseBytes: number;
  errorMessage?: string;
}): ToolCompletedEvent {
  return {
    schema_version: SCHEMA_VERSION,
    event_id: newEventId(),
    session_id: fields.sessionId,
    occurred_at: fields.at,
    recorded_at: fields.at,
    interceptor: "mcp-proxy",
    event_type: "tool.completed",
    tool_call_id: fields.toolCallId,
    duration_ms: fields.durationMs,
    status: fields.status,
    response_bytes: fields.responseBytes,
    ...(fields.errorMessage !== undefined ? { error_message: fields.errorMessage } : {}),
  };
}
