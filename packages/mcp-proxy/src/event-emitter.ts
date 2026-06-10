// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- event-emitter
 *
 * Wraps upstream tool calls with TraceEvent generation. Emits tool.invoked
 * before forwarding the call and tool.completed (with timing and status)
 * after the upstream responds. Respects the redact_parameters flag.
 *
 * This is deliberately a thin layer -- it delegates the actual upstream call
 * to UpstreamClientPool and the actual event write to the EmitFn from
 * @omnodex/shared. No buffering, no retry logic.
 */

import { randomUUID } from "node:crypto";
import {
  SCHEMA_VERSION,
  type EmitFn,
  type ToolInvokedEvent,
  type ToolCompletedEvent,
} from "@omnodex/shared";
import {
  type UpstreamClientPool,
  type UpstreamCallResult,
  McpToolNotFoundError,
} from "./upstream-client.js";
import { type ProxyConfig, shouldRedactParams } from "./config.js";

const REDACTED_SENTINEL = "[REDACTED]";

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface CallToolOptions {
  /** Prefixed tool name as seen by the agent, e.g. "filesystem/read_file" */
  prefixedName: string;
  /** Raw arguments from the agent's tools/call request */
  args: Record<string, unknown>;
  /** Identifies this call in the event log and for correlation */
  toolCallId: string;
  /** Session the call belongs to */
  sessionId: string;
}

export interface CallToolOutcome {
  result: UpstreamCallResult;
  /** Duration of the upstream round-trip in milliseconds */
  durationMs: number;
}

/**
 * Calls an upstream tool via the pool, emitting tool.invoked and
 * tool.completed TraceEvents around the call.
 *
 * The returned outcome contains the raw upstream result so proxy-server.ts
 * can forward it verbatim to the agent.
 *
 * Never throws for upstream errors: if the upstream call fails, the error is
 * captured in the tool.completed event and the outcome has isError: true.
 * McpToolNotFoundError re-throws immediately (before tool.invoked) because
 * there is no upstream call to wrap.
 */
export async function callToolWithEvents(
  pool: UpstreamClientPool,
  config: ProxyConfig,
  emit: EmitFn,
  opts: CallToolOptions
): Promise<CallToolOutcome> {
  const { prefixedName, args, toolCallId, sessionId } = opts;

  const serverName = pool.getServerName(prefixedName);
  // Resolve before emitting -- if the tool doesn't exist we bail early.
  if (!serverName) {
    throw new McpToolNotFoundError(
      prefixedName,
      pool.getTools().map((t) => t.prefixedName)
    );
  }

  // Determine whether to redact parameters for this upstream server.
  const server = config.upstream_servers.find((s) => s.name === serverName);
  const redact = server ? shouldRedactParams(server, config) : config.redact_parameters;

  const now = () => new Date().toISOString();
  const invokedAt = now();

  // Emit tool.invoked (fire-and-forget, non-blocking).
  const invokedEvent: ToolInvokedEvent = {
    schema_version: SCHEMA_VERSION,
    event_id: randomUUID(),
    session_id: sessionId,
    occurred_at: invokedAt,
    recorded_at: invokedAt,
    interceptor: "mcp-proxy",
    event_type: "tool.invoked",
    tool_call_id: toolCallId,
    tool_name: prefixedName,
    mcp_server: serverName,
    parameters: redact ? redactParameters(args) : args,
  };
  void emit(invokedEvent);

  // Call upstream and measure duration.
  const startMs = Date.now();
  let result: UpstreamCallResult;
  let status: "success" | "error" = "success";
  let errorMessage: string | undefined;

  try {
    result = await pool.callTool(prefixedName, args);
    if (result.isError) {
      status = "error";
      errorMessage = extractErrorMessage(result.content);
    }
  } catch (err) {
    // Upstream threw (network error, process crash, etc.).
    status = "error";
    errorMessage = err instanceof Error ? err.message : String(err);
    // Re-package as an MCP error result so proxy-server.ts can forward it.
    result = {
      content: [{ type: "text", text: errorMessage }],
      isError: true,
    };
  }

  const durationMs = Date.now() - startMs;
  const completedAt = now();

  // Estimate response bytes from JSON serialisation of content.
  const responseBytes = Buffer.byteLength(
    JSON.stringify(result.content),
    "utf8"
  );

  const completedEvent: ToolCompletedEvent = {
    schema_version: SCHEMA_VERSION,
    event_id: randomUUID(),
    session_id: sessionId,
    occurred_at: completedAt,
    recorded_at: completedAt,
    interceptor: "mcp-proxy",
    event_type: "tool.completed",
    tool_call_id: toolCallId,
    duration_ms: durationMs,
    status,
    response_bytes: responseBytes,
    ...(errorMessage !== undefined ? { error_message: errorMessage } : {}),
  };
  void emit(completedEvent);

  return { result, durationMs };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Replaces every value in the args object with the redaction sentinel.
 * Keys are preserved so rule matchers can still see which parameters were
 * passed, even if their content is hidden.
 */
function redactParameters(
  args: Record<string, unknown>
): Record<string, unknown> {
  const redacted: Record<string, unknown> = {};
  for (const key of Object.keys(args)) {
    redacted[key] = REDACTED_SENTINEL;
  }
  return redacted;
}

/**
 * Tries to extract a human-readable error string from an MCP error content
 * array. Falls back to a generic message if the content is not in a
 * recognisable shape.
 */
function extractErrorMessage(content: unknown[]): string {
  if (content.length === 0) return "upstream returned an error";
  const first = content[0];
  if (
    first !== null &&
    typeof first === "object" &&
    "text" in first &&
    typeof (first as { text: unknown }).text === "string"
  ) {
    return (first as { text: string }).text;
  }
  return JSON.stringify(first);
}
