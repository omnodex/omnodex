// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- proxy-server
 *
 * Inbound MCP server: the face the agent talks to. Accepts the agent's
 * MCP connection on stdin/stdout (stdio transport), exposes the merged,
 * prefixed tool list from all configured upstream servers, and routes
 * tools/call requests through the event-emitter layer to the upstream pool.
 *
 * The server re-presents the combined upstream tool surface verbatim except
 * for the name prefix, so agents that inspect inputSchema, descriptions, or
 * annotations see the real upstream definitions.
 */

import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SCHEMA_VERSION, type EmitFn, type SessionStartedEvent, type SessionEndedEvent } from "@omnodex/shared";
import { type UpstreamClientPool } from "./upstream-client.js";
import { callToolWithEvents } from "./event-emitter.js";
import { type ProxyConfig } from "./config.js";

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface ProxyServerOptions {
  pool: UpstreamClientPool;
  config: ProxyConfig;
  emit: EmitFn;
  sessionId: string;
  /** Human-readable project path for session.started event. */
  projectPath?: string;
}

/**
 * Creates and starts the inbound MCP server. Returns a stop function that
 * cleanly closes the server transport and emits session.ended.
 *
 * This function does not return until the agent disconnects (stdin closes).
 * Callers should await it in the main proxy process.
 */
export async function runProxyServer(opts: ProxyServerOptions): Promise<void> {
  const { pool, config, emit, sessionId } = opts;
  const projectPath = opts.projectPath ?? process.cwd();

  const server = new Server(
    { name: "omnodex-mcp-proxy", version: "0.0.0" },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // ── Built-in status tool ──────────────────────────────────────────────────
  const STATUS_TOOL = {
    name: "omnodex_status",
    description:
      "Returns the status of the Omnodex MCP proxy: version, session ID, " +
      "connected upstream servers, and uptime.",
    inputSchema: { type: "object" as const, properties: {} },
  };

  // ── tools/list ────────────────────────────────────────────────────────────
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = pool.getTools().map((t) => t.definition);
    return { tools: [STATUS_TOOL, ...tools] };
  });

  // ── tools/call ────────────────────────────────────────────────────────────
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const prefixedName = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;

    // Handle built-in omnodex_status tool
    if (prefixedName === "omnodex_status") {
      const status = {
        proxy: "omnodex-mcp-proxy",
        version: "0.1.0",
        status: "running",
        session_id: sessionId,
        uptime_ms: Date.now() - connectStart,
        upstream_servers: pool.getServerNames(),
        tool_count: pool.getTools().length,
        redact_parameters: config.redact_parameters,
      };
      return {
        content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
        isError: false,
      };
    }
    // Use the MCP request id as correlation key when available; otherwise mint
    // a fresh UUID. The tool_call_id is what links tool.invoked to tool.completed
    // in the event log.
    const toolCallId = randomUUID();

    try {
      const outcome = await callToolWithEvents(pool, config, emit, {
        prefixedName,
        args,
        toolCallId,
        sessionId,
      });
      return {
        content: outcome.result.content as Array<{ type: string }>,
        isError: outcome.result.isError,
      };
    } catch (err) {
      // McpToolNotFoundError or any other unexpected error: return as MCP
      // error content so the agent receives a well-formed response.
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: message }],
        isError: true,
      };
    }
  });

  // ── Transport + session lifecycle ─────────────────────────────────────────
  const transport = new StdioServerTransport();
  const connectStart = Date.now();
  const sessionStart = new Date().toISOString();

  // Emit session.started
  const startedEvent: SessionStartedEvent = {
    schema_version: SCHEMA_VERSION,
    event_id: randomUUID(),
    session_id: sessionId,
    occurred_at: sessionStart,
    recorded_at: sessionStart,
    interceptor: "mcp-proxy",
    event_type: "session.started",
    user: process.env.USER ?? process.env.USERNAME ?? "unknown",
    project_path: projectPath,
    mcp_servers: config.upstream_servers.map((s) => s.name),
  };
  void emit(startedEvent);

  // Print the parameter-logging disclosure to stderr so it appears in the
  // agent's session log (Cowork shows this in the terminal panel).
  const redacting = config.redact_parameters;
  if (!redacting) {
    process.stderr.write(
      "[omnodex] Parameters are logged locally. " +
        "Set redact_parameters: true in omnodex-proxy.json to disable.\n"
    );
  }

  // connect() resolves when the transport closes (agent disconnects / EOF).
  await server.connect(transport);

  const endedAt = new Date().toISOString();
  const endedEvent: SessionEndedEvent = {
    schema_version: SCHEMA_VERSION,
    event_id: randomUUID(),
    session_id: sessionId,
    occurred_at: endedAt,
    recorded_at: endedAt,
    interceptor: "mcp-proxy",
    event_type: "session.ended",
    duration_ms: Date.now() - connectStart,
    status: "completed",
  };
  void emit(endedEvent);
}
