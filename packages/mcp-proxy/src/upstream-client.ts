// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- upstream-client
 *
 * Manages a pool of MCP client connections to upstream servers. Responsible
 * for:
 *   1. Spawning upstream stdio subprocesses (or connecting to HTTP servers)
 *   2. Calling tools/list on each to build a unified, prefixed tool index
 *   3. Routing tools/call to the correct upstream by prefixed name
 *   4. Returning raw call results for the event-emitter layer to wrap
 *
 * Transport note: MCP stdio is newline-delimited JSON-RPC 2.0. The SDK's
 * ReadBuffer accumulates bytes and emits one complete JSON object per
 * message -- no partial-frame complexity for the proxy to handle. Large
 * response payloads are buffered momentarily in ReadBuffer before being
 * forwarded; this is acceptable for the local proxy use case.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  type ProxyConfig,
  type UpstreamServer,
  resolveUpstreamEnv,
  toolNamePrefix,
} from "./config.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * A single tool entry in the proxy's unified tool index. The prefixedName is
 * what the agent sees; originalName is what the upstream server expects.
 */
export interface PrefixedTool {
  /** Name exposed to the agent, e.g. "filesystem/read_file" */
  prefixedName: string;
  /** Original name on the upstream server, e.g. "read_file" */
  originalName: string;
  /** Logical name of the upstream server that owns this tool */
  serverName: string;
  /** Full tool definition with `name` rewritten to prefixedName */
  definition: Tool;
}

/** Raw result from an upstream tools/call. */
export interface UpstreamCallResult {
  content: unknown[];
  isError?: boolean;
}

// ---------------------------------------------------------------------------
// Internal: one upstream connection
// ---------------------------------------------------------------------------

class UpstreamConnection {
  readonly server: UpstreamServer;
  private readonly client: Client;
  private readonly prefix: string;
  private readonly toolMap = new Map<string, Tool>(); // originalName -> Tool

  constructor(server: UpstreamServer, client: Client) {
    this.server = server;
    this.client = client;
    this.prefix = toolNamePrefix(server);
  }

  /**
   * Calls tools/list on the upstream, builds the local tool map, and returns
   * the prefixed tool entries ready for the proxy's unified index.
   */
  async discoverTools(): Promise<PrefixedTool[]> {
    const result = await this.client.listTools();
    const prefixed: PrefixedTool[] = [];

    for (const tool of result.tools) {
      this.toolMap.set(tool.name, tool);
      const prefixedName = `${this.prefix}/${tool.name}`;
      prefixed.push({
        prefixedName,
        originalName: tool.name,
        serverName: this.server.name,
        // Return the definition with the agent-visible name so the inbound
        // server can pass it through verbatim without re-deriving the prefix.
        definition: { ...tool, name: prefixedName },
      });
    }

    return prefixed;
  }

  /**
   * Calls a tool on the upstream by its original (un-prefixed) name.
   * The UpstreamClientPool is responsible for deriving the original name from
   * the prefixed name before calling this method.
   */
  async callTool(
    originalName: string,
    args: Record<string, unknown>
  ): Promise<UpstreamCallResult> {
    const result = await this.client.callTool({
      name: originalName,
      arguments: args,
    });
    return {
      content: result.content as unknown[],
      isError: result.isError === true,
    };
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

// ---------------------------------------------------------------------------
// Public: the pool
// ---------------------------------------------------------------------------

/**
 * UpstreamClientPool connects to every upstream server listed in the proxy
 * config, discovers their tools, and provides a single callTool() entry point
 * that routes by prefixed name.
 *
 * Lifecycle: call connect() once at startup, callTool() any number of times,
 * then close() on shutdown. Not designed for reconnection -- if an upstream
 * dies, the error propagates up to the proxy server which can surface it to
 * the agent as an MCP error response.
 */
export class UpstreamClientPool {
  private readonly connections = new Map<string, UpstreamConnection>();
  /** prefixedName -> connection that owns it */
  private readonly toolIndex = new Map<string, UpstreamConnection>();
  private cachedTools: PrefixedTool[] = [];

  /**
   * Connects to all upstream servers in the config and runs tools/list on
   * each. Must be called before getTools() or callTool().
   *
   * Throws if any upstream fails to connect or to list its tools -- the proxy
   * cannot operate with a partial tool surface.
   */
  async connect(config: ProxyConfig): Promise<void> {
    for (const server of config.upstream_servers) {
      const client = new Client(
        { name: "omnodex-mcp-proxy", version: "0.0.0" },
        {}
      );

      await this.connectUpstream(client, server);

      const conn = new UpstreamConnection(server, client);
      const tools = await conn.discoverTools();

      this.connections.set(server.name, conn);
      for (const tool of tools) {
        if (this.toolIndex.has(tool.prefixedName)) {
          // Two upstreams claim the same prefixed name. Last one wins but we
          // warn so the operator knows to use name_override.
          process.stderr.write(
            `[omnodex-mcp-proxy] WARNING: tool name collision: ${tool.prefixedName} ` +
              `(already registered by another upstream). Use name_override to resolve.\n`
          );
        }
        this.toolIndex.set(tool.prefixedName, conn);
        this.cachedTools.push(tool);
      }
    }
  }

  /** Returns the full prefixed tool list for tools/list responses. */
  getTools(): PrefixedTool[] {
    return this.cachedTools;
  }

  /**
   * Returns the upstream server name that owns a given prefixed tool name.
   * Used by the event-emitter to populate the mcp_server field of TraceEvents.
   */
  getServerName(prefixedName: string): string | undefined {
    return this.toolIndex.get(prefixedName)?.server.name;
  }

  /** Returns names of all connected upstream servers. */
  getServerNames(): string[] {
    return [...this.connections.keys()];
  }

  /**
   * Routes a tools/call to the correct upstream and returns the raw result.
   * Throws McpToolNotFoundError if the prefixed name is unknown.
   */
  async callTool(
    prefixedName: string,
    args: Record<string, unknown>
  ): Promise<UpstreamCallResult> {
    const conn = this.toolIndex.get(prefixedName);
    if (!conn) {
      throw new McpToolNotFoundError(
        prefixedName,
        [...this.toolIndex.keys()]
      );
    }

    // Derive original name: strip the prefix and the separating slash.
    const prefix = toolNamePrefix(conn.server);
    const originalName = prefixedName.slice(prefix.length + 1);

    return conn.callTool(originalName, args);
  }

  /** Gracefully closes all upstream connections. */
  async close(): Promise<void> {
    await Promise.allSettled(
      [...this.connections.values()].map((c) => c.close())
    );
    this.connections.clear();
    this.toolIndex.clear();
    this.cachedTools = [];
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private async connectUpstream(
    client: Client,
    server: UpstreamServer
  ): Promise<void> {
    if (server.transport === "stdio") {
      const transport = new StdioClientTransport({
        command: server.command,
        args: server.args ?? [],
        env: resolveUpstreamEnv(server.env),
        cwd: server.cwd,
        // Inherit stderr so upstream server error output is visible in the
        // proxy's own stderr stream (visible in Cowork's session log).
        stderr: "inherit",
      });
      await client.connect(transport);
    } else {
      // HTTP+SSE transport: deferred to v0.5+. The config schema accepts http
      // upstreams so configs written now will be valid when we add support.
      throw new Error(
        `HTTP upstream transport is not yet supported (server: "${server.name}"). ` +
          `Use transport: "stdio" for now.`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/** Thrown when tools/call names a tool not in the proxy's tool index. */
export class McpToolNotFoundError extends Error {
  constructor(
    readonly prefixedName: string,
    readonly knownTools: string[]
  ) {
    super(
      `Tool not found: "${prefixedName}". ` +
        `Known tools: ${knownTools.length > 0 ? knownTools.join(", ") : "(none)"}`
    );
    this.name = "McpToolNotFoundError";
  }
}
