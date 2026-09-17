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
 *   5. Keeping each upstream's connection state, retrying failed upstreams
 *      with a doubling delay, and reporting changes to the connected set
 *
 * Upstreams are independent: they connect in parallel, and one that is slow,
 * fails to start, or dies later never affects the others.
 *
 * Transport note: MCP stdio is newline-delimited JSON-RPC 2.0. The SDK's
 * ReadBuffer accumulates bytes and emits one complete JSON object per
 * message -- no partial-frame complexity for the proxy to handle. Large
 * response payloads are buffered momentarily in ReadBuffer before being
 * forwarded; this is acceptable for the local proxy use case.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  type ProxyConfig,
  type UpstreamConnectionSettings,
  type UpstreamServer,
  ProxyConfigSchema,
  TOOL_NAME_SEPARATOR,
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
  /** Name exposed to the agent, e.g. "filesystem__read_file" */
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
  /**
   * Structured result for tools that declare an outputSchema. Clients reject
   * a result without it when the tool advertises an outputSchema, so it must
   * be forwarded whenever the upstream provides it.
   */
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export type UpstreamState = "connecting" | "connected" | "failed";

/** Connection state of one upstream, as reported by omnodex_status. */
export interface UpstreamStatus {
  name: string;
  state: UpstreamState;
  tool_count: number;
  /** Error from the most recent failure; null once connected. */
  last_error: string | null;
  /** ISO time the most recent connection attempt started. */
  last_attempt_at: string | null;
  /** Failures since the upstream last held a stable connection. */
  failed_attempts: number;
  /** ISO time of the scheduled retry, when one is scheduled. */
  next_retry_at: string | null;
  /** True once retries have stopped; the upstream stays failed. */
  retries_exhausted: boolean;
}

/**
 * JSON Schema dialect that MCP clients validate tool schemas against. Schemas
 * declaring any other "$schema" (commonly draft-07, emitted by
 * zod-to-json-schema) are rejected by clients whose validator only supports
 * this dialect.
 */
const SUPPORTED_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";

/**
 * A connection that closes sooner than this after connecting keeps its
 * earlier failure count, so an upstream that crashes right after starting
 * still reaches the retry limit instead of retrying at the shortest delay
 * forever.
 */
const STABLE_CONNECTION_MS = 30_000;

/**
 * Removes a top-level "$schema" declaration that names a dialect other than
 * JSON Schema 2020-12, so the schema is validated under the client's default
 * dialect. The keywords MCP servers use in tool schemas (type, properties,
 * required, items, enum, additionalProperties, description) behave the same
 * in draft-07 and 2020-12. Returns the input unchanged when there is nothing
 * to remove.
 */
export function normalizeSchemaDialect<T>(schema: T): T {
  if (schema === null || typeof schema !== "object" || !("$schema" in schema)) {
    return schema;
  }
  const { $schema, ...rest } = schema as Record<string, unknown>;
  if (typeof $schema === "string" && $schema.replace(/#$/, "") === SUPPORTED_SCHEMA_DIALECT) {
    return schema;
  }
  return rest as T;
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
  async discoverTools(options?: RequestOptions): Promise<PrefixedTool[]> {
    const result = await this.client.listTools(undefined, options);
    const prefixed: PrefixedTool[] = [];

    for (const tool of result.tools) {
      this.toolMap.set(tool.name, tool);
      const prefixedName = `${this.prefix}${TOOL_NAME_SEPARATOR}${tool.name}`;
      const definition: Tool = {
        ...tool,
        name: prefixedName,
        inputSchema: normalizeSchemaDialect(tool.inputSchema),
      };
      if (tool.outputSchema) {
        definition.outputSchema = normalizeSchemaDialect(tool.outputSchema);
      }
      prefixed.push({
        prefixedName,
        originalName: tool.name,
        serverName: this.server.name,
        // Return the definition with the agent-visible name so the inbound
        // server can pass it through verbatim without re-deriving the prefix.
        definition,
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
      ...(result.structuredContent !== undefined
        ? { structuredContent: result.structuredContent as Record<string, unknown> }
        : {}),
      isError: result.isError === true,
    };
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

/** Mutable per-upstream bookkeeping behind UpstreamStatus. */
interface UpstreamEntry {
  server: UpstreamServer;
  prefix: string;
  state: UpstreamState;
  connection: UpstreamConnection | undefined;
  tools: PrefixedTool[];
  lastError: string | null;
  lastAttemptAt: number | null;
  connectedAt: number | null;
  failedAttempts: number;
  /** failedAttempts as it stood when the current connection was made. */
  failuresBeforeConnect: number;
  nextRetryAt: number | null;
  retryTimer: NodeJS.Timeout | undefined;
  retriesExhausted: boolean;
}

// ---------------------------------------------------------------------------
// Public: the pool
// ---------------------------------------------------------------------------

/**
 * UpstreamClientPool connects to every upstream server listed in the proxy
 * config, discovers their tools, and provides a single callTool() entry point
 * that routes by prefixed name.
 *
 * Lifecycle: call start() once (it returns immediately and connects in the
 * background) or connect() to also wait for every first attempt, then
 * callTool() any number of times, then close() on shutdown.
 *
 * A failed upstream is retried after retry_initial_delay_ms, doubling each
 * time. Once the next delay would reach retry_give_up_delay_ms the pool stops
 * retrying and reports the upstream through onRetriesExhausted. An upstream
 * that disconnects after connecting has its tools removed and is retried the
 * same way.
 */
export class UpstreamClientPool {
  private readonly entries: UpstreamEntry[] = [];
  /** prefixedName -> connection that owns it */
  private toolIndex = new Map<string, UpstreamConnection>();
  private cachedTools: PrefixedTool[] = [];
  private readonly warnedCollisions = new Set<string>();
  private settings: UpstreamConnectionSettings = ProxyConfigSchema.parse({ version: 1 })
    .upstream_connection;
  private initialAttempts: Promise<void> = Promise.resolve();
  private started = false;
  private closed = false;
  private readonly toolsChangedListeners = new Set<() => void>();
  private readonly exhaustedListeners = new Set<(status: UpstreamStatus) => void>();

  /**
   * Starts connecting to every upstream in parallel and returns immediately.
   * Never throws for upstream failures: they are recorded per upstream.
   */
  start(config: ProxyConfig): void {
    if (this.started) {
      throw new Error("UpstreamClientPool.start() called twice");
    }
    this.started = true;
    this.settings = config.upstream_connection;
    for (const server of config.upstream_servers) {
      this.entries.push({
        server,
        prefix: toolNamePrefix(server),
        state: "connecting",
        connection: undefined,
        tools: [],
        lastError: null,
        lastAttemptAt: null,
        connectedAt: null,
        failedAttempts: 0,
        failuresBeforeConnect: 0,
        nextRetryAt: null,
        retryTimer: undefined,
        retriesExhausted: false,
      });
    }
    this.initialAttempts = Promise.all(this.entries.map((e) => this.attempt(e))).then(
      () => undefined
    );
  }

  /**
   * Starts the pool and waits until every upstream has finished its first
   * connection attempt, successful or not.
   */
  async connect(config: ProxyConfig): Promise<void> {
    this.start(config);
    await this.initialAttempts;
  }

  /**
   * Resolves once every upstream has finished its first attempt, or after
   * timeoutMs, whichever comes first.
   */
  async waitForInitialAttempts(timeoutMs: number): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, timeoutMs);
    });
    try {
      await Promise.race([this.initialAttempts, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Registers a listener for changes to the connected tool set. Returns a
   * function that removes it.
   */
  onToolsChanged(listener: () => void): () => void {
    this.toolsChangedListeners.add(listener);
    return () => this.toolsChangedListeners.delete(listener);
  }

  /**
   * Registers a listener called when an upstream stops being retried.
   * Returns a function that removes it.
   */
  onRetriesExhausted(listener: (status: UpstreamStatus) => void): () => void {
    this.exhaustedListeners.add(listener);
    return () => this.exhaustedListeners.delete(listener);
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

  /** Returns names of the currently connected upstream servers. */
  getServerNames(): string[] {
    return this.entries.filter((e) => e.state === "connected").map((e) => e.server.name);
  }

  /** Returns the connection state of every configured upstream. */
  getUpstreamStatuses(): UpstreamStatus[] {
    return this.entries.map((e) => toStatus(e));
  }

  /**
   * Returns the status of the upstream that would own prefixedName if it were
   * connected, or undefined when the name matches no unavailable upstream.
   * Lets a call to a tool on a down upstream report why it is down rather
   * than "tool not found".
   */
  findUnavailableUpstream(prefixedName: string): UpstreamStatus | undefined {
    let match: UpstreamEntry | undefined;
    for (const entry of this.entries) {
      if (entry.state === "connected") continue;
      if (!prefixedName.startsWith(`${entry.prefix}${TOOL_NAME_SEPARATOR}`)) continue;
      if (!match || entry.prefix.length > match.prefix.length) match = entry;
    }
    return match ? toStatus(match) : undefined;
  }

  /**
   * Retries every failed upstream now, including those whose retries were
   * exhausted, with a fresh failure count. Returns the names retried.
   */
  retryFailed(): string[] {
    const retried: string[] = [];
    for (const entry of this.entries) {
      if (entry.state !== "failed") continue;
      clearTimeout(entry.retryTimer);
      entry.failedAttempts = 0;
      entry.retriesExhausted = false;
      retried.push(entry.server.name);
      void this.attempt(entry);
    }
    return retried;
  }

  /**
   * Routes a tools/call to the correct upstream and returns the raw result.
   * Throws McpUpstreamUnavailableError if the name belongs to an upstream that
   * is not connected, and McpToolNotFoundError if the name is unknown.
   */
  async callTool(
    prefixedName: string,
    args: Record<string, unknown>
  ): Promise<UpstreamCallResult> {
    const conn = this.toolIndex.get(prefixedName);
    if (!conn) {
      const unavailable = this.findUnavailableUpstream(prefixedName);
      if (unavailable) throw new McpUpstreamUnavailableError(unavailable);
      throw new McpToolNotFoundError(
        prefixedName,
        [...this.toolIndex.keys()]
      );
    }

    // Derive original name: strip the prefix and the separator.
    const prefix = toolNamePrefix(conn.server);
    const originalName = prefixedName.slice(prefix.length + TOOL_NAME_SEPARATOR.length);

    return conn.callTool(originalName, args);
  }

  /** Gracefully closes all upstream connections and cancels retries. */
  async close(): Promise<void> {
    this.closed = true;
    const connections: UpstreamConnection[] = [];
    for (const entry of this.entries) {
      clearTimeout(entry.retryTimer);
      if (entry.connection) connections.push(entry.connection);
      entry.connection = undefined;
    }
    await Promise.allSettled(connections.map((c) => c.close()));
    this.entries.length = 0;
    this.toolIndex.clear();
    this.cachedTools = [];
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private async attempt(entry: UpstreamEntry): Promise<void> {
    entry.state = "connecting";
    entry.lastAttemptAt = Date.now();
    entry.nextRetryAt = null;
    entry.retryTimer = undefined;

    const client = new Client(
      { name: "omnodex-mcp-proxy", version: "0.0.0" },
      {}
    );
    const options: RequestOptions = { timeout: this.settings.connect_timeout_ms };

    try {
      await client.connect(createTransport(entry.server), options);
      const connection = new UpstreamConnection(entry.server, client);
      client.onclose = () => this.handleDisconnect(entry, connection);
      const tools = await connection.discoverTools(options);

      if (this.closed) {
        await client.close();
        return;
      }
      entry.connection = connection;
      entry.tools = tools;
      entry.state = "connected";
      entry.connectedAt = Date.now();
      entry.failuresBeforeConnect = entry.failedAttempts;
      entry.failedAttempts = 0;
      entry.lastError = null;
      entry.retriesExhausted = false;
      this.rebuildToolIndex();
    } catch (err) {
      // Closing the client also stops a subprocess that started but did not
      // finish the handshake in time.
      await client.close().catch(() => undefined);
      if (this.closed) return;
      this.recordFailure(entry, err instanceof Error ? err.message : String(err));
    }
  }

  private handleDisconnect(entry: UpstreamEntry, connection: UpstreamConnection): void {
    if (this.closed || entry.connection !== connection) return;
    const uptime = Date.now() - (entry.connectedAt ?? 0);
    if (uptime < STABLE_CONNECTION_MS) {
      entry.failedAttempts = entry.failuresBeforeConnect;
    }
    entry.connection = undefined;
    entry.connectedAt = null;
    entry.tools = [];
    this.recordFailure(entry, "upstream connection closed");
    this.rebuildToolIndex();
  }

  private recordFailure(entry: UpstreamEntry, message: string): void {
    const name = entry.server.name;
    entry.state = "failed";
    entry.lastError = message;
    entry.failedAttempts += 1;

    const delay = this.settings.retry_initial_delay_ms * 2 ** (entry.failedAttempts - 1);
    if (delay >= this.settings.retry_give_up_delay_ms) {
      entry.retriesExhausted = true;
      entry.nextRetryAt = null;
      const status = toStatus(entry);
      process.stderr.write(
        `[omnodex-mcp-proxy] WARNING: ${describeUnavailable(status)}\n`
      );
      for (const listener of this.exhaustedListeners) listener(status);
      return;
    }

    entry.nextRetryAt = Date.now() + delay;
    entry.retryTimer = setTimeout(() => void this.attempt(entry), delay);
    // Retries alone must not keep the process alive after the agent leaves.
    entry.retryTimer.unref();
    process.stderr.write(
      `[omnodex-mcp-proxy] upstream "${name}" failed: ${message}. ` +
        `Retrying in ${formatDelay(delay)}.\n`
    );
  }

  /** Rebuilds the tool list from connected upstreams, in config order. */
  private rebuildToolIndex(): void {
    const index = new Map<string, UpstreamConnection>();
    const tools: PrefixedTool[] = [];
    for (const entry of this.entries) {
      if (!entry.connection) continue;
      for (const tool of entry.tools) {
        if (index.has(tool.prefixedName) && !this.warnedCollisions.has(tool.prefixedName)) {
          // Two upstreams claim the same prefixed name. Last one wins but we
          // warn so the operator knows to use name_override.
          this.warnedCollisions.add(tool.prefixedName);
          process.stderr.write(
            `[omnodex-mcp-proxy] WARNING: tool name collision: ${tool.prefixedName} ` +
              `(already registered by another upstream). Use name_override to resolve.\n`
          );
        }
        index.set(tool.prefixedName, entry.connection);
        tools.push(tool);
      }
    }
    this.toolIndex = index;
    this.cachedTools = tools;
    for (const listener of this.toolsChangedListeners) listener();
  }
}

function createTransport(server: UpstreamServer): Transport {
  if (server.transport === "stdio") {
    return new StdioClientTransport({
      command: server.command,
      args: server.args ?? [],
      env: resolveUpstreamEnv(server.env),
      cwd: server.cwd,
      // Inherit stderr so upstream server error output is visible in the
      // proxy's own stderr stream (visible in Cowork's session log).
      stderr: "inherit",
    });
  }
  // HTTP+SSE transport: deferred to v0.5+. The config schema accepts http
  // upstreams so configs written now will be valid when we add support.
  throw new Error(
    `HTTP upstream transport is not yet supported (server: "${server.name}"). ` +
      `Use transport: "stdio" for now.`
  );
}

function toStatus(entry: UpstreamEntry): UpstreamStatus {
  const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());
  return {
    name: entry.server.name,
    state: entry.state,
    tool_count: entry.tools.length,
    last_error: entry.lastError,
    last_attempt_at: iso(entry.lastAttemptAt),
    failed_attempts: entry.failedAttempts,
    next_retry_at: iso(entry.nextRetryAt),
    retries_exhausted: entry.retriesExhausted,
  };
}

function formatDelay(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${Math.round(ms / 1000)}s`;
}

/** One-sentence explanation of why an upstream's tools are unavailable. */
export function describeUnavailable(status: UpstreamStatus): string {
  const base = `Upstream MCP server "${status.name}"`;
  if (status.state === "connecting") {
    return `${base} is still connecting. Try again shortly.`;
  }
  const error = status.last_error ? ` Last error: ${status.last_error}.` : "";
  if (status.retries_exhausted) {
    return (
      `${base} is not connected and retries have stopped after ` +
      `${status.failed_attempts} failed attempts.${error} ` +
      `Check the server, then restart the MCP host or call omnodex_status ` +
      `with retry_failed: true.`
    );
  }
  const retry = status.next_retry_at
    ? ` Retrying in ${formatDelay(Math.max(0, Date.parse(status.next_retry_at) - Date.now()))}.`
    : "";
  return `${base} is not connected.${error}${retry}`;
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

/** Thrown when tools/call names a tool on an upstream that is not connected. */
export class McpUpstreamUnavailableError extends Error {
  constructor(readonly upstream: UpstreamStatus) {
    super(describeUnavailable(upstream));
    this.name = "McpUpstreamUnavailableError";
  }
}
