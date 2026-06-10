// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- mcp-proxy
 *
 * MCPProxy implements the @omnodex/shared Interceptor interface.
 * It wires together the upstream client pool, the event-emitter, and the
 * inbound proxy server into a single object that the CLI or any test harness
 * can drive via start() / stop().
 *
 * Typical lifecycle (from the bin entrypoint):
 *
 *   const proxy = new MCPProxy(config);
 *   const stop = await proxy.start(emit);  // blocks until agent disconnects
 *   await stop();                           // graceful shutdown
 */

import { randomUUID } from "node:crypto";
import {
  type Interceptor,
  type EmitFn,
  type StopFn,
  type InterceptorKind,
} from "@omnodex/shared";
import { type ProxyConfig } from "./config.js";
import { UpstreamClientPool } from "./upstream-client.js";
import { runProxyServer } from "./proxy-server.js";

export class MCPProxy implements Interceptor {
  readonly name = "omnodex-mcp-proxy";
  readonly kind: InterceptorKind = "mcp-proxy";

  private readonly config: ProxyConfig;
  private readonly sessionId: string;
  private readonly projectPath: string | undefined;

  constructor(config: ProxyConfig, options?: { projectPath?: string }) {
    this.config = config;
    this.sessionId = randomUUID();
    this.projectPath = options?.projectPath;
  }

  /**
   * Starts the MCP proxy:
   *   1. Connects to all upstream servers and discovers their tools.
   *   2. Starts the inbound MCP server on stdin/stdout.
   *   3. Runs until the agent disconnects, then emits session.ended.
   *
   * Returns a StopFn that closes the upstream pool (the server transport
   * closes naturally when the agent disconnects, so calling stop() after
   * runProxyServer() resolves is a no-op for the server but does clean up
   * upstream connections).
   */
  async start(emit: EmitFn): Promise<StopFn> {
    const pool = new UpstreamClientPool();
    await pool.connect(this.config);

    // runProxyServer resolves when the agent disconnects (stdin EOF).
    // We don't await it here so we can return the stop function immediately
    // to the caller. The proxy's main loop is the runProxyServer promise.
    const serverDone = runProxyServer({
      pool,
      config: this.config,
      emit,
      sessionId: this.sessionId,
      projectPath: this.projectPath,
    });

    const stop: StopFn = async () => {
      // Close upstream connections. The server transport will have already
      // closed if the agent disconnected; this cleans up any lingering
      // upstream processes.
      await pool.close();
    };

    // Propagate unhandled upstream errors to stderr.
    serverDone.catch((err: unknown) => {
      process.stderr.write(
        `[omnodex-mcp-proxy] Fatal error in proxy server: ${err instanceof Error ? err.message : String(err)}\n`
      );
      process.exit(1);
    });

    return stop;
  }
}
