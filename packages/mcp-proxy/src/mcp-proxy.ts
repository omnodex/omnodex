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
 * It also carries the two cloud paths that hook shims get for free, because
 * proxy-only platforms (Cowork Desktop, ChatGPT Desktop) have no hooks:
 *
 *   - every event is queued for the live relay after it is written locally,
 *     so the session shows up in the hosted dashboard as it happens;
 *   - a timer refreshes the encrypted sync blob, and the entrypoint asks for
 *     one more refresh once the agent has disconnected.
 *
 * Both are off unless the machine has stream credentials, and neither can
 * fail the proxy: the local event log stays the source of truth.
 *
 * Typical lifecycle (from the bin entrypoint):
 *
 *   const proxy = new MCPProxy(config, { home, autoSyncScriptPath });
 *   const stop = await proxy.start(emit);  // blocks until agent disconnects
 *   await stop();                           // graceful shutdown
 */

import { randomUUID } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import {
  type Interceptor,
  type EmitFn,
  type StopFn,
  type InterceptorKind,
} from "@omnodex/shared";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { type ProxyConfig } from "./config.js";
import { UpstreamClientPool } from "./upstream-client.js";
import { runProxyServer } from "./proxy-server.js";
import {
  startProxyHttpServer,
  type HttpServeOptions,
  type ProxyHttpServer,
} from "./http-server.js";
import { createCloudPushQueue, type CloudPushFn } from "./cloud-push.js";
import {
  startAutoSyncTimer,
  type AutoSyncTimer,
  type StartSyncFn,
} from "./background-sync.js";

export interface MCPProxyOptions {
  /** Project path recorded in session.started. Defaults to cwd. */
  projectPath?: string;
  /** OMNODEX_HOME. Defaults to $OMNODEX_HOME, then ~/.omnodex. */
  home?: string;
  /**
   * Script the detached sync child runs; entrypoints pass process.argv[1].
   * Omitting it leaves the periodic sync off, which is what tests and any
   * embedder without an AUTO_SYNC_CHILD_ENV branch want.
   */
  autoSyncScriptPath?: string;
  /** Inbound transport. Defaults to stdio; tests pass an in-memory pair. */
  transport?: Transport;
  /**
   * Serve over Streamable HTTP instead of stdio. Each client session is a
   * separate proxy session over one shared upstream pool. Ignored when
   * transport is set.
   */
  http?: HttpServeOptions;
  /** Overrides for tests. */
  hooks?: {
    pushFn?: CloudPushFn;
    startSyncFn?: StartSyncFn;
    autoSyncIntervalMs?: number;
    pushFlushDelayMs?: number;
  };
}

export class MCPProxy implements Interceptor {
  readonly name = "omnodex-mcp-proxy";
  readonly kind: InterceptorKind = "mcp-proxy";

  private readonly config: ProxyConfig;
  private readonly sessionId: string;
  private readonly projectPath: string | undefined;
  private readonly home: string;
  private readonly autoSyncScriptPath: string | undefined;
  private readonly transport: Transport | undefined;
  private readonly http: HttpServeOptions | undefined;
  private readonly hooks: MCPProxyOptions["hooks"];
  private serverDone: Promise<void> | undefined;
  private httpServer: ProxyHttpServer | undefined;

  constructor(config: ProxyConfig, options?: MCPProxyOptions) {
    this.config = config;
    this.sessionId = randomUUID();
    this.projectPath = options?.projectPath;
    this.home =
      options?.home ??
      process.env.OMNODEX_HOME ??
      path.join(os.homedir(), ".omnodex");
    this.autoSyncScriptPath = options?.autoSyncScriptPath;
    this.transport = options?.transport;
    this.http = options?.transport ? undefined : options?.http;
    this.hooks = options?.hooks;
  }

  /**
   * Starts the MCP proxy:
   *   1. Starts connecting to the upstream servers in the background.
   *   2. Starts the inbound MCP server on stdin/stdout right away, so the
   *      agent is answered even while upstreams are slow or failing.
   *   3. Pushes each event to the cloud relay and refreshes the sync blob on
   *      a timer, both fire-and-forget.
   *   4. Runs until the agent disconnects, then emits session.ended.
   *
   * Returns a StopFn that flushes the pending cloud push, cancels the sync
   * timer and closes the upstream pool (the server transport closes naturally
   * when the agent disconnects, so calling stop() after runProxyServer()
   * resolves is a no-op for the server but does clean up the rest).
   */
  async start(emit: EmitFn): Promise<StopFn> {
    const pool = new UpstreamClientPool();
    pool.start(this.config);

    // The local log is written first and awaited; the push is queued after so
    // a slow or unreachable relay cannot delay an event reaching disk.
    const push = createCloudPushQueue({
      home: this.home,
      pushFn: this.hooks?.pushFn,
      flushDelayMs: this.hooks?.pushFlushDelayMs,
    });
    const emitAndPush: EmitFn = async (event) => {
      await emit(event);
      push.enqueue(event);
    };

    // Needs a script to re-spawn, so an embedder that has not opted in by
    // passing one gets the proxy's previous behaviour.
    let syncTimer: AutoSyncTimer | undefined;
    if (this.autoSyncScriptPath) {
      syncTimer = await startAutoSyncTimer({
        home: this.home,
        scriptPath: this.autoSyncScriptPath,
        intervalMs: this.hooks?.autoSyncIntervalMs,
        startSyncFn: this.hooks?.startSyncFn,
      });
    }

    // Over stdio, runProxyServer resolves when the agent disconnects (stdin
    // EOF). Over HTTP, the server runs until stop(), with one session per
    // client. Neither is awaited here, so the stop function returns at once.
    let serverDone: Promise<void>;
    if (this.http) {
      const httpServer = await startProxyHttpServer({
        ...this.http,
        pool,
        config: this.config,
        emit: emitAndPush,
        ...(this.projectPath !== undefined ? { projectPath: this.projectPath } : {}),
      });
      this.httpServer = httpServer;
      serverDone = httpServer.closed;
    } else {
      serverDone = runProxyServer({
        pool,
        config: this.config,
        emit: emitAndPush,
        sessionId: this.sessionId,
        projectPath: this.projectPath,
        ...(this.transport ? { transport: this.transport } : {}),
      });
    }
    this.serverDone = serverDone;

    const stop: StopFn = async () => {
      // Ends every HTTP session first, so each records session.ended.
      await this.httpServer?.close();
      syncTimer?.stop();
      // Sends session.ended and anything still batched behind it. Bounded by
      // pushEventsToCloud's own request timeout, so shutdown cannot hang.
      await push.close();
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

  /**
   * Resolves once the agent has disconnected and session.ended has been
   * recorded. Entrypoints use it to run their shutdown (close upstreams and
   * the event log) and exit, since hosts usually just close the pipe.
   */
  /** The endpoint URL when serving over HTTP, once start() has returned. */
  httpUrl(): string | undefined {
    return this.httpServer?.url;
  }

  whenClosed(): Promise<void> {
    if (!this.serverDone) {
      throw new Error("MCPProxy.whenClosed() called before start()");
    }
    return this.serverDone;
  }
}
