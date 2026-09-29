// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Dashboard HTTP server. Serves the single-file HTML dashboard at "/" and
 * a tiny JSON API at /api/* that reads from the SQLite read model.
 *
 * Also exposes a Server-Sent Events endpoint at /api/events that pushes
 * projected read-model updates to the browser in real time as the
 * streaming detect loop processes new events from the event log.
 *
 * The server listens on loopback only and answers only requests addressed
 * to a loopback host, so neither another machine on the network nor a web
 * page open in the user's browser can read what the agent did. There is no
 * CORS allowance: the page is served from the same origin as the API.
 *
 * Uses Node's built-in http module -- zero new dependencies.
 */

import * as http from "node:http";
import * as path from "node:path";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import { collapseCorrelated, readSnapshot } from "@omnodex/projection";
import type {
  FileEventRow,
  ReadModelStore,
  RiskEventRow,
  SessionRow,
  ToolCallRow,
} from "@omnodex/projection";

export interface DashboardServerOptions {
  store: ReadModelStore;
  /** Port to listen on. 0 picks a free port (see DashboardServer.port). */
  port: number;
  /** Directory containing dashboard.html */
  assetsDir: string;
}

/**
 * Addresses the server listens on. IPv4 loopback is required; IPv6 loopback
 * is best effort, so `localhost` works whichever address the browser tries
 * first, on hosts with IPv6 disabled too.
 */
const IPV4_LOOPBACK = "127.0.0.1";
const IPV6_LOOPBACK = "::1";

/** Host names a request may be addressed to. */
const LOOPBACK_NAMES = new Set(["localhost", IPV4_LOOPBACK, IPV6_LOOPBACK]);

/**
 * Whether a Host header (or an Origin's host) names this server on a
 * loopback name. Anything else is a request routed here under a foreign
 * name, which is what a DNS-rebinding page produces.
 */
export function isLoopbackHost(host: string | undefined, port: number): boolean {
  if (!host) return false;
  const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(host);
  if (!match) return false;
  const name = (match[1] ?? match[2]).toLowerCase();
  return LOOPBACK_NAMES.has(name) && Number(match[3]) === port;
}

/** Whether an Origin header, when present, is this server's own origin. */
export function isLoopbackOrigin(origin: string | undefined, port: number): boolean {
  if (origin === undefined) return true;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  return url.protocol === "http:" && isLoopbackHost(url.host, port);
}

/**
 * The directory to serve dashboard.html from, given the running module's
 * URL (`import.meta.url`, or its CommonJS equivalent in the npm bundle).
 *
 * In a source checkout (the module sits in the CLI package's dist/) this is
 * src/, so the page is always the current one whichever build command ran:
 * `tsc -b` compiles the TypeScript but copies no assets. Anywhere else, such
 * as the npm bundle, the page ships next to the module.
 *
 * fileURLToPath, not URL.pathname: pathname keeps a leading "/" before a
 * Windows drive letter and leaves spaces percent-encoded on every platform.
 */
export function resolveDashboardAssetsDir(moduleUrl: string): string {
  const moduleDir = path.dirname(fileURLToPath(moduleUrl));
  const pkgDir = path.dirname(moduleDir);
  const srcDir = path.join(pkgDir, "src");
  if (isCliPackage(pkgDir) && fs.existsSync(path.join(srcDir, "dashboard.html"))) {
    return srcDir;
  }
  return moduleDir;
}

function isCliPackage(dir: string): boolean {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf-8")) as { name?: unknown };
    return pkg.name === "@omnodex/cli";
  } catch {
    return false;
  }
}

/** What the dashboard command holds open while it runs. */
export interface DashboardResources {
  /** Stops the streaming loop; resolves once its tails have finished. */
  stopStreaming: () => Promise<void>;
  /** Flushes buffered cloud events, if cloud streaming is on. */
  transport?: { stop(): Promise<void> } | null;
  server: { close(): Promise<void> };
  logs: ReadonlyArray<{ log: { close(): Promise<void> } }>;
  store: { close(): Promise<void> };
}

/**
 * Release everything the dashboard command holds, in dependency order: stop
 * the writers (streaming loop, cloud transport) first, then the HTTP server,
 * then the event logs and the read model they write into. Each step is
 * awaited, so SQLite and log files are closed before the process exits;
 * on Windows an open handle keeps the files locked. A failing step is
 * logged and does not stop the rest.
 */
export async function shutdownDashboard(resources: DashboardResources): Promise<void> {
  const step = async (name: string, fn: () => Promise<void>): Promise<void> => {
    try {
      await fn();
    } catch (err) {
      console.error(`[dashboard] error closing ${name}:`, err);
    }
  };
  await step("streaming loop", resources.stopStreaming);
  if (resources.transport) {
    const transport = resources.transport;
    await step("cloud transport", () => transport.stop());
  }
  await step("server", () => resources.server.close());
  for (const { log } of resources.logs) {
    await step("event log", () => log.close());
  }
  await step("read model", () => resources.store.close());
}

// ---------------------------------------------------------------------------
// SSE message types
// ---------------------------------------------------------------------------

/**
 * Discriminated union of every message the server can push to SSE clients.
 * The browser handles each type independently, updating only the affected
 * panel rather than doing a full page reload.
 */
export type SseMessage =
  | { type: "connected" }
  | { type: "heartbeat" }
  | { type: "session.upserted"; payload: SessionRow }
  | { type: "tool_call.inserted"; payload: ToolCallRow }
  | { type: "tool_call.patched"; payload: ToolCallRow }
  | { type: "file_event.inserted"; payload: FileEventRow }
  | { type: "risk_event.inserted"; payload: RiskEventRow }
  /** Rows changed in place (a correlation pass paired calls); reload the snapshot. */
  | { type: "read_model.changed" };

// ---------------------------------------------------------------------------
// DashboardServer class
// ---------------------------------------------------------------------------

/**
 * HTTP server for the Omnodex local dashboard.
 *
 * Usage:
 *   const server = new DashboardServer({ store, port, assetsDir });
 *   await server.ready;
 *   server.broadcast({ type: "session.upserted", payload: row });
 *   server.close();
 */
export class DashboardServer {
  private readonly store: ReadModelStore;
  private readonly assetsDir: string;
  private readonly servers: http.Server[] = [];
  private readonly sseClients = new Set<http.ServerResponse>();
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private boundPort = 0;

  /**
   * Resolves once the server is listening on IPv4 loopback. Rejects if it
   * cannot (for example, the port is taken).
   */
  readonly ready: Promise<void>;

  constructor(options: DashboardServerOptions) {
    this.store = options.store;
    this.assetsDir = options.assetsDir;
    this.ready = this.listen(options.port);

    // Heartbeat keeps SSE connections alive through proxies and firewalls.
    this.heartbeatTimer = setInterval(() => {
      this.broadcast({ type: "heartbeat" });
    }, 15_000);
  }

  /** The port the server is listening on, once `ready` has resolved. */
  get port(): number {
    return this.boundPort;
  }

  private async listen(port: number): Promise<void> {
    const ipv4 = this.createServer();
    await listenOn(ipv4, port, IPV4_LOOPBACK);
    this.servers.push(ipv4);
    const address = ipv4.address();
    this.boundPort = typeof address === "object" && address ? address.port : port;

    const ipv6 = this.createServer();
    try {
      await listenOn(ipv6, this.boundPort, IPV6_LOOPBACK);
      this.servers.push(ipv6);
    } catch (err) {
      // No IPv6 on this host is fine: browsers fall back to 127.0.0.1. The
      // port being held on ::1 by something else is not, because a browser
      // that tries ::1 first for `localhost` would reach that process.
      if ((err as NodeJS.ErrnoException).code === "EADDRINUSE") {
        console.warn(
          `[dashboard] port ${this.boundPort} is in use on ${IPV6_LOOPBACK} by another process; ` +
            `open http://${IPV4_LOOPBACK}:${this.boundPort} instead of localhost`,
        );
      }
    }
    console.log(`[dashboard] listening on http://localhost:${this.boundPort} (loopback only)`);
  }

  private createServer(): http.Server {
    return http.createServer((req, res) => {
      this.handleRequest(req, res).catch((err: unknown) => {
        console.error("[dashboard] request error:", err);
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "internal server error" }));
        }
      });
    });
  }

  /**
   * Push a message to all connected SSE clients. Silently drops any
   * client whose write has failed (e.g. the tab was closed).
   */
  broadcast(message: SseMessage): void {
    if (this.sseClients.size === 0) return;
    const payload = `data: ${JSON.stringify(message)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(payload);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  /**
   * Shut down the HTTP server and cancel the heartbeat. Open connections,
   * including idle keep-alive sockets and SSE streams, are closed rather
   * than waited for. Resolves once every listener has stopped.
   */
  async close(): Promise<void> {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    for (const client of this.sseClients) {
      try { client.end(); } catch { /* ignore */ }
    }
    this.sseClients.clear();
    await Promise.all(
      this.servers.map(
        (server) =>
          new Promise<void>((resolve) => {
            server.close(() => resolve());
            server.closeAllConnections();
          }),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Request handler
  // -------------------------------------------------------------------------

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    // Refuse anything not addressed to this server by a loopback name, or
    // sent from another origin. The first stops DNS rebinding; the second
    // stops a page elsewhere from reading the API, SSE stream included.
    if (
      !isLoopbackHost(req.headers.host, this.boundPort) ||
      !isLoopbackOrigin(req.headers.origin, this.boundPort)
    ) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "forbidden" }));
      return;
    }

    const url = new URL(req.url ?? "/", "http://localhost");
    const pathname = url.pathname;

    // --- SSE endpoint ---
    if (pathname === "/api/events") {
      this.handleSse(req, res);
      return;
    }

    // --- JSON API routes ---
    // Every session with its rows, correlated hook and proxy observations
    // collapsed into one call and one finding: what the page renders.
    if (pathname === "/api/snapshot") {
      return sendJson(res, collapseCorrelated(await readSnapshot(this.store)));
    }

    if (pathname === "/api/sessions") {
      const sessions = await this.store.listSessions();
      return sendJson(res, sessions);
    }

    const sessionMatch = pathname.match(/^\/api\/sessions\/([^/]+)$/);
    if (sessionMatch) {
      const session = await this.store.getSession(sessionMatch[1]);
      if (!session) return send404(res);
      return sendJson(res, session);
    }

    const toolCallsMatch = pathname.match(
      /^\/api\/sessions\/([^/]+)\/tool-calls$/,
    );
    if (toolCallsMatch) {
      const rows = await this.store.listToolCalls(toolCallsMatch[1]);
      return sendJson(res, rows);
    }

    const fileEventsMatch = pathname.match(
      /^\/api\/sessions\/([^/]+)\/file-events$/,
    );
    if (fileEventsMatch) {
      const rows = await this.store.listFileEvents(fileEventsMatch[1]);
      return sendJson(res, rows);
    }

    const riskEventsMatch = pathname.match(
      /^\/api\/sessions\/([^/]+)\/risk-events$/,
    );
    if (riskEventsMatch) {
      const rows = await this.store.listRiskEvents(riskEventsMatch[1]);
      return sendJson(res, rows);
    }

    // --- Static: serve dashboard.html at root ---
    if (pathname === "/" || pathname === "/index.html") {
      const htmlPath = path.join(this.assetsDir, "dashboard.html");
      const html = fs.readFileSync(htmlPath, "utf-8");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
      return;
    }

    send404(res);
  }

  // -------------------------------------------------------------------------
  // SSE connection handler
  // -------------------------------------------------------------------------

  private handleSse(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): void {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no", // disable nginx buffering if present
    });

    // Confirm connection to the client immediately
    res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
    this.sseClients.add(res);

    req.on("close", () => {
      this.sseClients.delete(res);
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function listenOn(server: http.Server, port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => reject(err);
    server.once("error", onError);
    server.listen(port, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
}

function sendJson(res: http.ServerResponse, data: unknown): void {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function send404(res: http.ServerResponse): void {
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}
