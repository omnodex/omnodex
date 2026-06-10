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
 * Uses Node's built-in http module -- zero new dependencies.
 */

import * as http from "node:http";
import * as path from "node:path";
import * as fs from "node:fs";
import type {
  FileEventRow,
  ReadModelStore,
  RiskEventRow,
  SessionRow,
  ToolCallRow,
} from "@omnodex/projection";

export interface DashboardServerOptions {
  store: ReadModelStore;
  port: number;
  /** Directory containing dashboard.html */
  assetsDir: string;
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
  | { type: "risk_event.inserted"; payload: RiskEventRow };

// ---------------------------------------------------------------------------
// DashboardServer class
// ---------------------------------------------------------------------------

/**
 * HTTP server for the Omnodex local dashboard.
 *
 * Usage:
 *   const server = new DashboardServer({ store, port, assetsDir });
 *   server.broadcast({ type: "session.upserted", payload: row });
 *   server.close();
 */
export class DashboardServer {
  private readonly store: ReadModelStore;
  private readonly assetsDir: string;
  private readonly server: http.Server;
  private readonly sseClients = new Set<http.ServerResponse>();
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: DashboardServerOptions) {
    this.store = options.store;
    this.assetsDir = options.assetsDir;

    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res).catch((err: unknown) => {
        console.error("[dashboard] request error:", err);
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "internal server error" }));
        }
      });
    });

    this.server.listen(options.port, () => {
      console.log(`[dashboard] listening on http://localhost:${options.port}`);
    });

    // Heartbeat keeps SSE connections alive through proxies and firewalls.
    this.heartbeatTimer = setInterval(() => {
      this.broadcast({ type: "heartbeat" });
    }, 15_000);
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

  /** Gracefully shut down the HTTP server and cancel the heartbeat. */
  close(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    for (const client of this.sseClients) {
      try { client.end(); } catch { /* ignore */ }
    }
    this.sseClients.clear();
    this.server.close();
  }

  // -------------------------------------------------------------------------
  // Request handler
  // -------------------------------------------------------------------------

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const pathname = url.pathname;

    // CORS headers for local dev
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // --- SSE endpoint ---
    if (pathname === "/api/events") {
      this.handleSse(req, res);
      return;
    }

    // --- JSON API routes ---
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

function sendJson(res: http.ServerResponse, data: unknown): void {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function send404(res: http.ServerResponse): void {
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}
