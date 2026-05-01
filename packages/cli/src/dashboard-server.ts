// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
/**
 * Dashboard HTTP server. Serves the single-file HTML dashboard at "/" and
 * a tiny JSON API at /api/* that reads from the SQLite read model.
 *
 * Uses Node's built-in http module -- zero new dependencies.
 */

import * as http from "node:http";
import * as path from "node:path";
import * as fs from "node:fs";
import type { ReadModelStore } from "@omnodex/projection";

export interface DashboardServerOptions {
  store: ReadModelStore;
  port: number;
  /** Directory containing dashboard.html */
  assetsDir: string;
}

export function startDashboardServer(
  options: DashboardServerOptions,
): http.Server {
  const { store, port, assetsDir } = options;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${port}`);
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

    try {
      // --- API routes ---
      if (pathname === "/api/sessions") {
        const sessions = await store.listSessions();
        return sendJson(res, sessions);
      }

      const sessionMatch = pathname.match(
        /^\/api\/sessions\/([^/]+)$/,
      );
      if (sessionMatch) {
        const session = await store.getSession(sessionMatch[1]);
        if (!session) return send404(res);
        return sendJson(res, session);
      }

      const toolCallsMatch = pathname.match(
        /^\/api\/sessions\/([^/]+)\/tool-calls$/,
      );
      if (toolCallsMatch) {
        const rows = await store.listToolCalls(toolCallsMatch[1]);
        return sendJson(res, rows);
      }

      const fileEventsMatch = pathname.match(
        /^\/api\/sessions\/([^/]+)\/file-events$/,
      );
      if (fileEventsMatch) {
        const rows = await store.listFileEvents(fileEventsMatch[1]);
        return sendJson(res, rows);
      }

      const riskEventsMatch = pathname.match(
        /^\/api\/sessions\/([^/]+)\/risk-events$/,
      );
      if (riskEventsMatch) {
        const rows = await store.listRiskEvents(riskEventsMatch[1]);
        return sendJson(res, rows);
      }

      // --- Static: serve dashboard.html at root ---
      if (pathname === "/" || pathname === "/index.html") {
        const htmlPath = path.join(assetsDir, "dashboard.html");
        const html = fs.readFileSync(htmlPath, "utf-8");
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(html);
        return;
      }

      send404(res);
    } catch (err) {
      console.error("[dashboard] request error:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "internal server error" }));
    }
  });

  server.listen(port, () => {
    console.log(`[dashboard] listening on http://localhost:${port}`);
  });

  return server;
}

function sendJson(res: http.ServerResponse, data: unknown): void {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function send404(res: http.ServerResponse): void {
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}
