// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- http-server
 *
 * Serves the proxy over Streamable HTTP instead of stdin/stdout, for hosts
 * that connect to MCP servers by URL. Each MCP session a client opens gets
 * its own runProxyServer instance, with its own session_id and
 * session.started / session.ended events; all sessions share one upstream
 * pool.
 *
 * Binds to loopback by default. Any other address requires allowRemote and
 * a bearer token, since the proxy calls upstream tools with the user's
 * credentials.
 */

import * as http from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { EmitFn } from "@omnodex/shared";
import type { ProxyConfig } from "./config.js";
import type { UpstreamClientPool } from "./upstream-client.js";
import { runProxyServer } from "./proxy-server.js";

/** Path the MCP endpoint is served on. */
export const HTTP_MCP_PATH = "/mcp";

/** Largest request body accepted, in bytes. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;

export interface HttpServeOptions {
  /** Address to bind. Loopback unless allowRemote is set. */
  host: string;
  /** Port to bind; 0 picks a free port. */
  port: number;
  /** Permit a non-loopback host. Requires authToken. */
  allowRemote?: boolean;
  /** When set, every request must carry "Authorization: Bearer <token>". */
  authToken?: string;
}

export interface ProxyHttpServerOptions extends HttpServeOptions {
  pool: UpstreamClientPool;
  config: ProxyConfig;
  emit: EmitFn;
  projectPath?: string;
}

export interface ProxyHttpServer {
  /** Endpoint URL, e.g. http://127.0.0.1:8787/mcp */
  url: string;
  /** Number of MCP sessions currently open. */
  sessionCount(): number;
  /** Ends every session (recording session.ended) and stops listening. */
  close(): Promise<void>;
  /** Resolves once close() has finished. */
  closed: Promise<void>;
}

export function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}

/**
 * Parses "host:port", "[::1]:port" or a bare port (loopback) as passed to
 * --http. Throws on anything else.
 */
export function parseHttpListen(value: string): { host: string; port: number } {
  const bare = /^\d+$/.test(value);
  const m = bare ? null : /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(value);
  if (!bare && !m) throw new Error(`--http expects host:port or a port, got "${value}"`);
  const host = bare ? "127.0.0.1" : m![1]!.replace(/^\[|\]$/g, "");
  const port = Number(bare ? value : m![2]);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`--http port out of range: "${value}"`);
  }
  return { host, port };
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    return isLoopbackHost(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function tokenMatches(header: string | undefined, token: string): boolean {
  const expected = Buffer.from(`Bearer ${token}`);
  const got = Buffer.from(header ?? "");
  return got.length === expected.length && timingSafeEqual(got, expected);
}

function sendJsonRpcError(res: http.ServerResponse, status: number, message: string): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }));
}

async function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : undefined;
}

/** Starts listening and returns once the port is bound. */
export async function startProxyHttpServer(opts: ProxyHttpServerOptions): Promise<ProxyHttpServer> {
  const { pool, config, emit, projectPath, host, port, allowRemote, authToken } = opts;
  if (!isLoopbackHost(host)) {
    if (!allowRemote) {
      throw new Error(
        `refusing to serve on non-loopback address ${host}: the proxy calls upstream ` +
          `tools with your credentials. Pass --allow-remote with a bearer token to do this deliberately.`
      );
    }
    if (!authToken) {
      throw new Error(`serving on non-loopback address ${host} requires a bearer token`);
    }
  }

  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; done: Promise<void> }>();
  let allowedHosts: string[] | undefined;

  const httpServer = http.createServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      if (!res.headersSent) {
        sendJsonRpcError(res, 400, err instanceof Error ? err.message : String(err));
      } else {
        res.end();
      }
    });
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (authToken && !tokenMatches(req.headers.authorization, authToken)) {
      res.writeHead(401, { "www-authenticate": "Bearer" }).end();
      return;
    }
    // A loopback server only answers requests addressed to a loopback name,
    // and refuses browser requests from other origins, so a web page cannot
    // reach it through DNS rebinding.
    if (allowedHosts) {
      if (!allowedHosts.includes(req.headers.host ?? "")) {
        res.writeHead(403).end("host not allowed");
        return;
      }
      const origin = req.headers.origin;
      if (origin && !isLoopbackOrigin(origin)) {
        res.writeHead(403).end("origin not allowed");
        return;
      }
    }
    const path = (req.url ?? "").split("?")[0];
    if (path !== HTTP_MCP_PATH) {
      res.writeHead(404).end();
      return;
    }

    const sessionHeader = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader;
    if (sessionId) {
      const session = sessions.get(sessionId);
      if (!session) {
        sendJsonRpcError(res, 404, "Session not found");
        return;
      }
      const body = req.method === "POST" ? await readJsonBody(req) : undefined;
      await session.transport.handleRequest(req, res, body);
      return;
    }

    if (req.method !== "POST") {
      sendJsonRpcError(res, 400, "Missing mcp-session-id header");
      return;
    }
    const body = await readJsonBody(req);
    if (!isInitializeRequest(body)) {
      sendJsonRpcError(res, 400, "The first request of a session must be initialize");
      return;
    }

    // One proxy session per MCP session, over the shared upstream pool.
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, done });
      },
    });
    let onConnected!: () => void;
    const connected = new Promise<void>((resolve) => {
      onConnected = resolve;
    });
    const done = runProxyServer({
      pool,
      config,
      emit,
      sessionId: randomUUID(),
      ...(projectPath !== undefined ? { projectPath } : {}),
      transport,
      onConnected,
    }).finally(() => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    });
    done.catch((err: unknown) => {
      process.stderr.write(
        `[omnodex-mcp-proxy] session error: ${err instanceof Error ? err.message : String(err)}\n`
      );
    });
    await connected;
    await transport.handleRequest(req, res, body);
  }

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => {
      httpServer.off("error", reject);
      resolve();
    });
  });
  const address = httpServer.address();
  const boundPort = typeof address === "object" && address ? address.port : port;
  const urlHost = host.includes(":") ? `[${host}]` : host;
  if (isLoopbackHost(host)) {
    allowedHosts = [`127.0.0.1:${boundPort}`, `localhost:${boundPort}`, `[::1]:${boundPort}`];
  }

  let resolveClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  let closing: Promise<void> | undefined;

  return {
    url: `http://${urlHost}:${boundPort}${HTTP_MCP_PATH}`,
    sessionCount: () => sessions.size,
    closed,
    close() {
      closing ??= (async () => {
        const open = [...sessions.values()];
        await Promise.allSettled(open.map((s) => s.transport.close()));
        await Promise.allSettled(open.map((s) => s.done));
        httpServer.closeAllConnections();
        await new Promise<void>((resolve) => httpServer.close(() => resolve()));
        resolveClosed();
      })();
      return closing;
    },
  };
}
