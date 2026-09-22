// In-process Streamable HTTP MCP server for tests of HTTP upstreams.
//
// startHttpMcpServer({ token }) listens on 127.0.0.1 and returns:
//   url              endpoint URL (path /mcp)
//   requests         headers of every request received, lower-cased names
//   aborted          tool call ids whose request the client cancelled
//   setToken(t)      change the accepted bearer token (null: no auth)
//   dropSessions()   forget every session, so the next request gets 404
//   close()
//
// A request without the right bearer token gets 401 with a body that echoes
// the Authorization header it received, so tests can check the proxy scrubs
// credentials from error text.
//
// Tools: echo { text } returns the text; slow { ms } waits, and records an
// abort if the client cancels first.

import * as http from "node:http";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";

export async function startHttpMcpServer(options = {}) {
  let token = options.token ?? null;
  const requests = [];
  const aborted = [];
  const sessions = new Map(); // session id -> transport

  function makeServer() {
    const server = new Server({ name: "http-test-upstream", version: "0.0.0" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        { name: "echo", description: "Echo text", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
        { name: "slow", description: "Wait", inputSchema: { type: "object", properties: { ms: { type: "number" }, id: { type: "string" } } } },
      ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const args = request.params.arguments ?? {};
      if (request.params.name === "echo") {
        return { content: [{ type: "text", text: String(args.text ?? "") }] };
      }
      if (request.params.name === "slow") {
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, Number(args.ms ?? 1000));
          extra.signal.addEventListener("abort", () => {
            clearTimeout(timer);
            aborted.push(String(args.id ?? ""));
            resolve();
          });
        });
        return { content: [{ type: "text", text: "done" }] };
      }
      return { content: [{ type: "text", text: "unknown tool" }], isError: true };
    });
    return server;
  }

  async function readJson(req) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const text = Buffer.concat(chunks).toString("utf8");
    return text ? JSON.parse(text) : undefined;
  }

  const httpServer = http.createServer(async (req, res) => {
    requests.push({ method: req.method, headers: { ...req.headers } });
    if (token !== null && req.headers.authorization !== `Bearer ${token}`) {
      res.writeHead(401, { "content-type": "text/plain" });
      res.end(`unauthorized; received authorization=${req.headers.authorization ?? "(none)"}`);
      return;
    }
    const sessionId = req.headers["mcp-session-id"];
    try {
      if (sessionId) {
        const transport = sessions.get(sessionId);
        if (!transport) {
          res.writeHead(404, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null }));
          return;
        }
        const body = req.method === "POST" ? await readJson(req) : undefined;
        await transport.handleRequest(req, res, body);
        return;
      }
      if (req.method !== "POST") {
        res.writeHead(405).end();
        return;
      }
      const body = await readJson(req);
      if (!isInitializeRequest(body)) {
        res.writeHead(400).end("expected initialize");
        return;
      }
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => sessions.set(id, transport),
      });
      await makeServer().connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      if (!res.headersSent) res.writeHead(500).end(String(err));
    }
  });

  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const { port } = httpServer.address();

  return {
    url: `http://127.0.0.1:${port}/mcp`,
    requests,
    aborted,
    setToken(t) {
      token = t;
    },
    dropSessions() {
      sessions.clear();
    },
    async close() {
      for (const t of sessions.values()) await t.close().catch(() => undefined);
      httpServer.closeAllConnections?.();
      await new Promise((resolve) => httpServer.close(resolve));
    },
  };
}
