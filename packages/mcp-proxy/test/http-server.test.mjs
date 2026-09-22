// Tests for serving the proxy over Streamable HTTP: one proxy session per
// client session over a shared upstream pool, session events, loopback-only
// binding, bearer tokens, host and origin checks, and that the core modules
// stay runtime-neutral.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import {
  startProxyHttpServer,
  parseHttpListen,
  isLoopbackHost,
} from "../dist/http-server.js";
import { MCPProxy } from "../dist/mcp-proxy.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");
const BUILT_INS = ["omnodex_status", "omnodex_connect", "omnodex_connection_status"];

function makeConfig() {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "mock",
        transport: "stdio",
        command: process.execPath,
        args: [MOCK_SERVER],
        env: { MOCK_TOOLS: JSON.stringify(["ping"]), MOCK_RESULT_TEXT: "pong" },
      },
    ],
  });
}

async function startServer(extra = {}) {
  const config = makeConfig();
  const pool = new UpstreamClientPool();
  await pool.connect(config);
  const events = [];
  const server = await startProxyHttpServer({
    host: "127.0.0.1",
    port: 0,
    pool,
    config,
    emit: (e) => {
      events.push(e);
    },
    projectPath: "/home/case/project",
    ...extra,
  });
  return {
    server,
    events,
    async stop() {
      await server.close();
      await pool.close();
    },
  };
}

async function connectClient(endpoint, headers) {
  const transport = new StreamableHTTPClientTransport(new URL(endpoint), headers ? { requestInit: { headers } } : {});
  const client = new Client({ name: "http-server-test", version: "0.0.0" }, {});
  await client.connect(transport);
  return { client, transport };
}

const started = (events) => events.filter((e) => e.event_type === "session.started");
const ended = (events) => events.filter((e) => e.event_type === "session.ended");

test("an HTTP client lists and calls tools, and its session is recorded start to end", async () => {
  const s = await startServer();
  try {
    assert.match(s.server.url, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
    const { client, transport } = await connectClient(s.server.url);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name), [...BUILT_INS, "mock__ping"]);
    const result = await client.callTool({ name: "mock__ping", arguments: {} });
    assert.equal(result.content[0].text, "pong:ping:");

    assert.equal(started(s.events).length, 1);
    assert.deepEqual(started(s.events)[0].mcp_server_transports, [{ name: "mock", transport: "stdio" }]);
    const sessionId = started(s.events)[0].session_id;
    assert.ok(s.events.some((e) => e.event_type === "tool.invoked" && e.session_id === sessionId));

    await transport.terminateSession();
    await client.close();
    for (let i = 0; i < 100 && ended(s.events).length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    assert.equal(ended(s.events).length, 1);
    assert.equal(ended(s.events)[0].session_id, sessionId);
    assert.equal(s.server.sessionCount(), 0);
  } finally {
    await s.stop();
  }
});

test("each client gets its own session over the shared upstream pool, and close() ends them all", async () => {
  const s = await startServer();
  try {
    const a = await connectClient(s.server.url);
    const b = await connectClient(s.server.url);
    assert.equal((await a.client.callTool({ name: "mock__ping", arguments: {} })).content[0].text, "pong:ping:");
    assert.equal((await b.client.callTool({ name: "mock__ping", arguments: {} })).content[0].text, "pong:ping:");
    assert.equal(s.server.sessionCount(), 2);
    const ids = started(s.events).map((e) => e.session_id);
    assert.equal(new Set(ids).size, 2);

    await s.server.close();
    assert.deepEqual(ended(s.events).map((e) => e.session_id).sort(), [...ids].sort());
    await a.client.close().catch(() => undefined);
    await b.client.close().catch(() => undefined);
  } finally {
    await s.stop();
  }
});

test("a non-loopback address is refused unless allowed, and allowing it needs a token", async () => {
  const config = makeConfig();
  const base = { port: 0, pool: new UpstreamClientPool(), config, emit: () => undefined };
  await assert.rejects(startProxyHttpServer({ ...base, host: "0.0.0.0" }), /refusing to serve on non-loopback/);
  await assert.rejects(startProxyHttpServer({ ...base, host: "0.0.0.0", allowRemote: true }), /requires a bearer token/);
});

test("with a token set, requests without it get 401 and requests with it work", async () => {
  const s = await startServer({ authToken: "case-proxy-token" });
  try {
    const res = await fetch(s.server.url, { method: "POST", body: "{}", headers: { "content-type": "application/json" } });
    assert.equal(res.status, 401);
    const { client } = await connectClient(s.server.url, { Authorization: "Bearer case-proxy-token" });
    assert.equal((await client.callTool({ name: "mock__ping", arguments: {} })).content[0].text, "pong:ping:");
    await client.close();
  } finally {
    await s.stop();
  }
});

test("foreign Host or Origin headers, unknown paths and unknown sessions are rejected", async () => {
  const s = await startServer();
  try {
    const endpoint = new URL(s.server.url);
    const init = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    };
    const post = (target, headers = {}) =>
      new Promise((resolve, reject) => {
        // node:http so the Host header can be set explicitly.
        import("node:http").then(({ request }) => {
          const req = request(
            { host: endpoint.hostname, port: endpoint.port, path: target, method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers } },
            (res) => {
              res.resume();
              res.on("end", () => resolve(res.statusCode));
            }
          );
          req.on("error", reject);
          req.end(JSON.stringify(init));
        });
      });

    assert.equal(await post("/mcp", { host: "evil.example:80" }), 403);
    assert.equal(await post("/mcp", { origin: "https://evil.example" }), 403);
    assert.equal(await post("/other"), 404);
    assert.equal(await post("/mcp", { "mcp-session-id": "no-such-session" }), 404);
    // A loopback origin, such as a local tool's own page, is allowed.
    assert.equal(await post("/mcp", { origin: `http://localhost:${endpoint.port}` }), 200);
  } finally {
    await s.stop();
  }
});

test("MCPProxy serves over HTTP when given the http option", async () => {
  // A scratch home: the proxy keeps machine state for rule detection there.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-http-proxy-"));
  const proxy = new MCPProxy(makeConfig(), {
    home,
    projectPath: "/home/case/project",
    http: { host: "127.0.0.1", port: 0 },
    hooks: { pushFn: async () => undefined },
  });
  const events = [];
  const stop = await proxy.start((e) => {
    events.push(e);
  });
  try {
    assert.match(proxy.httpUrl(), /\/mcp$/);
    const { client } = await connectClient(proxy.httpUrl());
    for (let i = 0; i < 100; i++) {
      const { tools } = await client.listTools();
      if (tools.some((t) => t.name === "mock__ping")) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal((await client.callTool({ name: "mock__ping", arguments: {} })).content[0].text, "pong:ping:");
    await client.close();
  } finally {
    await stop();
  }
  await proxy.whenClosed();
  assert.equal(ended(events).length, started(events).length);
});

test("parseHttpListen and isLoopbackHost", () => {
  assert.deepEqual(parseHttpListen("127.0.0.1:8787"), { host: "127.0.0.1", port: 8787 });
  assert.deepEqual(parseHttpListen("8787"), { host: "127.0.0.1", port: 8787 });
  assert.deepEqual(parseHttpListen("[::1]:9000"), { host: "::1", port: 9000 });
  assert.deepEqual(parseHttpListen("localhost:0"), { host: "localhost", port: 0 });
  assert.throws(() => parseHttpListen("nope"), /expects host:port/);
  assert.throws(() => parseHttpListen("127.0.0.1:70000"), /out of range/);
  for (const h of ["127.0.0.1", "127.1.2.3", "localhost", "::1", "[::1]"]) assert.ok(isLoopbackHost(h), h);
  for (const h of ["0.0.0.0", "192.168.1.5", "example.com", "::"]) assert.ok(!isLoopbackHost(h), h);
});

test("the core modules use no Node-only APIs, so another runtime can share them", () => {
  const coreDir = path.join(__dirname, "..", "dist", "core");
  const files = fs.readdirSync(coreDir).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 2);
  for (const f of files) {
    const src = fs.readFileSync(path.join(coreDir, f), "utf8");
    for (const banned of [/from\s+["']node:/, /\brequire\(/, /\bprocess\./, /\bBuffer\b/]) {
      assert.ok(!banned.test(src), `${f} matches ${banned}`);
    }
  }
});
