// Integration tests for runProxyServer.
// Drives the inbound server with the SDK's own Client over an in-memory
// transport, against a real mock upstream subprocess. The SDK Client applies
// the same outputSchema and structuredContent checks that MCP hosts do.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig() {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: {
          MOCK_TOOLS: JSON.stringify(["get_info"]),
          MOCK_STRUCTURED: "1",
          MOCK_RESULT_TEXT: "proxied",
        },
      },
    ],
  });
}

/**
 * Starts the proxy server on an in-memory transport and connects an SDK
 * client to it. Returns the client, collected events, and the promise that
 * resolves when the server has finished (after the client disconnects).
 */
async function startProxy() {
  const config = makeConfig();
  const pool = new UpstreamClientPool();
  await pool.connect(config);

  const events = [];
  const emit = (ev) => events.push(ev);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  const serverDone = runProxyServer({
    pool,
    config,
    emit,
    sessionId: "sess-proxy-test",
    projectPath: "/home/case/project",
    transport: serverTransport,
  });

  const client = new Client({ name: "proxy-test-client", version: "0.0.0" }, {});
  await client.connect(clientTransport);

  return { client, events, serverDone, pool };
}

// ---------------------------------------------------------------------------
// Tool surface and structured results
// ---------------------------------------------------------------------------

test("client can call a passthrough tool that declares an outputSchema", async () => {
  const { client, serverDone, pool } = await startProxy();
  try {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "filesystem__get_info");
    assert.ok(tool, `passthrough tool missing: ${tools.map((t) => t.name).join(", ")}`);
    assert.equal(tool.outputSchema.$schema, undefined);

    // The SDK client throws if a tool with an outputSchema returns no
    // structuredContent, so a successful call proves it was forwarded.
    const result = await client.callTool({ name: "filesystem__get_info", arguments: { input: "q" } });
    assert.equal(result.isError, false);
    assert.deepEqual(result.structuredContent, { content: "proxied:get_info:q" });
  } finally {
    await client.close();
    await serverDone;
    await pool.close();
  }
});

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

test("session.ended is emitted only after the client disconnects", async () => {
  const { client, events, serverDone, pool } = await startProxy();
  try {
    await client.callTool({ name: "filesystem__get_info", arguments: {} });
    // Let any fire-and-forget emits settle.
    await new Promise((r) => setImmediate(r));

    const typesWhileConnected = events.map((e) => e.event_type);
    assert.ok(typesWhileConnected.includes("session.started"));
    assert.ok(typesWhileConnected.includes("tool.completed"));
    assert.equal(typesWhileConnected.includes("session.ended"), false);

    await client.close();
    await serverDone;

    const types = events.map((e) => e.event_type);
    assert.equal(types.at(-1), "session.ended");
    assert.equal(types.filter((t) => t === "session.ended").length, 1);
  } finally {
    await pool.close();
  }
});
