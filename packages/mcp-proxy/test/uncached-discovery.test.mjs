// Cold upstream discovery and recovery guidance through the inbound MCP server.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ProxyConfigSchema } from "../dist/config.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { runProxyServer } from "../dist/proxy-server.js";

const mockServer = fileURLToPath(new URL("./helpers/mock-mcp-server.mjs", import.meta.url));
function upstream(name, delay, extra = {}) {
  return { name, transport: "stdio", command: process.execPath, args: [mockServer],
    env: { MOCK_TOOLS: '["ping"]', MOCK_STARTUP_DELAY_MS: String(delay), ...extra } };
}

async function start(t, upstreams, connection = {}, cached = new Map()) {
  const stderr = [];
  t.mock.method(process.stderr, "write", (chunk) => { stderr.push(String(chunk)); return true; });
  const config = ProxyConfigSchema.parse({ version: 1, upstream_servers: upstreams,
    upstream_connection: { connect_timeout_ms: 90000, retry_initial_delay_ms: 600000,
      retry_give_up_delay_ms: 6000000, ...connection } });
  const pool = new UpstreamClientPool({ toolCache: {
    load: (server) => cached.get(server.name), save: () => undefined,
  } });
  pool.start(config);
  const [clientTransport, transport] = InMemoryTransport.createLinkedPair();
  const startedAt = performance.now();
  const done = runProxyServer({ pool, config, emit: () => undefined, sessionId: "cold-discovery",
    projectPath: "/home/case/project", transport });
  const client = new Client({ name: "discovery-test", version: "1" }, {});
  await client.connect(clientTransport);
  t.after(async () => { await client.close(); await done; await pool.close(); });
  return { client, pool, stderr, startedAt,
    names: async () => (await client.listTools()).tools.map((tool) => tool.name),
    status: async () => JSON.parse((await client.callTool({ name: "omnodex_status", arguments: {} })).content[0].text),
  };
}

test("an uncached upstream starting in 25 seconds appears in the first list", { timeout: 45000 }, async (t) => {
  const proxy = await start(t, [upstream("cold", 25000)]);
  const began = performance.now();
  assert.ok((await proxy.names()).includes("cold__ping"));
  assert.ok(performance.now() - began < 40000, "return once connected rather than waiting out 45 seconds");
  assert.equal((await proxy.status()).warnings, undefined);
});

test("a 60-second cold start stops listing at 45 seconds and reports restart guidance", { timeout: 95000 }, async (t) => {
  const proxy = await start(t, [upstream("late", 60000)]);
  assert.equal((await proxy.names()).includes("late__ping"), false);
  const elapsed = performance.now() - proxy.startedAt;
  assert.ok(elapsed >= 44000 && elapsed < 49000, `expected the 45-second ceiling, got ${elapsed}ms`);
  const warningLines = () => proxy.stderr.filter((line) => /late.*restart the agent app/i.test(line));
  assert.equal(warningLines().length, 1);
  assert.match((await proxy.status()).warnings.join("\n"), /late.*still connecting.*restart the agent app/i);
  await proxy.pool.waitForInitialAttempts(35000);
  assert.equal(proxy.pool.getUpstreamStatuses()[0].state, "connected");
  assert.match((await proxy.status()).warnings.join("\n"), /late.*connected after the tool list was sent.*quit and reopen/i);
  assert.equal(warningLines().length, 1, "the warning is emitted once per upstream");
  assert.ok((await proxy.names()).includes("late__ping"));
  assert.equal((await proxy.status()).warnings, undefined, "an explicit refresh makes the tools available");
});

test("a cached upstream is listed immediately even with a long cold-start window", async (t) => {
  const cached = new Map([["cached", [{ name: "ping", inputSchema: { type: "object" } }]]]);
  const proxy = await start(t, [upstream("cached", 1200)], {}, cached);
  const began = performance.now();
  assert.ok((await proxy.names()).includes("cached__ping"));
  assert.ok(performance.now() - began < 800);
  await proxy.pool.waitForInitialAttempts(5000);
  assert.equal((await proxy.status()).warnings, undefined);
});

test("a failed uncached upstream returns at its first failure without awaiting retry", async (t) => {
  const proxy = await start(t, [upstream("broken", 0, { MOCK_FAIL_STARTUP: "1" })]);
  const began = performance.now();
  assert.equal((await proxy.names()).includes("broken__ping"), false);
  assert.ok(performance.now() - began < 3000);
  assert.equal(proxy.pool.getUpstreamStatuses()[0].state, "failed");
});

test("a short uncached override expires from proxy start and does not delay later lists", async (t) => {
  const proxy = await start(t, [upstream("late", 1800)], {
    discovery_window_ms: 10, discovery_window_uncached_ms: 500,
  });
  assert.equal((await proxy.names()).includes("late__ping"), false);
  assert.ok(performance.now() - proxy.startedAt >= 400);
  assert.equal((await proxy.names()).includes("late__ping"), false);
  assert.ok(performance.now() - proxy.startedAt < 1000, "the second request gets no new window");
  assert.equal(proxy.stderr.filter((line) => /restart the agent app/i.test(line)).length, 1);
  await proxy.pool.waitForInitialAttempts(5000);
});
