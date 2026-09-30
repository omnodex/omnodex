// Tests for the upstream tool cache: an upstream's tools are remembered
// between runs and listed at once on the next run, even when the upstream
// starts slower than the discovery window, and a call to one waits for it.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";
import { createToolListCache, upstreamCacheKey } from "../dist/tool-cache.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

const BUILT_INS = ["omnodex_status", "omnodex_connect", "omnodex_connection_status"];
const NO_RETRY = { retry_initial_delay_ms: 600000, retry_give_up_delay_ms: 6000000 };

function mockUpstream(name, env = {}) {
  return {
    name,
    transport: "stdio",
    command: process.execPath,
    args: [MOCK_SERVER],
    env: { MOCK_TOOLS: JSON.stringify(["ping", "pong"]), MOCK_RESULT_TEXT: name, ...env },
  };
}

function makeConfig(upstreams, connection = {}) {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: upstreams,
    upstream_connection: { ...NO_RETRY, ...connection },
  });
}

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-tool-cache-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function startProxy(config, toolCache) {
  const pool = new UpstreamClientPool({ toolCache });
  pool.start(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const serverDone = runProxyServer({
    pool,
    config,
    emit: () => undefined,
    sessionId: "sess-tool-cache-test",
    projectPath: "/home/case/project",
    transport: serverTransport,
  });
  const client = new Client({ name: "tool-cache-test-client", version: "0.0.0" }, {});
  await client.connect(clientTransport);
  return {
    client,
    pool,
    async toolNames() {
      const { tools } = await client.listTools();
      return tools.map((t) => t.name);
    },
    async stop() {
      await client.close();
      await serverDone;
      await pool.close();
    },
  };
}

// ---------------------------------------------------------------------------
// The cache file store
// ---------------------------------------------------------------------------

test("a saved tool list loads back for the same upstream entry only", (t) => {
  const cache = createToolListCache(path.join(tempDir(t), "nested"));
  const server = mockUpstream("fs");
  const tools = [{ name: "read", description: "Reads", inputSchema: { type: "object" } }];

  assert.equal(cache.load(server), undefined);
  cache.save(server, tools);
  assert.deepEqual(cache.load(server), tools);

  // Any change to the entry is a different upstream as far as the cache goes.
  assert.equal(cache.load({ ...server, args: [...server.args, "--other"] }), undefined);
  assert.notEqual(upstreamCacheKey(server), upstreamCacheKey({ ...server, name: "fs2" }));
});

test("an unreadable or malformed cache file is ignored", (t) => {
  const dir = tempDir(t);
  const cache = createToolListCache(dir);
  const server = mockUpstream("fs");
  const file = path.join(dir, `${upstreamCacheKey(server)}.json`);

  fs.writeFileSync(file, "{ not json");
  assert.equal(cache.load(server), undefined);
  fs.writeFileSync(file, JSON.stringify({ version: 2, tools: [] }));
  assert.equal(cache.load(server), undefined);
  fs.writeFileSync(
    file,
    JSON.stringify({ version: 1, tools: [{ name: "ok", inputSchema: { type: "object" } }, { bad: 1 }] })
  );
  assert.deepEqual(cache.load(server).map((t) => t.name), ["ok"]);
});

test("the cache stores tool definitions, not the upstream's environment", async (t) => {
  const dir = tempDir(t);
  const server = mockUpstream("secretive", { API_KEY: "sk-test-do-not-store" });
  const pool = new UpstreamClientPool({ toolCache: createToolListCache(dir) });
  try {
    await pool.connect(makeConfig([server]));
    const [file] = fs.readdirSync(dir);
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    assert.doesNotMatch(text, /sk-test-do-not-store/);
    assert.deepEqual(JSON.parse(text).tools.map((t) => t.name), ["ping", "pong"]);
  } finally {
    await pool.close();
  }
});

// ---------------------------------------------------------------------------
// Through the proxy
// ---------------------------------------------------------------------------

test("a slow upstream seen on an earlier run is listed at once and its calls wait for it", async (t) => {
  const cache = createToolListCache(tempDir(t));
  const slow = mockUpstream("slow", { MOCK_STARTUP_DELAY_MS: "1500" });

  // Earlier run: the upstream connects and its tools are remembered.
  const first = new UpstreamClientPool({ toolCache: cache });
  await first.connect(makeConfig([slow]));
  assert.equal(first.getUpstreamStatuses()[0].state, "connected");
  await first.close();

  // This run: the discovery window is far shorter than the upstream's start.
  const proxy = await startProxy(makeConfig([slow], { discovery_window_ms: 100 }), cache);
  try {
    const started = Date.now();
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "slow__ping", "slow__pong"]);
    assert.ok(Date.now() - started < 1000, "a cached upstream should not hold up tools/list");
    assert.equal(proxy.pool.getUpstreamStatuses()[0].state, "connecting");

    const call = await proxy.client.callTool({ name: "slow__pong", arguments: {} });
    assert.equal(call.isError, false);
    assert.equal(call.content[0].text, "slow:pong:");
  } finally {
    await proxy.stop();
  }
});

test("without a cached list the first tools/list still waits for the upstream", async (t) => {
  const cache = createToolListCache(tempDir(t));
  const proxy = await startProxy(
    makeConfig([mockUpstream("fresh", { MOCK_STARTUP_DELAY_MS: "500" })], { discovery_window_ms: 20000 }),
    cache
  );
  try {
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "fresh__ping", "fresh__pong"]);
  } finally {
    await proxy.stop();
  }
});

test("a cached upstream that fails to start is listed and its calls say why", async (t) => {
  const dir = tempDir(t);
  const cache = createToolListCache(dir);
  const broken = mockUpstream("broken", { MOCK_FAIL_STARTUP: "1" });
  cache.save(broken, [{ name: "ping", inputSchema: { type: "object" } }]);

  const proxy = await startProxy(makeConfig([broken], { discovery_window_ms: 20000 }), cache);
  try {
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "broken__ping"]);
    const call = await proxy.client.callTool({ name: "broken__ping", arguments: {} });
    assert.equal(call.isError, true);
    assert.match(call.content[0].text, /"broken" is not connected/);
    assert.doesNotMatch(call.content[0].text, /not found/i);
  } finally {
    await proxy.stop();
  }
});

test("a changed tool list replaces the cached one", async (t) => {
  const cache = createToolListCache(tempDir(t));
  const server = mockUpstream("grows");
  cache.save(server, [{ name: "old", inputSchema: { type: "object" } }]);

  const pool = new UpstreamClientPool({ toolCache: cache });
  try {
    await pool.connect(makeConfig([server]));
    assert.deepEqual(cache.load(server).map((t) => t.name), ["ping", "pong"]);
    assert.deepEqual(pool.getListedTools().map((t) => t.prefixedName), ["grows__ping", "grows__pong"]);
  } finally {
    await pool.close();
  }
});
