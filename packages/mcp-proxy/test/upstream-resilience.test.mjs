// Tests for upstream resilience: the proxy serves its built-in tools whatever
// state the upstreams are in, discovers late upstreams, and retries failed
// ones with a doubling delay until the retry limit.
// Drives runProxyServer with the SDK Client over an in-memory transport,
// against real mock upstream subprocesses.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";

import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

const BUILT_INS = ["omnodex_status", "omnodex_connect", "omnodex_connection_status"];

// Keeps retries out of tests that are not about retrying.
const NO_RETRY = { retry_initial_delay_ms: 600000, retry_give_up_delay_ms: 6000000 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockUpstream(name, env = {}) {
  return {
    name,
    transport: "stdio",
    command: process.execPath,
    args: [MOCK_SERVER],
    env: { MOCK_TOOLS: JSON.stringify(["ping"]), MOCK_RESULT_TEXT: name, ...env },
  };
}

function makeConfig(upstreams, connection = {}) {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: upstreams,
    upstream_connection: connection,
  });
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

/** Starts the pool and proxy server the way MCPProxy does, plus a client. */
async function startProxy(config) {
  const pool = new UpstreamClientPool();
  pool.start(config);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const serverDone = runProxyServer({
    pool,
    config,
    emit: () => undefined,
    sessionId: "sess-resilience-test",
    projectPath: "/home/case/project",
    transport: serverTransport,
  });

  const client = new Client({ name: "resilience-test-client", version: "0.0.0" }, {});
  let listChanged = 0;
  client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    listChanged += 1;
  });
  await client.connect(clientTransport);

  return {
    client,
    pool,
    listChangedCount: () => listChanged,
    async toolNames() {
      const { tools } = await client.listTools();
      return tools.map((t) => t.name);
    },
    async status(args = {}) {
      const result = await client.callTool({ name: "omnodex_status", arguments: args });
      return JSON.parse(result.content[0].text);
    },
    async stop() {
      await client.close();
      await serverDone;
      await pool.close();
    },
  };
}

// ---------------------------------------------------------------------------
// Zero upstreams
// ---------------------------------------------------------------------------

test("with zero upstreams the proxy serves its built-in tools", async () => {
  const proxy = await startProxy(makeConfig([]));
  try {
    assert.deepEqual(await proxy.toolNames(), BUILT_INS);
    const status = await proxy.status();
    assert.deepEqual(status.upstream_servers, []);
    assert.equal(status.tool_count, 0);
  } finally {
    await proxy.stop();
  }
});

// ---------------------------------------------------------------------------
// One failing plus one healthy upstream
// ---------------------------------------------------------------------------

test("a failing upstream does not affect a healthy one or the built-ins", async () => {
  const config = makeConfig(
    [mockUpstream("good"), mockUpstream("bad", { MOCK_FAIL_STARTUP: "1" })],
    { discovery_window_ms: 20000, ...NO_RETRY }
  );
  const proxy = await startProxy(config);
  try {
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "good__ping"]);

    const good = await proxy.client.callTool({ name: "good__ping", arguments: {} });
    assert.equal(good.isError, false);
    assert.equal(good.content[0].text, "good:ping:");

    const bad = await proxy.client.callTool({ name: "bad__ping", arguments: {} });
    assert.equal(bad.isError, true);
    assert.match(bad.content[0].text, /"bad" is not connected/);
    assert.match(bad.content[0].text, /Retrying in/);
    assert.doesNotMatch(bad.content[0].text, /not found/i);

    const status = await proxy.status();
    const byName = Object.fromEntries(status.upstream_servers.map((u) => [u.name, u]));
    assert.equal(byName.good.state, "connected");
    assert.equal(byName.good.tool_count, 1);
    assert.equal(byName.good.last_error, null);
    assert.ok(byName.good.last_attempt_at);
    assert.equal(byName.bad.state, "failed");
    assert.equal(byName.bad.tool_count, 0);
    assert.ok(byName.bad.last_error, "failed upstream should report its error");
    assert.ok(byName.bad.last_attempt_at);
    assert.equal(byName.bad.failed_attempts, 1);
    assert.ok(byName.bad.next_retry_at);
    assert.equal(byName.bad.retries_exhausted, false);

    const retry = await proxy.status({ retry_failed: true });
    assert.deepEqual(retry.retried, ["bad"]);
  } finally {
    await proxy.stop();
  }
});

// ---------------------------------------------------------------------------
// Discovery window
// ---------------------------------------------------------------------------

test("an upstream that connects inside the discovery window is in the first tools/list", async () => {
  const config = makeConfig([mockUpstream("slow", { MOCK_STARTUP_DELAY_MS: "500" })], {
    discovery_window_ms: 20000,
    ...NO_RETRY,
  });
  const proxy = await startProxy(config);
  try {
    // The client is already initialized while the upstream is still starting.
    assert.equal(proxy.pool.getUpstreamStatuses()[0].state, "connecting");
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "slow__ping"]);
  } finally {
    await proxy.stop();
  }
});

test("an upstream slower than the discovery window is announced with list_changed", async () => {
  const config = makeConfig([mockUpstream("slow", { MOCK_STARTUP_DELAY_MS: "3000" })], {
    discovery_window_ms: 200,
    ...NO_RETRY,
  });
  const proxy = await startProxy(config);
  try {
    const started = Date.now();
    assert.deepEqual(await proxy.toolNames(), BUILT_INS);
    assert.ok(Date.now() - started < 2500, "first tools/list should return at the window");

    const early = await proxy.client.callTool({ name: "slow__ping", arguments: {} });
    assert.equal(early.isError, true);
    assert.match(early.content[0].text, /still connecting/);

    await waitFor(() => proxy.listChangedCount() > 0, 20000, "tools/list_changed");
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "slow__ping"]);
    const late = await proxy.client.callTool({ name: "slow__ping", arguments: {} });
    assert.equal(late.isError, false);
  } finally {
    await proxy.stop();
  }
});

// ---------------------------------------------------------------------------
// Upstream dies after connecting
// ---------------------------------------------------------------------------

test("an upstream that dies after connecting is removed, reported and scheduled for retry", async () => {
  const config = makeConfig([mockUpstream("crashy", { MOCK_EXIT_AFTER_MS: "1500" })], {
    discovery_window_ms: 20000,
    ...NO_RETRY,
  });
  const proxy = await startProxy(config);
  try {
    assert.deepEqual(await proxy.toolNames(), [...BUILT_INS, "crashy__ping"]);

    // One notification when it connected (the client was already
    // initialized), one when it went away.
    await waitFor(() => proxy.listChangedCount() >= 2, 20000, "tools/list_changed on disconnect");
    assert.deepEqual(await proxy.toolNames(), BUILT_INS);

    const [upstream] = (await proxy.status()).upstream_servers;
    assert.equal(upstream.state, "failed");
    assert.equal(upstream.last_error, "upstream connection closed");
    assert.ok(upstream.next_retry_at);

    const call = await proxy.client.callTool({ name: "crashy__ping", arguments: {} });
    assert.equal(call.isError, true);
    assert.match(call.content[0].text, /"crashy" is not connected/);
  } finally {
    await proxy.stop();
  }
});

// ---------------------------------------------------------------------------
// Timeouts and retries (pool level)
// ---------------------------------------------------------------------------

test("an upstream that does not finish connecting within the timeout is marked failed", async () => {
  const pool = new UpstreamClientPool();
  try {
    await pool.connect(
      makeConfig([mockUpstream("stuck", { MOCK_STARTUP_DELAY_MS: "10000" })], {
        connect_timeout_ms: 300,
        ...NO_RETRY,
      })
    );
    const [upstream] = pool.getUpstreamStatuses();
    assert.equal(upstream.state, "failed");
    assert.match(upstream.last_error, /timed out/i);
  } finally {
    await pool.close();
  }
});

test("retries double and stop once the next delay reaches the give-up delay", async () => {
  const pool = new UpstreamClientPool();
  const exhausted = [];
  pool.onRetriesExhausted((status) => exhausted.push(status));
  try {
    const started = Date.now();
    pool.start(
      makeConfig(
        [{ name: "missing", transport: "stdio", command: "omnodex-test-no-such-command" }],
        // Delays 20, 40, 80 ms; the fourth failure would wait 160 ms, so it stops.
        { retry_initial_delay_ms: 20, retry_give_up_delay_ms: 150 }
      )
    );
    await waitFor(() => exhausted.length === 1, 10000, "retries to stop");
    // 20 + 40 + 80 ms, less a little timer granularity.
    assert.ok(Date.now() - started >= 120, "retries should wait out the doubling delays");

    const [upstream] = pool.getUpstreamStatuses();
    assert.equal(upstream.state, "failed");
    assert.equal(upstream.failed_attempts, 4);
    assert.equal(upstream.retries_exhausted, true);
    assert.equal(upstream.next_retry_at, null);
    assert.deepEqual(exhausted[0], upstream);

    await assert.rejects(
      () => pool.callTool("missing__anything", {}),
      (err) => {
        assert.equal(err.name, "McpUpstreamUnavailableError");
        assert.match(err.message, /retries have stopped after 4 failed attempts/);
        assert.match(err.message, /retry_failed: true/);
        return true;
      }
    );

    // A manual retry starts over with a fresh count and stops again.
    assert.deepEqual(pool.retryFailed(), ["missing"]);
    await waitFor(() => exhausted.length === 2, 10000, "retries to stop again");
    assert.equal(pool.getUpstreamStatuses()[0].failed_attempts, 4);
  } finally {
    await pool.close();
  }
});

test("an upstream that crashes right after connecting still reaches the retry limit", async () => {
  const pool = new UpstreamClientPool();
  const exhausted = [];
  pool.onRetriesExhausted((status) => exhausted.push(status));
  try {
    pool.start(
      makeConfig([mockUpstream("flappy", { MOCK_EXIT_AFTER_MS: "100" })], {
        retry_initial_delay_ms: 50,
        retry_give_up_delay_ms: 150,
      })
    );
    await waitFor(() => exhausted.length === 1, 60000, "retries to stop");
    const [upstream] = pool.getUpstreamStatuses();
    assert.equal(upstream.failed_attempts, 3);
    assert.equal(upstream.last_error, "upstream connection closed");
  } finally {
    await pool.close();
  }
});
