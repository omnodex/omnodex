// Tests for remote upstreams over Streamable HTTP: headers and bearer tokens
// from the environment, the needs_auth state, session loss, per-call
// timeouts and cancellation, and that no credential reaches status, stderr
// text or the event log.
// Drives runProxyServer with the SDK Client over an in-memory transport,
// against an in-process Streamable HTTP MCP server.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";
import { startHttpMcpServer } from "./helpers/http-mcp-server.mjs";

const TOKEN = "tok-case-0123456789abcdef";
const TOKEN_VAR = "OMNODEX_TEST_HTTP_TOKEN";
const HEADER_VAR = "OMNODEX_TEST_HTTP_WORKSPACE";
const UNSET_VAR = "OMNODEX_TEST_HTTP_UNSET";
const NO_RETRY = { retry_initial_delay_ms: 600000, retry_give_up_delay_ms: 6000000 };

process.env[TOKEN_VAR] = TOKEN;
process.env[HEADER_VAR] = "ws-case-secret-value";
delete process.env[UNSET_VAR];

function httpUpstream(url, extra = {}) {
  return { name: "remote", transport: "http", url, bearer_token_env_var: TOKEN_VAR, ...extra };
}

function makeConfig(upstreams) {
  return ProxyConfigSchema.parse({ version: 1, upstream_servers: upstreams, upstream_connection: NO_RETRY });
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function startProxy(config) {
  const pool = new UpstreamClientPool();
  pool.start(config);
  const events = [];
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const serverDone = runProxyServer({
    pool,
    config,
    emit: (e) => {
      events.push(e);
    },
    sessionId: "sess-http-test",
    projectPath: "/home/case/project",
    transport: serverTransport,
  });
  const client = new Client({ name: "http-test-client", version: "0.0.0" }, {});
  await client.connect(clientTransport);
  return {
    client,
    pool,
    events,
    async status(args = {}) {
      const result = await client.callTool({ name: "omnodex_status", arguments: args });
      return JSON.parse(result.content[0].text);
    },
    async upstream(args) {
      return (await this.status(args)).upstream_servers[0];
    },
    async stop() {
      await client.close();
      await serverDone;
      await pool.close();
    },
  };
}

function assertNoSecrets(value, label) {
  const text = JSON.stringify(value);
  for (const secret of [TOKEN, process.env[HEADER_VAR]]) {
    assert.ok(!text.includes(secret), `${label} contains a credential`);
  }
}

// ---------------------------------------------------------------------------

test("an http upstream connects with a bearer token and its tools are callable", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url)]));
  try {
    const { tools } = await proxy.client.listTools();
    assert.ok(tools.some((t) => t.name === "remote__echo"));
    const result = await proxy.client.callTool({ name: "remote__echo", arguments: { text: "hi case" } });
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text, "hi case");

    const status = await proxy.upstream();
    assert.equal(status.state, "connected");
    assert.equal(status.transport, "http");
    assertNoSecrets(status, "status");
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("static and env headers are sent, unset env headers are skipped, and the bearer token wins over an Authorization header", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(
    makeConfig([
      httpUpstream(upstream.url, {
        http_headers: { "X-Workspace-Slug": "case", authorization: "Bearer from-static-header" },
        env_http_headers: { "X-Workspace-Key": HEADER_VAR, "X-Missing": UNSET_VAR, Authorization: HEADER_VAR },
      }),
    ])
  );
  try {
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected");
    const post = upstream.requests.find((r) => r.method === "POST");
    assert.equal(post.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(post.headers["x-workspace-slug"], "case");
    assert.equal(post.headers["x-workspace-key"], process.env[HEADER_VAR]);
    assert.equal(post.headers["x-missing"], undefined);
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("an unset bearer_token_env_var fails the upstream with a message naming the variable", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url, { bearer_token_env_var: UNSET_VAR })]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "failed", 5000, "failed");
    const status = await proxy.upstream();
    assert.match(status.last_error, new RegExp(`${UNSET_VAR} \\(bearer_token_env_var\\) is not set`));
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("a 401 puts the upstream in needs_auth without retrying, scrubs the echoed credential, and retry_failed recovers", async () => {
  const upstream = await startHttpMcpServer({ token: "some-other-token" });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url)]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "needs_auth", 5000, "needs_auth");
    const status = await proxy.upstream();
    assert.equal(status.next_retry_at, null);
    assert.match(status.last_error, /401/);
    assert.match(status.last_error, /\[REDACTED\]/);
    assertNoSecrets(status, "needs_auth status");

    const call = await proxy.client.callTool({ name: "remote__echo", arguments: { text: "x" } });
    assert.equal(call.isError, true);
    assert.match(call.content[0].text, /needs authorization/);

    upstream.setToken(TOKEN);
    const retried = await proxy.status({ retry_failed: true });
    assert.deepEqual(retried.retried, ["remote"]);
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected after retry");
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("a 401 during a call moves a connected upstream to needs_auth and removes its tools", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url)]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected");
    upstream.setToken("rotated-token");
    const call = await proxy.client.callTool({ name: "remote__echo", arguments: { text: "x" } });
    assert.equal(call.isError, true);
    assert.match(call.content[0].text, /needs authorization/);
    const status = await proxy.upstream();
    assert.equal(status.state, "needs_auth");
    assert.equal(status.tool_count, 0);
    assertNoSecrets(proxy.events, "events");
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("when the server forgets the session, the proxy starts a new one and the call succeeds", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url)]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected");
    upstream.dropSessions();
    const result = await proxy.client.callTool({ name: "remote__echo", arguments: { text: "again" } });
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text, "again");
    assert.equal((await proxy.upstream()).state, "connected");
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("tool_timeout_sec bounds a slow call", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url, { tool_timeout_sec: 0.3 })]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected");
    const started = Date.now();
    const result = await proxy.client.callTool({ name: "remote__slow", arguments: { ms: 5000, id: "t1" } });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /timed out/i);
    assert.ok(Date.now() - started < 3000);
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("cancelling a call at the agent cancels it at the upstream", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const proxy = await startProxy(makeConfig([httpUpstream(upstream.url)]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected");
    const controller = new AbortController();
    const call = proxy.client.callTool({ name: "remote__slow", arguments: { ms: 10000, id: "c1" } }, undefined, {
      signal: controller.signal,
    });
    await new Promise((r) => setTimeout(r, 300));
    controller.abort();
    await assert.rejects(call);
    await waitFor(() => upstream.aborted.includes("c1"), 5000, "upstream abort");
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("session.started records transport and host only, and no event carries a credential or query string", async () => {
  const upstream = await startHttpMcpServer({ token: TOKEN });
  const url = `${upstream.url}?api_key=case-query-secret`;
  const proxy = await startProxy(
    makeConfig([httpUpstream(url, { env_http_headers: { "X-Workspace-Key": HEADER_VAR } })])
  );
  try {
    await waitFor(async () => (await proxy.upstream()).state === "connected", 5000, "connected");
    await proxy.client.callTool({ name: "remote__echo", arguments: { text: "logged" } });
    const started = proxy.events.find((e) => e.event_type === "session.started");
    assert.deepEqual(started.mcp_server_transports, [
      { name: "remote", transport: "http", host: new URL(upstream.url).host },
    ]);
    assertNoSecrets(proxy.events, "events");
    assert.ok(!JSON.stringify(proxy.events).includes("case-query-secret"));
  } finally {
    await proxy.stop();
    await upstream.close();
  }
});

test("errors that echo the url have the query string removed", async () => {
  // Nothing listens on this port, so the connection error names the URL.
  const url = "http://127.0.0.1:9/mcp?api_key=case-query-secret";
  const proxy = await startProxy(makeConfig([httpUpstream(url)]));
  try {
    await waitFor(async () => (await proxy.upstream()).state === "failed", 5000, "failed");
    const status = await proxy.upstream();
    assert.ok(!status.last_error.includes("case-query-secret"));
  } finally {
    await proxy.stop();
  }
});
