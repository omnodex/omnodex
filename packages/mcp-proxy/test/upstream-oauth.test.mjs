// Tests for OAuth sign-in to remote upstreams: the token store, the sign-in
// flow (discovery, PKCE S256, resource indicator, registration and client ID
// metadata documents), refresh before and after expiry, the needs_auth state,
// the omnodex_auth tool, and that no token reaches status or event output.
// Runs against a local OAuth and MCP test server.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema, oauthSettings } from "../dist/config.js";
import { FileTokenStore, MemoryTokenStore } from "../dist/auth/token-store.js";
import { beginSignIn } from "../dist/auth/sign-in.js";
import { startOAuthMcpServer } from "./helpers/oauth-mcp-server.mjs";

const NO_RETRY = { retry_initial_delay_ms: 600000, retry_give_up_delay_ms: 6000000 };

function configFor(url, extra = {}) {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [{ name: "remote", transport: "http", url, ...extra }],
    upstream_connection: NO_RETRY,
  });
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function startProxy(config, store) {
  const pool = new UpstreamClientPool({ tokenStore: store });
  pool.start(config);
  const events = [];
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const serverDone = runProxyServer({
    pool,
    config,
    emit: (e) => void events.push(e),
    sessionId: "sess-oauth-test",
    projectPath: "/home/case/project",
    transport: serverTransport,
  });
  const client = new Client({ name: "oauth-test-client", version: "0.0.0" }, {});
  await client.connect(clientTransport);
  const call = async (name, args = {}) => {
    const result = await client.callTool({ name, arguments: args });
    return { ...result, json: result.content?.[0]?.text?.startsWith("{") ? JSON.parse(result.content[0].text) : undefined };
  };
  return {
    client,
    pool,
    events,
    call,
    state: async () => (await call("omnodex_status")).json.upstream_servers[0].state,
    async stop() {
      await client.close();
      await serverDone;
      await pool.close();
    },
  };
}

/** Signs in the way a user would: through omnodex_auth, then the browser. */
async function signInThroughTool(proxy, server) {
  await waitFor(async () => (await proxy.state()) === "needs_auth", 5000, "needs_auth");
  const result = await proxy.call("omnodex_auth", { upstream: "remote" });
  assert.equal(result.json.status, "sign_in_url");
  assert.equal(await server.approve(result.json.url), 200);
  await waitFor(async () => (await proxy.state()) === "connected", 10000, "connected");
  return result.json;
}

test("token store: file is private, keyed by upstream and url", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-tokens-"));
  const file = path.join(dir, "nested", "upstream-tokens.json");
  const store = new FileTokenStore(file);
  assert.equal(await store.get("a", "https://x.example/mcp"), undefined);
  await store.put("a", { url: "https://x.example/mcp", tokens: { access_token: "t", token_type: "Bearer", obtained_at: 1 } });
  if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal((await store.get("a", "https://x.example/mcp")).tokens.access_token, "t");
  // A changed URL never gets the old tokens.
  assert.equal(await store.get("a", "https://other.example/mcp"), undefined);
  assert.deepEqual(Object.keys(await store.list()), ["a"]);
  assert.equal(await store.delete("a"), true);
  assert.equal(await store.delete("a"), false);
  fs.writeFileSync(file, "not json");
  assert.deepEqual(await store.list(), {});
  fs.rmSync(dir, { recursive: true, force: true });
});

test("oauth settings: on unless a token or Authorization header is configured", () => {
  const base = { name: "r", transport: "http", url: "https://x.example/mcp" };
  const parse = (extra) => ProxyConfigSchema.parse({ version: 1, upstream_servers: [{ ...base, ...extra }] }).upstream_servers[0];
  assert.deepEqual(oauthSettings(parse({})), {});
  assert.equal(oauthSettings(parse({ bearer_token_env_var: "TOKEN_VAR" })), undefined);
  assert.equal(oauthSettings(parse({ http_headers: { authorization: "x" } })), undefined);
  assert.equal(oauthSettings(parse({ oauth: false })), undefined);
  assert.deepEqual(oauthSettings(parse({ oauth: { scope: "read" } })), { scope: "read" });
});

test("sign-in: PKCE S256, resource indicator, registration, tokens stored", async () => {
  const server = await startOAuthMcpServer();
  const store = new MemoryTokenStore();
  try {
    const session = await beginSignIn({ upstreamName: "remote", serverUrl: server.url, store, callbackPort: 0 });
    const url = new URL(session.authorizationUrl);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("resource"), server.url);
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.ok(url.searchParams.get("state"));
    assert.equal(server.registrations.length, 1);
    assert.equal(server.registrations[0].token_endpoint_auth_method, "none");
    assert.equal(await server.approve(session.authorizationUrl), 200);
    await session.completed;
    const record = await store.get("remote", server.url);
    assert.ok(record.tokens.access_token);
    assert.ok(record.tokens.refresh_token);
    assert.equal(server.tokenRequests[0].resource, server.url);
  } finally {
    await server.close();
  }
});

test("sign-in: a callback with the wrong state is refused", async () => {
  const server = await startOAuthMcpServer();
  const store = new MemoryTokenStore();
  try {
    const session = await beginSignIn({ upstreamName: "remote", serverUrl: server.url, store, callbackPort: 0 });
    const redirect = new URL(new URL(session.authorizationUrl).searchParams.get("redirect_uri"));
    redirect.searchParams.set("code", "forged");
    redirect.searchParams.set("state", "wrong");
    assert.equal((await fetch(redirect)).status, 400);
    session.cancel();
    await assert.rejects(session.completed);
    assert.equal((await store.get("remote", server.url))?.tokens, undefined);
  } finally {
    await server.close();
  }
});

test("sign-in: uses a client ID metadata document when the server supports it", async () => {
  const server = await startOAuthMcpServer({ cimd: true });
  const store = new MemoryTokenStore();
  const metadataUrl = "https://omnodex.example/oauth/omnodex-client.json";
  try {
    const session = await beginSignIn({
      upstreamName: "remote",
      serverUrl: server.url,
      store,
      callbackPort: 0,
      clientMetadataUrl: metadataUrl,
    });
    assert.equal(server.registrations.length, 0);
    assert.equal(new URL(session.authorizationUrl).searchParams.get("client_id"), metadataUrl);
    assert.equal(await server.approve(session.authorizationUrl), 200);
    await session.completed;
  } finally {
    await server.close();
  }
});

test("omnodex_auth: needs_auth upstream gets a URL, then connects without a restart", async () => {
  const server = await startOAuthMcpServer();
  const store = new MemoryTokenStore();
  const proxy = await startProxy(configFor(server.url, { oauth: { callback_port: 47999 } }), store);
  try {
    const signedIn = await signInThroughTool(proxy, server);
    // The same call while connected makes no new sign-in.
    const again = await proxy.call("omnodex_auth", { upstream: "remote" });
    assert.equal(again.json.status, "already_connected");
    const echoed = await proxy.call("remote__echo", { text: "hello" });
    assert.equal(echoed.content[0].text, "hello");

    // No token anywhere the agent or the log can see.
    const record = await store.get("remote", server.url);
    const secrets = [record.tokens.access_token, record.tokens.refresh_token];
    const seen = JSON.stringify([
      (await proxy.call("omnodex_status")).content,
      signedIn,
      again.json,
      echoed.content,
      proxy.events,
    ]);
    for (const secret of secrets) assert.equal(seen.includes(secret), false);
  } finally {
    await proxy.stop();
    await server.close();
  }
});

test("omnodex_auth: with no upstream named it picks the one that needs sign-in", async () => {
  const server = await startOAuthMcpServer();
  const proxy = await startProxy(configFor(server.url), new MemoryTokenStore());
  try {
    await waitFor(async () => (await proxy.state()) === "needs_auth", 5000, "needs_auth");
    const result = await proxy.call("omnodex_auth");
    assert.equal(result.json.status, "sign_in_url");
    assert.equal(result.json.upstream, "remote");
    const missing = await proxy.call("omnodex_auth", { upstream: "nope" });
    assert.equal(missing.json.status, "unknown_upstream");
    assert.equal(missing.isError, true);
  } finally {
    await proxy.stop();
    await server.close();
  }
});

test("restart: stored sign-in connects with no prompt", async () => {
  const server = await startOAuthMcpServer();
  const store = new MemoryTokenStore();
  const first = await startProxy(configFor(server.url), store);
  try {
    await signInThroughTool(first, server);
  } finally {
    await first.stop();
  }
  const second = await startProxy(configFor(server.url), store);
  try {
    await waitFor(async () => (await second.state()) === "connected", 10000, "connected after restart");
  } finally {
    await second.stop();
    await server.close();
  }
});

test("refresh: a token near expiry is refreshed before the call, and the refresh token rotates", async () => {
  const server = await startOAuthMcpServer({ expiresIn: 30 }); // inside the refresh margin
  const store = new MemoryTokenStore();
  const proxy = await startProxy(configFor(server.url), store);
  try {
    await signInThroughTool(proxy, server);
    const before = (await store.get("remote", server.url)).tokens;
    const refreshesBefore = server.tokenRequests.filter((r) => r.grant_type === "refresh_token").length;
    const echoed = await proxy.call("remote__echo", { text: "after refresh" });
    assert.equal(echoed.content[0].text, "after refresh");
    const after = (await store.get("remote", server.url)).tokens;
    assert.notEqual(after.access_token, before.access_token);
    assert.notEqual(after.refresh_token, before.refresh_token);
    assert.ok(server.tokenRequests.filter((r) => r.grant_type === "refresh_token").length > refreshesBefore);
  } finally {
    await proxy.stop();
    await server.close();
  }
});

test("refresh: a 401 on a live connection refreshes and retries once", async () => {
  const server = await startOAuthMcpServer();
  const store = new MemoryTokenStore();
  const proxy = await startProxy(configFor(server.url), store);
  try {
    await signInThroughTool(proxy, server);
    // The server forgets the access token (not the refresh token) and its session.
    server.revokeAccess();
    server.mcp.dropSessions();
    const echoed = await proxy.call("remote__echo", { text: "recovered" });
    assert.equal(echoed.content[0].text, "recovered");
    assert.equal(await proxy.state(), "connected");
  } finally {
    await proxy.stop();
    await server.close();
  }
});

test("refresh: a refresh the server rejects moves the upstream to needs_auth", async () => {
  const server = await startOAuthMcpServer({ expiresIn: 30 });
  const store = new MemoryTokenStore();
  const proxy = await startProxy(configFor(server.url), store);
  try {
    await signInThroughTool(proxy, server);
    server.revokeRefresh();
    const result = await proxy.call("remote__echo", { text: "x" });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /needs authorization/);
    assert.match(result.content[0].text, /omnodex_auth/);
    assert.equal(await proxy.state(), "needs_auth");
  } finally {
    await proxy.stop();
    await server.close();
  }
});

test("oauth: false leaves a 401 as a plain needs_auth with no sign-in offered", async () => {
  const server = await startOAuthMcpServer();
  const proxy = await startProxy(configFor(server.url, { oauth: false }), new MemoryTokenStore());
  try {
    await waitFor(async () => (await proxy.state()) === "needs_auth", 5000, "needs_auth");
    const result = await proxy.call("omnodex_auth", { upstream: "remote" });
    assert.equal(result.json.status, "not_oauth");
    assert.equal(server.registrations.length, 0);
  } finally {
    await proxy.stop();
    await server.close();
  }
});
