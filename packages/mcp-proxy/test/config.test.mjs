// Unit tests for config.ts -- schema validation, env interpolation, helpers.
// Runs against dist/; build the package before running.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import {
  ProxyConfigSchema,
  resolveUpstreamEnv,
  shouldRedactParams,
  toolNamePrefix,
  loadProxyConfig,
  resolveHttpHeaders,
  redactSecrets,
} from "../dist/config.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function withTmpDir(t, fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-proxy-config-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return fn(dir);
}

const MINIMAL_STDIO = {
  version: 1,
  upstream_servers: [
    { name: "fs", transport: "stdio", command: "node", args: ["server.js"] },
  ],
};

// ---------------------------------------------------------------------------
// ProxyConfigSchema
// ---------------------------------------------------------------------------

test("parses a minimal stdio upstream config", () => {
  const result = ProxyConfigSchema.safeParse(MINIMAL_STDIO);
  assert.ok(result.success, result.error?.message);
  const cfg = result.data;
  assert.equal(cfg.version, 1);
  assert.equal(cfg.redact_parameters, false); // default
  assert.equal(cfg.upstream_servers.length, 1);
  assert.equal(cfg.upstream_servers[0].name, "fs");
  assert.equal(cfg.upstream_servers[0].transport, "stdio");
});

test("defaults redact_parameters to false", () => {
  const result = ProxyConfigSchema.safeParse(MINIMAL_STDIO);
  assert.ok(result.success);
  assert.equal(result.data.redact_parameters, false);
});

test("accepts explicit redact_parameters: true", () => {
  const result = ProxyConfigSchema.safeParse({
    ...MINIMAL_STDIO,
    redact_parameters: true,
  });
  assert.ok(result.success);
  assert.equal(result.data.redact_parameters, true);
});

test("accepts an http upstream", () => {
  const result = ProxyConfigSchema.safeParse({
    version: 1,
    upstream_servers: [
      { name: "remote", transport: "http", url: "https://example.com/mcp" },
    ],
  });
  assert.ok(result.success, result.error?.message);
  assert.equal(result.data.upstream_servers[0].transport, "http");
});

test("accepts Codex-style credential keys on an http upstream", () => {
  const result = ProxyConfigSchema.safeParse({
    version: 1,
    upstream_servers: [
      {
        name: "plane",
        transport: "http",
        url: "https://mcp.example.com/mcp",
        bearer_token_env_var: "PLANE_API_KEY",
        http_headers: { "x-workspace-slug": "case" },
        env_http_headers: { "x-api-key": "SOME_ENV_VAR" },
        tool_timeout_sec: 30,
      },
    ],
  });
  assert.ok(result.success, result.error?.message);
});

test("rejects bad http upstream fields", () => {
  const base = { name: "r", transport: "http", url: "https://example.com/mcp" };
  const bad = [
    { ...base, url: "ftp://example.com/mcp" },
    { ...base, bearer_token_env_var: "not a var" },
    { ...base, http_headers: { "bad header": "x" } },
    { ...base, env_http_headers: { "x-key": "$VAR" } },
    { ...base, tool_timeout_sec: 0 },
  ];
  for (const server of bad) {
    const result = ProxyConfigSchema.safeParse({ version: 1, upstream_servers: [server] });
    assert.equal(result.success, false, JSON.stringify(server));
  }
});

test("resolveHttpHeaders: static, env and bearer headers, with bearer precedence", () => {
  const server = {
    name: "r",
    transport: "http",
    url: "https://example.com/mcp",
    bearer_token_env_var: "TOKEN_VAR",
    http_headers: { "X-Static": "s", authorization: "Basic static" },
    env_http_headers: { "X-From-Env": "HEADER_VAR", "X-Unset": "UNSET_VAR", AUTHORIZATION: "HEADER_VAR" },
  };
  const { headers, secrets } = resolveHttpHeaders(server, { TOKEN_VAR: "tok123", HEADER_VAR: "hdr456" });
  assert.deepEqual(headers, { "X-Static": "s", Authorization: "Bearer tok123", "X-From-Env": "hdr456" });
  assert.deepEqual(secrets.sort(), ["hdr456", "hdr456", "tok123"].sort());
});

test("resolveHttpHeaders: an unset bearer variable throws and names only the variable", () => {
  const server = { name: "r", transport: "http", url: "https://example.com/mcp", bearer_token_env_var: "TOKEN_VAR" };
  assert.throws(() => resolveHttpHeaders(server, {}), /TOKEN_VAR \(bearer_token_env_var\) is not set/);
  assert.throws(() => resolveHttpHeaders(server, { TOKEN_VAR: "" }), /is not set/);
});

test("redactSecrets removes credential values and the url query string", () => {
  const msg = "failed https://h/mcp?key=abc123 with Bearer tok123 and tok123";
  assert.equal(
    redactSecrets(msg, ["tok123"], "https://h/mcp?key=abc123"),
    "failed https://h/mcp?[REDACTED] with Bearer [REDACTED] and [REDACTED]"
  );
  // Very short values are left alone rather than shredding ordinary text.
  assert.equal(redactSecrets("a b c", ["a"]), "a b c");
});

test("missing upstream_servers defaults to an empty list", () => {
  const result = ProxyConfigSchema.safeParse({ version: 1 });
  assert.ok(result.success);
  assert.deepEqual(result.data.upstream_servers, []);
});

test("accepts an empty upstream_servers array", () => {
  const result = ProxyConfigSchema.safeParse({ version: 1, upstream_servers: [] });
  assert.ok(result.success);
  assert.deepEqual(result.data.upstream_servers, []);
});

test("upstream_connection defaults apply when omitted", () => {
  const cfg = ProxyConfigSchema.parse(MINIMAL_STDIO);
  assert.deepEqual(cfg.upstream_connection, {
    discovery_window_ms: 15000,
    connect_timeout_ms: 30000,
    retry_initial_delay_ms: 1000,
    retry_give_up_delay_ms: 180000,
  });
});

test("upstream_connection keeps set values and fills the rest", () => {
  const cfg = ProxyConfigSchema.parse({
    ...MINIMAL_STDIO,
    upstream_connection: { discovery_window_ms: 0, retry_give_up_delay_ms: 60000 },
  });
  assert.equal(cfg.upstream_connection.discovery_window_ms, 0);
  assert.equal(cfg.upstream_connection.retry_give_up_delay_ms, 60000);
  assert.equal(cfg.upstream_connection.connect_timeout_ms, 30000);
});

test("rejects a non-positive connect timeout", () => {
  const result = ProxyConfigSchema.safeParse({
    ...MINIMAL_STDIO,
    upstream_connection: { connect_timeout_ms: 0 },
  });
  assert.ok(!result.success);
});

test("rejects wrong version number", () => {
  const result = ProxyConfigSchema.safeParse({ ...MINIMAL_STDIO, version: 2 });
  assert.ok(!result.success);
});

test("rejects stdio upstream missing command", () => {
  const result = ProxyConfigSchema.safeParse({
    version: 1,
    upstream_servers: [{ name: "fs", transport: "stdio" }],
  });
  assert.ok(!result.success);
});

test("accepts optional per-server fields (env, cwd, name_override, redact_parameters)", () => {
  const result = ProxyConfigSchema.safeParse({
    version: 1,
    upstream_servers: [
      {
        name: "fs",
        transport: "stdio",
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem"],
        env: { HOME: "/tmp" },
        cwd: "/tmp",
        name_override: "filesystem",
        redact_parameters: true,
      },
    ],
  });
  assert.ok(result.success, result.error?.message);
  const srv = result.data.upstream_servers[0];
  assert.equal(srv.name_override, "filesystem");
  assert.equal(srv.redact_parameters, true);
});

// ---------------------------------------------------------------------------
// resolveUpstreamEnv
// ---------------------------------------------------------------------------

test("resolveUpstreamEnv returns undefined for undefined input", () => {
  assert.equal(resolveUpstreamEnv(undefined), undefined);
});

test("resolveUpstreamEnv passes through literal values", () => {
  const result = resolveUpstreamEnv({ KEY: "value" });
  assert.deepEqual(result, { KEY: "value" });
});

test("resolveUpstreamEnv interpolates known env vars", () => {
  process.env.OMNODEX_TEST_VAR = "hello";
  const result = resolveUpstreamEnv({ KEY: "\${OMNODEX_TEST_VAR}" });
  assert.equal(result.KEY, "hello");
  delete process.env.OMNODEX_TEST_VAR;
});

test("resolveUpstreamEnv leaves unknown vars as-is", () => {
  const result = resolveUpstreamEnv({ KEY: "\${DEFINITELY_NOT_SET_XYZ}" });
  assert.equal(result.KEY, "\${DEFINITELY_NOT_SET_XYZ}");
});

test("resolveUpstreamEnv handles multiple vars in one value", () => {
  process.env.OMNODEX_A = "foo";
  process.env.OMNODEX_B = "bar";
  const result = resolveUpstreamEnv({ KEY: "\${OMNODEX_A}-\${OMNODEX_B}" });
  assert.equal(result.KEY, "foo-bar");
  delete process.env.OMNODEX_A;
  delete process.env.OMNODEX_B;
});

// ---------------------------------------------------------------------------
// shouldRedactParams
// ---------------------------------------------------------------------------

const BASE_CONFIG = ProxyConfigSchema.parse(MINIMAL_STDIO);
const FS_SERVER = BASE_CONFIG.upstream_servers[0];

test("shouldRedactParams uses global default (false) when no per-server override", () => {
  assert.equal(shouldRedactParams(FS_SERVER, BASE_CONFIG), false);
});

test("shouldRedactParams uses global true when set and no per-server override", () => {
  const cfg = ProxyConfigSchema.parse({ ...MINIMAL_STDIO, redact_parameters: true });
  assert.equal(shouldRedactParams(cfg.upstream_servers[0], cfg), true);
});

test("shouldRedactParams per-server override=true beats global false", () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    redact_parameters: false,
    upstream_servers: [
      { name: "fs", transport: "stdio", command: "node", redact_parameters: true },
    ],
  });
  assert.equal(shouldRedactParams(cfg.upstream_servers[0], cfg), true);
});

test("shouldRedactParams per-server override=false beats global true", () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    redact_parameters: true,
    upstream_servers: [
      { name: "fs", transport: "stdio", command: "node", redact_parameters: false },
    ],
  });
  assert.equal(shouldRedactParams(cfg.upstream_servers[0], cfg), false);
});

// ---------------------------------------------------------------------------
// toolNamePrefix
// ---------------------------------------------------------------------------

test("toolNamePrefix returns name when name_override absent", () => {
  assert.equal(toolNamePrefix(FS_SERVER), "fs");
});

test("toolNamePrefix returns name_override when set", () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      { name: "fs", transport: "stdio", command: "node", name_override: "filesystem" },
    ],
  });
  assert.equal(toolNamePrefix(cfg.upstream_servers[0]), "filesystem");
});

// ---------------------------------------------------------------------------
// loadProxyConfig
// ---------------------------------------------------------------------------

test("loadProxyConfig loads from an explicit path", async (t) => {
  await withTmpDir(t, async (dir) => {
    const cfgPath = path.join(dir, "proxy.json");
    await writeFile(cfgPath, JSON.stringify(MINIMAL_STDIO), "utf8");
    const cfg = await loadProxyConfig(cfgPath);
    assert.equal(cfg.version, 1);
    assert.equal(cfg.upstream_servers[0].name, "fs");
  });
});

/**
 * Runs fn with every config search location pointed at empty temp dirs, so a
 * config file on the machine running the tests cannot be picked up.
 */
async function withNoConfigAnywhere(t, fn) {
  const origEnv = { ...process.env };
  const origCwd = process.cwd();
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-proxy-home-"));
  const cwd = await mkdtemp(path.join(os.tmpdir(), "omnodex-proxy-cwd-"));
  delete process.env.OMNODEX_HOME;
  // os.homedir() reads these; both are set so the test behaves the same on
  // POSIX and Windows.
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.chdir(cwd);
  t.after(async () => {
    process.chdir(origCwd);
    process.env = origEnv;
    await rm(home, { recursive: true, force: true });
    await rm(cwd, { recursive: true, force: true });
  });
  return fn();
}

test("loadProxyConfig throws when config file not found", async (t) => {
  await withNoConfigAnywhere(t, async () => {
    await assert.rejects(
      () => loadProxyConfig("/definitely/does/not/exist/proxy.json"),
      /not found/i,
    );
  });
});

test("loadProxyConfig returns an empty config when none is found and allowMissing is set", async (t) => {
  await withNoConfigAnywhere(t, async () => {
    const cfg = await loadProxyConfig("/definitely/does/not/exist/proxy.json", {
      allowMissing: true,
    });
    assert.deepEqual(cfg.upstream_servers, []);
    assert.equal(cfg.redact_parameters, false);
    assert.equal(cfg.upstream_connection.discovery_window_ms, 15000);
  });
});

test("loadProxyConfig still throws on a config file it cannot parse when allowMissing is set", async (t) => {
  await withTmpDir(t, async (dir) => {
    const cfgPath = path.join(dir, "omnodex-proxy.json");
    await writeFile(cfgPath, "{ not valid json", "utf8");
    await assert.rejects(() => loadProxyConfig(cfgPath, { allowMissing: true }), /parse/i);
  });
});

test("loadProxyConfig throws on invalid JSON", async (t) => {
  await withTmpDir(t, async (dir) => {
    const cfgPath = path.join(dir, "omnodex-proxy.json");
    await writeFile(cfgPath, "{ not valid json", "utf8");
    await assert.rejects(() => loadProxyConfig(cfgPath), /parse/i);
  });
});

test("loadProxyConfig throws on schema violation", async (t) => {
  await withTmpDir(t, async (dir) => {
    const cfgPath = path.join(dir, "omnodex-proxy.json");
    await writeFile(cfgPath, JSON.stringify({ version: 2, upstream_servers: [] }), "utf8");
    await assert.rejects(() => loadProxyConfig(cfgPath), /invalid/i);
  });
});

test("loadProxyConfig resolves from OMNODEX_HOME when no explicit path", async (t) => {
  await withTmpDir(t, async (dir) => {
    const cfgPath = path.join(dir, "omnodex-proxy.json");
    await writeFile(cfgPath, JSON.stringify(MINIMAL_STDIO), "utf8");
    const prev = process.env.OMNODEX_HOME;
    process.env.OMNODEX_HOME = dir;
    t.after(() => {
      if (prev === undefined) delete process.env.OMNODEX_HOME;
      else process.env.OMNODEX_HOME = prev;
    });
    const cfg = await loadProxyConfig();
    assert.equal(cfg.upstream_servers[0].name, "fs");
  });
});
