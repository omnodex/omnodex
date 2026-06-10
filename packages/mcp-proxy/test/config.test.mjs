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

test("rejects missing upstream_servers", () => {
  const result = ProxyConfigSchema.safeParse({ version: 1 });
  assert.ok(!result.success);
});

test("rejects empty upstream_servers array", () => {
  const result = ProxyConfigSchema.safeParse({ version: 1, upstream_servers: [] });
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

test("loadProxyConfig throws when config file not found", async () => {
  const origHome = process.env.OMNODEX_HOME;
  const origCwd = process.cwd();
  delete process.env.OMNODEX_HOME;
  process.chdir("/tmp");
  try {
    await assert.rejects(
      () => loadProxyConfig("/definitely/does/not/exist/proxy.json"),
      /not found/i,
    );
  } finally {
    process.chdir(origCwd);
    if (origHome !== undefined) process.env.OMNODEX_HOME = origHome;
  }
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
    await writeFile(cfgPath, JSON.stringify({ version: 1, upstream_servers: [] }), "utf8");
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
