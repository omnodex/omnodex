// Tests for server observations: fingerprints of an upstream's config,
// identity and tool list, the npx installed-version lookup, tool list
// snapshots, and the server.observed events the proxy writes at connect
// and when an upstream announces new tools.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  canonicalJson,
  configFingerprint,
  createToolListSnapshots,
  npxInstalledVersion,
  npxPackageName,
  toolFingerprint,
  toolFingerprints,
} from "../dist/server-observation.js";
import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

const tool = (name, description = `Does ${name}`, inputSchema = { type: "object", properties: { a: { type: "string" } } }) =>
  ({ name, description, inputSchema });

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-observe-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

test("canonical JSON ignores key order at every level", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: [{ y: 1, x: 2 }] } }), canonicalJson({ a: { c: [{ x: 2, y: 1 }], d: 2 }, b: 1 }));
});

test("a tool's fingerprint follows its description and schema, not key order", () => {
  const base = tool("send_email");
  const reordered = { inputSchema: { properties: { a: { type: "string" } }, type: "object" }, description: base.description, name: "send_email" };
  assert.equal(toolFingerprint(base), toolFingerprint(reordered));
  assert.notEqual(toolFingerprint(base), toolFingerprint(tool("send_email", "Sends an email and copies it elsewhere")));
  assert.notEqual(toolFingerprint(base), toolFingerprint(tool("send_email", base.description, { type: "object", properties: { a: { type: "string" }, bcc: { type: "string" } } })));
});

test("a list fingerprint ignores tool order and changes when a tool is added", () => {
  const a = toolFingerprints([tool("x"), tool("y")]);
  const b = toolFingerprints([tool("y"), tool("x")]);
  assert.equal(a.toolListFingerprint, b.toolListFingerprint);
  assert.deepEqual(a.tools.map((t) => t.name), ["x", "y"]);
  assert.notEqual(a.toolListFingerprint, toolFingerprints([tool("x"), tool("y"), tool("z")]).toolListFingerprint);
});

test("the config fingerprint takes env and header names, never their values", () => {
  const stdio = (env, args = ["-y", "postmark-mcp"]) => ({ name: "mail", transport: "stdio", command: "npx", args, env });
  assert.equal(configFingerprint(stdio({ POSTMARK_TOKEN: "old-value" })), configFingerprint(stdio({ POSTMARK_TOKEN: "rotated-value" })));
  assert.notEqual(configFingerprint(stdio({ POSTMARK_TOKEN: "v" })), configFingerprint(stdio({ POSTMARK_TOKEN: "v", EXTRA: "v" })));
  assert.notEqual(configFingerprint(stdio({})), configFingerprint(stdio({}, ["-y", "postmark-mcp@1.0.16"])));
  const http = (headers) => ({ name: "remote", transport: "http", url: "https://mcp.example.com/mcp", http_headers: headers });
  assert.equal(configFingerprint(http({ "X-Team": "a" })), configFingerprint(http({ "X-Team": "b" })));
  assert.notEqual(configFingerprint(http({ "X-Team": "a" })), configFingerprint(http({ "X-Other": "a" })));
});

// ---------------------------------------------------------------------------
// npx installed version
// ---------------------------------------------------------------------------

test("npxPackageName reads the package an npx command runs", () => {
  assert.equal(npxPackageName("npx", ["-y", "postmark-mcp"]), "postmark-mcp");
  assert.equal(npxPackageName("npx", ["-y", "postmark-mcp@1.0.16"]), "postmark-mcp");
  assert.equal(npxPackageName("C:\\Program Files\\nodejs\\npx.cmd", ["--yes", "@scope/server@latest", "--port", "3"]), "@scope/server");
  assert.equal(npxPackageName("npx", ["-p", "@scope/pkg@2", "server-bin"]), "@scope/pkg");
  assert.equal(npxPackageName("npx", ["--package=@scope/pkg", "server-bin"]), "@scope/pkg");
  assert.equal(npxPackageName("node", ["server.js"]), undefined);
  assert.equal(npxPackageName("npx", ["-y"]), undefined);
});

test("npxInstalledVersion takes the most recently installed copy in the npx cache", (t) => {
  const cache = tempDir(t);
  const install = (hash, name, version, mtime) => {
    const dir = path.join(cache, hash, "node_modules", ...name.split("/"));
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "package.json");
    fs.writeFileSync(file, JSON.stringify({ name, version }));
    fs.utimesSync(file, mtime, mtime);
  };
  install("aaa111", "postmark-mcp", "1.0.15", new Date("2026-09-01"));
  install("bbb222", "postmark-mcp", "1.0.16", new Date("2026-09-20"));
  install("ccc333", "@scope/other", "3.1.0", new Date("2026-10-01"));
  const server = (args) => ({ name: "mail", transport: "stdio", command: "npx", args });
  assert.equal(npxInstalledVersion(server(["-y", "postmark-mcp"]), cache), "1.0.16");
  assert.equal(npxInstalledVersion(server(["-y", "@scope/other"]), cache), "3.1.0");
  assert.equal(npxInstalledVersion(server(["-y", "not-installed"]), cache), undefined);
  assert.equal(npxInstalledVersion(server(["-y", "postmark-mcp"]), path.join(cache, "missing")), undefined);
  assert.equal(npxInstalledVersion({ name: "r", transport: "http", url: "https://mcp.example.com/" }, cache), undefined);
});

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

test("snapshots keep each tool list under its fingerprint", (t) => {
  const dir = tempDir(t);
  const snapshots = createToolListSnapshots(dir);
  const listed = [tool("send_email")];
  const { toolListFingerprint } = toolFingerprints(listed);
  snapshots.save(toolListFingerprint, "mail", listed);
  assert.deepEqual(snapshots.load(toolListFingerprint), listed);
  assert.equal(snapshots.load("0".repeat(32)), undefined);
  // A path in place of a fingerprint never leaves the folder.
  assert.equal(snapshots.load("../../etc/passwd"), undefined);
});

// ---------------------------------------------------------------------------
// The proxy writes server.observed
// ---------------------------------------------------------------------------

function mockUpstream(name, env = {}) {
  return {
    name,
    transport: "stdio",
    command: process.execPath,
    args: [MOCK_SERVER],
    env: { MOCK_TOOLS: JSON.stringify(["ping"]), MOCK_SERVER_NAME: `${name}-server`, ...env },
  };
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function startProxy(t, upstreams) {
  const config = ProxyConfigSchema.parse({ version: 1, upstream_servers: upstreams });
  const snapshotDir = tempDir(t);
  const pool = new UpstreamClientPool({
    snapshots: createToolListSnapshots(snapshotDir),
    installedVersion: () => "9.9.9",
  });
  await pool.connect(config);
  const events = [];
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const serverDone = runProxyServer({
    pool,
    config,
    emit: (e) => { events.push(e); },
    sessionId: "sess-observe-test",
    projectPath: "/home/case/project",
    transport: serverTransport,
  });
  const client = new Client({ name: "observe-test-client", version: "0.0.0" }, {});
  await client.connect(clientTransport);
  return {
    events,
    snapshots: createToolListSnapshots(snapshotDir),
    observed: () => events.filter((e) => e.event_type === "server.observed"),
    async stop() {
      await client.close();
      await serverDone;
      await pool.close();
    },
  };
}

test("the proxy writes one server.observed per upstream after session.started", async (t) => {
  const proxy = await startProxy(t, [mockUpstream("mail", { MOCK_SERVER_VERSION: "1.0.16" }), mockUpstream("files")]);
  try {
    await waitFor(() => proxy.observed().length === 2, 10000, "two observations");
    const types = proxy.events.map((e) => e.event_type);
    assert.ok(types.indexOf("session.started") < types.indexOf("server.observed"));
    const mail = proxy.observed().find((e) => e.mcp_server === "mail");
    assert.equal(mail.trigger, "connect");
    assert.equal(mail.transport, "stdio");
    assert.deepEqual(mail.reported, { name: "mail-server", version: "1.0.16" });
    assert.equal(mail.installed_version, "9.9.9");
    assert.deepEqual(mail.tools.map((t) => t.name), ["ping"]);
    assert.match(mail.tool_list_fingerprint, /^[0-9a-f]{32}$/);
    assert.match(mail.config_fingerprint, /^[0-9a-f]{32}$/);
    assert.equal(mail.session_id, "sess-observe-test");
    // The full list is kept locally, and the event carries no descriptions.
    assert.equal(proxy.snapshots.load(mail.tool_list_fingerprint)[0].description, "Mock tool: ping");
    assert.ok(!JSON.stringify(mail).includes("Mock tool"));
  } finally {
    await proxy.stop();
  }
});

test("an upstream that announces new tools is listed again and observed with list_changed", async (t) => {
  const proxy = await startProxy(t, [mockUpstream("mail", { MOCK_ADD_TOOL: "send_copy", MOCK_ADD_TOOL_AFTER_MS: "300" })]);
  try {
    await waitFor(() => proxy.observed().some((e) => e.trigger === "list_changed"), 10000, "list_changed observation");
    const [first, second] = proxy.observed();
    assert.equal(first.trigger, "connect");
    assert.deepEqual(first.tools.map((t) => t.name), ["ping"]);
    assert.deepEqual(second.tools.map((t) => t.name), ["ping", "send_copy"]);
    assert.notEqual(first.tool_list_fingerprint, second.tool_list_fingerprint);
    assert.equal(first.config_fingerprint, second.config_fingerprint);
    // Both lists stay available for a before-and-after view.
    assert.equal(proxy.snapshots.load(first.tool_list_fingerprint).length, 1);
    assert.equal(proxy.snapshots.load(second.tool_list_fingerprint).length, 2);
  } finally {
    await proxy.stop();
  }
});
