// Validation: the proxy's periodic sync timer, and the cloud wiring in
// MCPProxy that connects the emit path to the relay and the sync.
//
// The proxy is the only interceptor for Cowork Desktop and ChatGPT Desktop,
// so if these two paths are not wired those platforms produce nothing in the
// hosted dashboard however long a session runs.
//
// Run: node --test packages/mcp-proxy/test/background-sync.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { startAutoSyncTimer } from "../dist/background-sync.js";
import { MCPProxy } from "../dist/mcp-proxy.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

const HOME = "/home/case/.omnodex";
const SCRIPT = "/home/case/omnodex/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js";

// ---------------------------------------------------------------------------
// The timer
// ---------------------------------------------------------------------------

test("the timer asks for a sync repeatedly, with the home and script to respawn", async () => {
  const calls = [];
  const timer = await startAutoSyncTimer({
    home: HOME,
    scriptPath: SCRIPT,
    intervalMs: 10,
    startSyncFn: async (opts) => {
      calls.push(opts);
      return "started";
    },
  });
  try {
    await new Promise((r) => setTimeout(r, 60));
    assert.ok(calls.length >= 2, `expected repeated ticks, got ${calls.length}`);
    assert.deepEqual(calls[0], { home: HOME, scriptPath: SCRIPT });
  } finally {
    timer.stop();
  }
});

test("stop() ends the timer and is safe to call twice", async () => {
  let calls = 0;
  const timer = await startAutoSyncTimer({
    home: HOME,
    scriptPath: SCRIPT,
    intervalMs: 10,
    startSyncFn: async () => {
      calls += 1;
      return "started";
    },
  });
  await new Promise((r) => setTimeout(r, 40));
  timer.stop();
  timer.stop();

  const after = calls;
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(calls, after, "timer kept firing after stop()");
});

test("a rejecting startBackgroundSync does not surface as an unhandled rejection", async () => {
  const timer = await startAutoSyncTimer({
    home: HOME,
    scriptPath: SCRIPT,
    intervalMs: 10,
    startSyncFn: async () => {
      throw new Error("state file unreadable");
    },
  });
  try {
    await new Promise((r) => setTimeout(r, 40));
  } finally {
    timer.stop();
  }
});

// ---------------------------------------------------------------------------
// MCPProxy wiring
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
        env: { MOCK_TOOLS: JSON.stringify(["get_info"]), MOCK_RESULT_TEXT: "proxied" },
      },
    ],
  });
}

/** Runs a whole proxy session over an in-memory transport. */
async function runSession(options = {}) {
  const pushed = [];
  const syncCalls = [];
  const logged = [];

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const proxy = new MCPProxy(makeConfig(), {
    projectPath: "/home/case/project",
    home: HOME,
    autoSyncScriptPath: options.autoSyncScriptPath,
    transport: serverTransport,
    hooks: {
      pushFn: async (events) => {
        pushed.push(...events);
        return true;
      },
      startSyncFn: async (opts) => {
        syncCalls.push(opts);
        return "started";
      },
      autoSyncIntervalMs: options.autoSyncIntervalMs ?? 10,
      pushFlushDelayMs: 1,
    },
  });

  const stop = await proxy.start(async (event) => {
    logged.push(event);
  });

  const client = new Client({ name: "cloud-test-client", version: "0.0.0" }, {});
  await client.connect(clientTransport);
  await client.callTool({ name: "filesystem__get_info", arguments: { input: "q" } });
  if (options.dwellMs) await new Promise((r) => setTimeout(r, options.dwellMs));
  await client.close();
  await proxy.whenClosed();
  await stop();

  return { pushed, syncCalls, logged };
}

test("every logged event is also pushed to the relay", async () => {
  const { pushed, logged } = await runSession();

  assert.ok(logged.length >= 4, "expected a full session in the local log");
  assert.deepEqual(
    pushed.map((e) => e.event_id),
    logged.map((e) => e.event_id),
    "the relay and the local log must see the same events, in the same order",
  );
  const types = pushed.map((e) => e.event_type);
  assert.ok(types.includes("session.started"));
  assert.ok(types.includes("tool.invoked"));
  assert.ok(types.includes("tool.completed"));
  assert.ok(
    types.includes("session.ended"),
    "stop() must flush session.ended, which is emitted after the client disconnects",
  );
});

test("the sync timer runs for the session when a respawn script is given", async () => {
  const { syncCalls } = await runSession({
    autoSyncScriptPath: SCRIPT,
    autoSyncIntervalMs: 10,
    dwellMs: 60,
  });

  assert.ok(syncCalls.length >= 1, "expected at least one sync while connected");
  assert.equal(syncCalls[0].scriptPath, SCRIPT);
  assert.equal(syncCalls[0].home, HOME);
});

test("without a respawn script the proxy never starts a sync", async () => {
  const { syncCalls, pushed } = await runSession({ dwellMs: 60 });

  assert.deepEqual(syncCalls, []);
  assert.ok(pushed.length > 0, "live push is independent of the sync timer");
});
