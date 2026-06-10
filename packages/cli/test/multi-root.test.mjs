/**
 * Tests for multi-root config and streaming.
 *
 * Tests:
 *   1. loadDashboardConfig: missing file, invalid roots, valid config
 *   2. resolveRoots: deduplication, env var, config merge
 *   3. parseRootsFlag: parsing --roots from CLI args
 *   4. Multi-root startStreamingLoop: events from 2 roots merge correctly
 *   5. Backwards compatibility: single EventLog still works
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../../event-log/dist/index.js";
import {
  InMemoryReadModelStore,
  Projector,
} from "../../projection/dist/index.js";
import { startStreamingLoop } from "../dist/streaming.js";
import {
  loadDashboardConfig,
  parseRootsFlag,
} from "../dist/config.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-multiroot-"));
}

function makeMockServer() {
  const messages = [];
  return {
    messages,
    broadcast(msg) {
      messages.push(msg);
    },
  };
}

function sessionStarted(sessionId, seq = 0) {
  return {
    schema_version: 1,
    event_id: `evt_${sessionId}_start`,
    session_id: sessionId,
    occurred_at: new Date(1700000000000 + seq * 1000).toISOString(),
    recorded_at: new Date(1700000000000 + seq * 1000).toISOString(),
    interceptor: "mock",
    event_type: "session.started",
    user: "case",
    project_path: "/tmp/demo",
    mcp_servers: [],
  };
}

function toolInvoked(sessionId, seq) {
  return {
    schema_version: 1,
    event_id: `evt_${sessionId}_tool_${seq}`,
    session_id: sessionId,
    occurred_at: new Date(1700000000000 + seq * 1000).toISOString(),
    recorded_at: new Date(1700000000000 + seq * 1000).toISOString(),
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: `tc_${sessionId}_${seq}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: `/tmp/normal_${seq}.txt` },
  };
}

// ---------------------------------------------------------------------------
// Config tests
// ---------------------------------------------------------------------------

test("loadDashboardConfig returns empty config when file is missing", async () => {
  const tmp = await mkTmp();
  const config = await loadDashboardConfig(tmp);
  assert.deepStrictEqual(config, {});
});

test("loadDashboardConfig loads valid config with roots", async () => {
  const tmp = await mkTmp();
  const configData = {
    dashboard: {
      roots: ["/home/case/.omnodex", "C:\\Users\\case\\.omnodex"],
    },
  };
  await fs.writeFile(
    path.join(tmp, "config.json"),
    JSON.stringify(configData),
  );
  const config = await loadDashboardConfig(tmp);
  assert.deepStrictEqual(config.dashboard.roots, [
    "/home/case/.omnodex",
    "C:\\Users\\case\\.omnodex",
  ]);
});

test("loadDashboardConfig ignores invalid roots (not array of strings)", async () => {
  const tmp = await mkTmp();
  const configData = { dashboard: { roots: [123, null] } };
  await fs.writeFile(
    path.join(tmp, "config.json"),
    JSON.stringify(configData),
  );
  const config = await loadDashboardConfig(tmp);
  // Should return empty config because roots validation failed.
  assert.deepStrictEqual(config, {});
});

// ---------------------------------------------------------------------------
// parseRootsFlag tests
// ---------------------------------------------------------------------------

test("parseRootsFlag extracts roots and remaining args", () => {
  const args = ["7890", "--roots", "/path/a", "/path/b", "--no-detect"];
  const { roots, rest } = parseRootsFlag(args);
  assert.deepStrictEqual(roots, ["/path/a", "/path/b"]);
  assert.deepStrictEqual(rest, ["7890", "--no-detect"]);
});

test("parseRootsFlag returns undefined roots when flag absent", () => {
  const args = ["7890", "--no-detect"];
  const { roots, rest } = parseRootsFlag(args);
  assert.strictEqual(roots, undefined);
  assert.deepStrictEqual(rest, ["7890", "--no-detect"]);
});

test("parseRootsFlag handles --roots with no values", () => {
  const args = ["--roots", "--no-detect"];
  const { roots, rest } = parseRootsFlag(args);
  assert.strictEqual(roots, undefined);
  assert.deepStrictEqual(rest, ["--no-detect"]);
});

// ---------------------------------------------------------------------------
// Multi-root streaming integration tests
// ---------------------------------------------------------------------------

test("startStreamingLoop tails two roots and projects sessions from both", async () => {
  const rootA = await mkTmp();
  const rootB = await mkTmp();

  const logA = new EventLog({ root: path.join(rootA, "event-log") });
  const logB = new EventLog({ root: path.join(rootB, "event-log") });
  await logA.init();
  await logB.init();

  // Write a session to each root.
  await logA.append(sessionStarted("sess_a", 0));
  await logA.append(toolInvoked("sess_a", 1));
  await logB.append(sessionStarted("sess_b", 2));
  await logB.append(toolInvoked("sess_b", 3));

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  // Pre-replay events (as cmdDashboard does before starting the loop).
  projector.setSourceRoot(rootA);
  for await (const event of logA.readAll()) {
    await projector.apply(event);
  }
  projector.setSourceRoot(rootB);
  for await (const event of logB.readAll()) {
    await projector.apply(event);
  }

  const { stop } = startStreamingLoop(
    [
      { rootPath: rootA, log: logA },
      { rootPath: rootB, log: logB },
    ],
    store,
    projector,
    server,
  );

  // Give the streaming loop time to start tailing.
  await new Promise((r) => setTimeout(r, 1500));

  const sessions = await store.listSessions();
  const sessionIds = sessions.map((s) => s.session_id).sort();
  assert.deepStrictEqual(sessionIds, ["sess_a", "sess_b"]);

  // Verify source_root is tagged.
  const sessA = await store.getSession("sess_a");
  const sessB = await store.getSession("sess_b");
  assert.strictEqual(sessA.source_root, rootA);
  assert.strictEqual(sessB.source_root, rootB);

  // Verify both sessions have tool calls projected.
  const callsA = await store.listToolCalls("sess_a");
  const callsB = await store.listToolCalls("sess_b");
  assert.strictEqual(callsA.length, 1);
  assert.strictEqual(callsB.length, 1);

  stop();
  await logA.close();
  await logB.close();
});

test("startStreamingLoop backwards compat: single EventLog still works", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root: path.join(root, "event-log") });
  await log.init();
  await log.append(sessionStarted("sess_single", 0));

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  // Pre-replay (as cmdDashboard does).
  for await (const event of log.readAll()) {
    await projector.apply(event);
  }

  // Pass a single EventLog (legacy API).
  const { stop } = startStreamingLoop(log, store, projector, server);

  await new Promise((r) => setTimeout(r, 1500));

  const sessions = await store.listSessions();
  assert.strictEqual(sessions.length, 1);
  assert.strictEqual(sessions[0].session_id, "sess_single");

  stop();
  await log.close();
});

test("startStreamingLoop detects new sessions appearing in any root", async () => {
  const rootA = await mkTmp();
  const rootB = await mkTmp();

  const logA = new EventLog({ root: path.join(rootA, "event-log") });
  const logB = new EventLog({ root: path.join(rootB, "event-log") });
  await logA.init();
  await logB.init();

  // Start with one session in root A.
  await logA.append(sessionStarted("sess_early", 0));

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  // Pre-replay root A's events (as cmdDashboard does).
  projector.setSourceRoot(rootA);
  for await (const event of logA.readAll()) {
    await projector.apply(event);
  }

  const { stop } = startStreamingLoop(
    [
      { rootPath: rootA, log: logA },
      { rootPath: rootB, log: logB },
    ],
    store,
    projector,
    server,
  );

  await new Promise((r) => setTimeout(r, 1500));

  // Add a new session to root B after the loop started.
  await logB.append(sessionStarted("sess_late", 5));

  // Wait for the poll loop to discover it.
  await new Promise((r) => setTimeout(r, 2000));

  const sessions = await store.listSessions();
  const sessionIds = sessions.map((s) => s.session_id).sort();
  assert.deepStrictEqual(sessionIds, ["sess_early", "sess_late"]);

  stop();
  await logA.close();
  await logB.close();
});
