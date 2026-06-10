/**
 * Tests for the streaming detection logic.
 *
 * Tests broadcastProjection() and tailSession() in isolation using:
 *   - InMemoryReadModelStore from @omnodex/projection (no SQLite)
 *   - A mock DashboardServer-like broadcast collector
 *   - A real EventLog on a temp directory
 *
 * These tests confirm:
 *   1. broadcastProjection emits the correct SSE message type for each event type.
 *   2. tailSession projects events incrementally and does not replay historical ones.
 *   3. tailSession runs the rule engine and emits risk.detected events for
 *      matching tool.invoked events.
 *   4. tailSession deduplicates risk events -- firing the same rule twice for
 *      the same tool call produces only one risk event.
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
import { RuleEngine, RuleRegistry } from "../../analyzer/dist/index.js";
import { broadcastProjection, tailSession } from "../dist/streaming.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-streaming-"));
}

/** Minimal broadcast recorder -- behaves like DashboardServer for these tests. */
function makeMockServer() {
  const messages = [];
  return {
    messages,
    broadcast(msg) {
      messages.push(msg);
    },
  };
}

function base(sessionId, eventId, seq) {
  return {
    schema_version: 1,
    event_id: eventId,
    session_id: sessionId,
    occurred_at: new Date(1700000000000 + seq * 100).toISOString(),
    recorded_at: new Date(1700000000000 + seq * 100).toISOString(),
    interceptor: "mock",
  };
}

function sessionStarted(sessionId) {
  return {
    ...base(sessionId, `evt_${sessionId}_start`, 0),
    event_type: "session.started",
    user: "tester",
    project_path: "/tmp/demo",
    mcp_servers: [],
  };
}

function toolInvoked(sessionId, seq, filePath) {
  return {
    ...base(sessionId, `evt_${sessionId}_tool_${seq}`, seq),
    event_type: "tool.invoked",
    tool_call_id: `tc_${sessionId}_${seq}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: filePath ?? `/tmp/normal_${seq}.txt` },
  };
}

function sensitiveToolInvoked(sessionId, seq) {
  // /etc/passwd matches RULE_SENSITIVE_PATH_READ
  return toolInvoked(sessionId, seq, "/etc/passwd");
}

function toolCompleted(sessionId, seq) {
  return {
    ...base(sessionId, `evt_${sessionId}_tc_${seq}`, seq + 0.5),
    event_type: "tool.completed",
    tool_call_id: `tc_${sessionId}_${seq}`,
    duration_ms: 10,
    status: "success",
    response_bytes: 42,
  };
}

// ---------------------------------------------------------------------------
// broadcastProjection tests
// ---------------------------------------------------------------------------

test("broadcastProjection: session.started emits session.upserted", async () => {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  const event = sessionStarted("sess_bp1");
  await projector.apply(event);
  await broadcastProjection(event, store, server);

  const types = server.messages.map((m) => m.type);
  assert.ok(types.includes("session.upserted"), `Expected session.upserted, got: ${JSON.stringify(types)}`);
  const msg = server.messages.find((m) => m.type === "session.upserted");
  assert.equal(msg.payload.session_id, "sess_bp1");
});

test("broadcastProjection: tool.invoked emits tool_call.inserted + session.upserted", async () => {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  // First apply the session.started so the session row exists
  await projector.apply(sessionStarted("sess_bp2"));

  const event = toolInvoked("sess_bp2", 1);
  await projector.apply(event);
  await broadcastProjection(event, store, server);

  const types = server.messages.map((m) => m.type);
  assert.ok(types.includes("tool_call.inserted"), `Expected tool_call.inserted in ${JSON.stringify(types)}`);
  assert.ok(types.includes("session.upserted"), `Expected session.upserted in ${JSON.stringify(types)}`);
});

test("broadcastProjection: tool.completed emits tool_call.patched", async () => {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  await projector.apply(sessionStarted("sess_bp3"));
  await projector.apply(toolInvoked("sess_bp3", 1));

  const event = toolCompleted("sess_bp3", 1);
  await projector.apply(event);
  await broadcastProjection(event, store, server);

  const types = server.messages.map((m) => m.type);
  assert.ok(types.includes("tool_call.patched"), `Expected tool_call.patched in ${JSON.stringify(types)}`);
});

test("broadcastProjection: risk.detected emits risk_event.inserted + session.upserted", async () => {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();

  await projector.apply(sessionStarted("sess_bp4"));
  await projector.apply(toolInvoked("sess_bp4", 1));

  const riskEvent = {
    ...base("sess_bp4", "evt_sess_bp4_risk_1", 2),
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "Read /etc/passwd",
    related_event_id: "tc_sess_bp4_1",
    rule_id: "RULE_SENSITIVE_PATH_READ",
  };
  await projector.apply(riskEvent);
  await broadcastProjection(riskEvent, store, server);

  const types = server.messages.map((m) => m.type);
  assert.ok(types.includes("risk_event.inserted"), `Expected risk_event.inserted in ${JSON.stringify(types)}`);
  assert.ok(types.includes("session.upserted"), `Expected session.upserted in ${JSON.stringify(types)}`);
});

// ---------------------------------------------------------------------------
// tailSession tests
// ---------------------------------------------------------------------------

test("tailSession: projects pre-existing events without re-processing them", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();
  const registry = new RuleRegistry();
  const engine = new RuleEngine(registry.getRules());

  // Write two events and replay them (simulates cmdDashboard's historical pass).
  const e1 = sessionStarted("sess_ts1");
  const e2 = toolInvoked("sess_ts1", 1);
  await log.append(e1);
  await log.append(e2);
  await projector.replay(
    (async function* () { yield e1; yield e2; })()
  );

  // Now tail -- the already-projected events must not be broadcast again.
  const ctrl = new AbortController();

  // Abort after a short delay (no new events will arrive)
  setTimeout(() => ctrl.abort(), 80);

  await tailSession("sess_ts1", log, store, projector, server, engine, ctrl.signal);

  // No broadcasts should have happened for the historical events.
  assert.equal(
    server.messages.length,
    0,
    `Expected 0 broadcasts for pre-existing events, got ${server.messages.length}`,
  );

  await log.close();
});

test("tailSession: projects new events and runs detection", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  // Write initial session.started event and replay it
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();
  const registry = new RuleRegistry();
  const engine = new RuleEngine(registry.getRules());

  const e1 = sessionStarted("sess_ts2");
  await log.append(e1);
  await projector.replay((async function* () { yield e1; })());

  const ctrl = new AbortController();

  const tailPromise = tailSession(
    "sess_ts2", log, store, projector, server, engine, ctrl.signal
  );

  // Append a sensitive tool call after a short delay
  await new Promise((r) => setTimeout(r, 50));
  const sensitiveEvent = sensitiveToolInvoked("sess_ts2", 1);
  await log.append(sensitiveEvent);

  // Wait for the tail to pick it up and run detection, then abort
  await new Promise((r) => setTimeout(r, 150));
  ctrl.abort();
  await tailPromise;

  // The tool call should have been projected and broadcast
  const broadcastTypes = server.messages.map((m) => m.type);
  assert.ok(
    broadcastTypes.includes("tool_call.inserted"),
    `Expected tool_call.inserted in broadcasts: ${JSON.stringify(broadcastTypes)}`,
  );

  // Detection should have fired: /etc/passwd matches RULE_SENSITIVE_PATH_READ
  const riskBroadcasts = server.messages.filter((m) => m.type === "risk_event.inserted");
  assert.ok(
    riskBroadcasts.length >= 1,
    `Expected at least 1 risk_event.inserted broadcast, got ${riskBroadcasts.length}`,
  );
  assert.equal(riskBroadcasts[0].payload.rule_id, "RULE_SENSITIVE_PATH_READ");

  // The risk event must also have been appended to the event log
  const loggedEvents = await log.readSession("sess_ts2");
  const riskEvents = loggedEvents.filter((e) => e.event_type === "risk.detected");
  assert.ok(riskEvents.length >= 1, "Expected at least 1 risk.detected event in the log");

  await log.close();
});

test("tailSession: deduplicates risk events for the same (rule, tool_call)", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();
  const registry = new RuleRegistry();
  const engine = new RuleEngine(registry.getRules());

  // Pre-existing: session started + sensitive tool already detected
  const e1 = sessionStarted("sess_ts3");
  const e2 = sensitiveToolInvoked("sess_ts3", 1);
  const e3 = {
    ...base("sess_ts3", "evt_sess_ts3_risk_1", 3),
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "Read /etc/passwd",
    related_event_id: "tc_sess_ts3_1",
    rule_id: "RULE_SENSITIVE_PATH_READ",
  };
  await log.append(e1);
  await log.append(e2);
  await log.append(e3);
  await projector.replay((async function* () { yield e1; yield e2; yield e3; })());

  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), 80);
  await tailSession("sess_ts3", log, store, projector, server, engine, ctrl.signal);

  // The already-detected risk must not produce a second risk_event.inserted broadcast
  const riskBroadcasts = server.messages.filter((m) => m.type === "risk_event.inserted");
  assert.equal(
    riskBroadcasts.length,
    0,
    `Expected 0 duplicate risk broadcasts, got ${riskBroadcasts.length}`,
  );

  // The event log must still have exactly one risk.detected entry
  const loggedEvents = await log.readSession("sess_ts3");
  const riskEvents = loggedEvents.filter((e) => e.event_type === "risk.detected");
  assert.equal(riskEvents.length, 1, "Expected exactly 1 risk.detected event in log");

  await log.close();
});

test("tailSession: replayHistory=true projects history before tailing (FK constraint regression)", async () => {
  // Regression test for: session detected by poll loop after startup, then
  // `omnodex detect` appends a risk.detected event. Without replayHistory=true,
  // session.started is skipped (pre-seeded into processedIds but never projected),
  // leaving no row in the sessions table, so insertRiskEvent fails with
  // "FOREIGN KEY constraint failed".
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = makeMockServer();
  const registry = new RuleRegistry();
  const engine = new RuleEngine(registry.getRules());

  // Simulate: spike wrote these events, then detect appended a risk event.
  // None of them have been projected yet (session appeared after dashboard startup).
  const e1 = sessionStarted("sess_fk");
  const e2 = sensitiveToolInvoked("sess_fk", 1);
  const e3 = {
    ...base("sess_fk", "evt_sess_fk_risk_1", 3),
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "Read /etc/passwd",
    related_event_id: "tc_sess_fk_1",
    rule_id: "RULE_SENSITIVE_PATH_READ",
  };
  await log.append(e1);
  await log.append(e2);
  await log.append(e3);

  // No replay has happened -- the store is empty.
  assert.ok(!await store.getSession("sess_fk"), "Store should be empty before tail");

  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), 80);

  // Must not throw; previously threw "FOREIGN KEY constraint failed" on the
  // SQLite store because session.started was skipped and no sessions row existed.
  await assert.doesNotReject(
    tailSession("sess_fk", log, store, projector, server, engine, ctrl.signal, true),
    "tailSession with replayHistory=true should not throw a FK constraint error",
  );

  // The session row must now exist in the read model.
  const session = await store.getSession("sess_fk");
  assert.ok(session, "Session row must exist after replayHistory=true tail");
  assert.equal(session.session_id, "sess_fk");

  // The risk event must be in the store.
  const risks = await store.listRiskEvents("sess_fk");
  assert.equal(risks.length, 1, "Expected 1 risk event projected from history");

  await log.close();
});
