/**
 * Tests for the event metadata the local dashboard shows.
 *
 * These tests confirm, for both stores:
 *   1. A session keeps how each MCP server is reached (mcp_server_transports).
 *   2. A finding keeps its rule tier and, for a sequence rule, every call in
 *      the pattern (related_event_ids).
 *   3. Rows without the metadata keep their old shape: no empty fields.
 *   4. A SQLite database from before these columns migrates, and its old
 *      rows read as they did.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore, Projector, SqliteReadModelStore } from "../dist/index.js";

const AT = "2026-09-29T12:00:00.000Z";
const TRANSPORTS = [
  { name: "filesystem", transport: "stdio" },
  { name: "docs", transport: "http", host: "docs.example.com" },
];

function event(overrides) {
  return {
    schema_version: 1,
    session_id: "sess_meta",
    occurred_at: AT,
    recorded_at: AT,
    interceptor: "mcp-proxy",
    ...overrides,
  };
}

const START = event({
  event_id: "e_start",
  event_type: "session.started",
  user: "case",
  project_path: "/home/case/repo",
  mcp_servers: ["filesystem", "docs"],
  mcp_server_transports: TRANSPORTS,
});

const SEQUENCE_FINDING = event({
  event_id: "e_seq",
  event_type: "risk.detected",
  interceptor: "analyzer",
  severity: "HIGH",
  category: "exfiltration",
  description: "read a secret, then sent it out",
  related_event_id: "tc_2",
  rule_id: "rule_sequence",
  rule_tier: "advanced",
  related_event_ids: ["tc_1", "tc_2"],
});

const PLAIN_FINDING = event({
  event_id: "e_plain",
  event_type: "risk.detected",
  interceptor: "analyzer",
  severity: "LOW",
  category: "supply_chain",
  description: "new MCP server",
  related_event_id: "tc_1",
  rule_id: "rule_plain",
});

/**
 * A SQLite store whose dir is removed after the store closes: Windows
 * cannot delete an open database file. Pass `root` to use an existing dir.
 */
async function sqliteStore(t, root) {
  const dir = root ?? await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-meta-"));
  const store = new SqliteReadModelStore({ dbPath: path.join(dir, "traces.db") });
  await store.init();
  t.after(async () => {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  });
  return store;
}

for (const [name, makeStore] of [
  ["in-memory", async () => new InMemoryReadModelStore()],
  ["sqlite", sqliteStore],
]) {
  test(`${name}: transports, rule tier and sequence links survive projection and reads`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    for (const e of [START, SEQUENCE_FINDING, PLAIN_FINDING]) await projector.apply(e);

    const session = await store.getSession("sess_meta");
    assert.deepEqual(session.mcp_server_transports, TRANSPORTS);

    const findings = Object.fromEntries((await store.listRiskEvents("sess_meta")).map((r) => [r.rule_id, r]));
    assert.equal(findings.rule_sequence.rule_tier, "advanced");
    assert.deepEqual(findings.rule_sequence.related_event_ids, ["tc_1", "tc_2"]);
    assert.ok(!("rule_tier" in findings.rule_plain), "no tier recorded, no field");
    assert.ok(!("related_event_ids" in findings.rule_plain), "single-call finding has no sequence");
  });

  test(`${name}: a session.started without transports keeps ones already recorded`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    const { mcp_server_transports: _dropped, ...startWithout } = START;
    await projector.apply(START);
    await projector.apply({ ...startWithout, event_id: "e_start_again" });
    assert.deepEqual((await store.getSession("sess_meta")).mcp_server_transports, TRANSPORTS);
  });
}

test("a database from before these columns migrates and its rows read as before", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-meta-"));
  const dbPath = path.join(root, "traces.db");

  const old = new DatabaseSync(dbPath);
  old.exec(`CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY, user TEXT NOT NULL, project_path TEXT NOT NULL,
    mcp_servers_json TEXT NOT NULL, interceptor TEXT NOT NULL DEFAULT 'unknown',
    started_at TEXT NOT NULL, ended_at TEXT, duration_ms INTEGER, status TEXT NOT NULL,
    tool_call_count INTEGER NOT NULL DEFAULT 0, file_read_count INTEGER NOT NULL DEFAULT 0,
    file_write_count INTEGER NOT NULL DEFAULT 0, risk_score REAL NOT NULL DEFAULT 0,
    last_event_at TEXT NOT NULL DEFAULT '', source_root TEXT, platform TEXT)`);
  old.exec(`CREATE TABLE risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL REFERENCES sessions(session_id), related_event_id TEXT NOT NULL,
    severity TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL,
    rule_id TEXT NOT NULL, detected_at TEXT NOT NULL, correlation_id TEXT)`);
  old.prepare(`INSERT INTO sessions (session_id, user, project_path, mcp_servers_json, started_at, status)
    VALUES ('sess_old', 'case', '/home/case/repo', '[]', ?, 'completed')`).run(AT);
  old.prepare(`INSERT INTO risk_events (event_id, session_id, related_event_id, severity, category, description, rule_id, detected_at)
    VALUES ('e_old', 'sess_old', 'tc_1', 'LOW', 'x', 'd', 'rule_old', ?)`).run(AT);
  old.close();

  const store = await sqliteStore(t, root);
  const session = await store.getSession("sess_old");
  assert.ok(!("mcp_server_transports" in session));
  const [finding] = await store.listRiskEvents("sess_old");
  assert.equal(finding.rule_id, "rule_old");
  assert.ok(!("rule_tier" in finding) && !("related_event_ids" in finding));
});
