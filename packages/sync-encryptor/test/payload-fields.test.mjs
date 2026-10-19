import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore, Projector, SqliteReadModelStore } from "../../projection/dist/index.js";
import { serializeReadModel, PAYLOAD_FIELDS } from "../dist/index.js";

/**
 * The sync payload is the hosted dashboard's contract. Each row carries the
 * fields in PAYLOAD_FIELDS and nothing else, so a column the read model
 * gains for the local dashboard cannot reach the hosted blob by accident.
 *
 * These tests confirm:
 *   1. The allowlist is exactly the fields written out below. Changing it
 *      means changing this test, on purpose.
 *   2. A read-model field that is not listed never appears in the payload.
 *   3. A session's platform survives projection, SQLite and serialization,
 *      including a session whose platform arrives only after it was created.
 *   4. A database from before the platform column migrates and reads null.
 *   5. A finding's tier, sequence and evidence survive projection, SQLite
 *      and serialization: hosted gates advanced findings and groups
 *      findings into investigations from them.
 */

const AT = "2026-09-29T12:00:00.000Z";

function event(overrides) {
  return {
    schema_version: 1,
    session_id: "sess_fields",
    occurred_at: AT,
    recorded_at: AT,
    interceptor: "claude-code-hook",
    ...overrides,
  };
}

const START = event({
  event_id: "e_start",
  event_type: "session.started",
  user: "case",
  project_path: "/home/case/repo",
  mcp_servers: ["filesystem"],
  platform: "cowork",
});

const INVOKED = event({
  event_id: "e_tool",
  event_type: "tool.invoked",
  tool_call_id: "tc_1",
  tool_name: "Read",
  mcp_server: "builtin",
  parameters: { path: "/home/case/repo/README.md" },
});

const RISK = event({
  event_id: "e_risk",
  event_type: "risk.detected",
  interceptor: "analyzer",
  severity: "HIGH",
  category: "sensitive_path_read",
  description: "read a sensitive path",
  related_event_id: "tc_1",
  rule_id: "rule_sensitive_path",
  rule_tier: "advanced",
  related_event_ids: ["tc_0", "tc_1"],
  evidence: {
    steps: [
      { tool_call_id: "tc_0", role: "source", summary: "Read /home/case/.aws/credentials", labels: ["AWS credentials"], interceptor: "claude-code-hook" },
      { tool_call_id: "tc_1", role: "sink", summary: "Network call to paste.example.net", interceptor: "claude-code-hook" },
    ],
    destination: { host: "paste.example.net", scheme: "https" },
    found_at: "background",
  },
});

/**
 * A SQLite store in a temp dir, closed before its dir is removed: Windows
 * cannot delete a database file that is still open.
 */
async function sqliteStore(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-fields-"));
  const store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
  await store.init();
  t.after(async () => {
    await store.close();
    await fs.rm(root, { recursive: true, force: true });
  });
  return store;
}

async function project(store, events) {
  const projector = new Projector(store);
  for (const e of events) await projector.apply(e);
  return store;
}

test("the payload allowlist is exactly these fields", () => {
  assert.deepEqual(PAYLOAD_FIELDS, {
    sessions: [
      "session_id", "user", "project_path", "mcp_servers", "interceptor",
      "started_at", "ended_at", "duration_ms", "status",
      "tool_call_count", "file_read_count", "file_write_count", "risk_score",
      "last_event_at", "source_root", "platform", "mcp_client_name", "title",
    ],
    tool_calls: [
      "tool_call_id", "session_id", "tool_name", "mcp_server", "interceptor",
      "correlation_id", "parameters_json", "started_at", "ended_at",
      "duration_ms", "status", "response_bytes", "error_message", "agent_id",
    ],
    file_events: ["event_id", "session_id", "direction", "path", "bytes", "at"],
    risk_events: [
      "event_id", "session_id", "related_event_id", "severity", "category",
      "description", "rule_id", "detected_at", "correlation_id",
      "rule_tier", "related_event_ids", "evidence", "enforcement",
    ],
    prompts: ["event_id", "session_id", "prompt", "prompt_id", "at"],
    subagents: [
      "session_id", "agent_id", "agent_type", "started_at", "ended_at",
      "duration_ms", "status", "response_bytes",
    ],
  });
});

test("a read-model field that is not listed stays out of the payload", async () => {
  const store = await project(new InMemoryReadModelStore(), [START, INVOKED, RISK]);
  // A column added to the read model for the local dashboard only.
  await store.patchSession("sess_fields", { local_only: "stays local" });

  const payload = await serializeReadModel(store);
  const rows = {
    sessions: payload.sessions,
    tool_calls: Object.values(payload.tool_calls).flat(),
    file_events: Object.values(payload.file_events).flat(),
    risk_events: Object.values(payload.risk_events).flat(),
  };
  for (const [table, list] of Object.entries(rows)) {
    for (const row of list) {
      for (const key of Object.keys(row)) {
        assert.ok(PAYLOAD_FIELDS[table].includes(key), `${table}.${key} is not in the allowlist`);
      }
    }
  }
  assert.equal(payload.sessions[0].local_only, undefined);
});

test("transports the read model keeps for the local dashboard stay out of the payload", async () => {
  const transports = [{ name: "filesystem", transport: "stdio" }];
  const store = await project(new InMemoryReadModelStore(), [
    { ...START, mcp_server_transports: transports },
    INVOKED,
    RISK,
  ]);
  // The read model has them...
  assert.deepEqual((await store.getSession("sess_fields")).mcp_server_transports, transports);

  // ...and the payload does not.
  const payload = await serializeReadModel(store);
  assert.ok(!("mcp_server_transports" in payload.sessions[0]));
});

test("a finding's tier, sequence and evidence survive projection, SQLite and serialization", async (t) => {
  const store = await project(await sqliteStore(t), [START, INVOKED, RISK]);
  const [row] = (await serializeReadModel(store)).risk_events.sess_fields;
  assert.equal(row.rule_tier, "advanced");
  assert.deepEqual(row.related_event_ids, ["tc_0", "tc_1"]);
  assert.deepEqual(row.evidence, RISK.evidence);
});

test("a single-call finding carries no sequence or evidence in the payload", async () => {
  const { rule_tier: _t, related_event_ids: _r, evidence: _e, ...plain } = RISK;
  const store = await project(new InMemoryReadModelStore(), [START, INVOKED, plain]);
  const [row] = (await serializeReadModel(store)).risk_events.sess_fields;
  assert.ok(!("rule_tier" in row) && !("related_event_ids" in row) && !("evidence" in row));
});

for (const [name, makeStore] of [
  ["in-memory", async () => new InMemoryReadModelStore()],
  ["sqlite", sqliteStore],
]) {
  test(`${name}: a finding's enforcement record survives projection and serialization`, async (t) => {
    const enforcement = { mode: "shadow", candidate: "deny", action: "alert_only", held: false, source: "rule-hint" };
    const store = await project(await makeStore(t), [START, INVOKED, { ...RISK, enforcement }]);
    const [row] = await store.listRiskEvents("sess_fields");
    assert.deepEqual(row.enforcement, enforcement);
    const payload = await serializeReadModel(store);
    assert.deepEqual(payload.risk_events.sess_fields[0].enforcement, enforcement);
  });
}

test("a finding without an enforcement record has none in the payload", async () => {
  const store = await project(new InMemoryReadModelStore(), [START, INVOKED, RISK]);
  const payload = await serializeReadModel(store);
  assert.ok(!("enforcement" in payload.risk_events.sess_fields[0]));
});

test("platform survives projection, SQLite and serialization", async (t) => {
  const store = await sqliteStore(t);
  await project(store, [START, INVOKED]);
  const payload = await serializeReadModel(store);
  assert.equal(payload.sessions[0].platform, "cowork");
  assert.equal(payload.sessions[0].interceptor, "claude-code-hook");
});

test("a proxy session's client name reaches the payload, for hosted labels", async (t) => {
  const store = await sqliteStore(t);
  await project(store, [{ ...START, interceptor: "mcp-proxy", platform: undefined, mcp_client: { name: "Some Client", version: "1.0" } }]);
  const payload = await serializeReadModel(store);
  assert.equal(payload.sessions[0].mcp_client_name, "Some Client");
});

for (const [name, makeStore] of [
  ["in-memory", async () => new InMemoryReadModelStore()],
  ["sqlite", sqliteStore],
]) {
  test(`${name}: a session created by a tool call learns its platform from the event`, async (t) => {
    const store = await makeStore(t);
    // No session.started: the first event creates a stub session.
    await project(store, [{ ...INVOKED, platform: "cowork" }]);
    assert.equal((await store.getSession("sess_fields")).platform, "cowork");
  });

  test(`${name}: a later session.started without a platform keeps the one already known`, async (t) => {
    const store = await makeStore(t);
    const { platform: _dropped, ...startWithout } = START;
    await project(store, [{ ...INVOKED, platform: "cowork" }, startWithout]);
    assert.equal((await store.getSession("sess_fields")).platform, "cowork");
  });

  test(`${name}: a session with no platform anywhere reads null`, async (t) => {
    const store = await makeStore(t);
    const { platform: _dropped, ...startWithout } = START;
    await project(store, [startWithout, INVOKED]);
    assert.equal((await store.getSession("sess_fields")).platform ?? null, null);
  });
}

test("a database from before the platform column migrates and reads null", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-fields-"));
  const dbPath = path.join(root, "traces.db");

  // The sessions table as it was before the column existed.
  const old = new DatabaseSync(dbPath);
  old.exec(`CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY, user TEXT NOT NULL, project_path TEXT NOT NULL,
    mcp_servers_json TEXT NOT NULL, interceptor TEXT NOT NULL DEFAULT 'unknown',
    started_at TEXT NOT NULL, ended_at TEXT, duration_ms INTEGER, status TEXT NOT NULL,
    tool_call_count INTEGER NOT NULL DEFAULT 0, file_read_count INTEGER NOT NULL DEFAULT 0,
    file_write_count INTEGER NOT NULL DEFAULT 0, risk_score REAL NOT NULL DEFAULT 0,
    last_event_at TEXT NOT NULL DEFAULT '', source_root TEXT)`);
  old.prepare(`INSERT INTO sessions (session_id, user, project_path, mcp_servers_json, interceptor, started_at, status)
    VALUES ('sess_old', 'case', '/home/case/repo', '[]', 'claude-code-hook', ?, 'completed')`).run(AT);
  old.close();

  const store = new SqliteReadModelStore({ dbPath });
  await store.init();
  t.after(async () => {
    await store.close();
    await fs.rm(root, { recursive: true, force: true });
  });
  assert.equal((await store.getSession("sess_old")).platform, null);
  const payload = await serializeReadModel(store);
  assert.equal(payload.sessions[0].platform, null);
});

test("prompts, subagents and a subagent's tool calls reach the payload; other sessions get no empty entries", async (t) => {
  const store = await sqliteStore(t);
  await project(store, [
    START,
    event({ event_id: "e_prompt", event_type: "prompt.submitted", prompt: "Summarise /home/case/repo", prompt_id: "p-1" }),
    event({ event_id: "e_sub_start", event_type: "subagent.started", agent_id: "agent-1", agent_type: "Explore" }),
    event({ ...INVOKED, agent_id: "agent-1" }),
    event({ event_id: "e_sub_stop", event_type: "subagent.stopped", agent_id: "agent-1", agent_type: "Explore", duration_ms: 900, status: "completed", response_bytes: 40 }),
    event({ event_id: "e_other", event_type: "session.started", session_id: "sess_plain", user: "case", project_path: "/home/case/other", mcp_servers: [] }),
  ]);
  const payload = await serializeReadModel(store);
  assert.deepEqual(payload.prompts.sess_fields, [
    { event_id: "e_prompt", session_id: "sess_fields", prompt: "Summarise /home/case/repo", prompt_id: "p-1", at: AT },
  ]);
  assert.deepEqual(payload.subagents.sess_fields, [{
    session_id: "sess_fields", agent_id: "agent-1", agent_type: "Explore", started_at: AT, ended_at: AT,
    duration_ms: 900, status: "completed", response_bytes: 40,
  }]);
  assert.equal(payload.tool_calls.sess_fields[0].agent_id, "agent-1");
  assert.equal("sess_plain" in payload.prompts, false);
  assert.equal("sess_plain" in payload.subagents, false);
  assert.equal("agent_id" in payload.tool_calls.sess_plain.concat([{}])[0], false);
});
