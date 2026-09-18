import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  InMemoryReadModelStore,
  Projector,
  SqliteReadModelStore,
} from "../dist/index.js";

/**
 * Projecting the same event twice must leave the read model exactly as one
 * pass would. This is not the same property as `replay()` being repeatable:
 * replay wipes the store first, so it never exercised the duplicate path.
 * These tests drive `apply()` directly, which is what the streaming loop and
 * the hook shims do.
 *
 * Three real paths reach here: hooks installed in both settings.json and
 * settings.local.json, Codex and Antigravity mapping Stop and SessionEnd
 * onto the same session.ended, and a log that already holds a duplicate.
 */

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-idem-"));
}

const AT = "2026-09-18T12:00:00.000Z";

function base(overrides = {}) {
  return {
    schema_version: 1,
    session_id: "sess_idem",
    occurred_at: AT,
    recorded_at: AT,
    interceptor: "claude-code-hook",
    ...overrides,
  };
}

/** A session that touches every counter the projector maintains. */
function sessionEvents() {
  return [
    base({
      event_id: "e_start",
      event_type: "session.started",
      user: "case",
      project_path: "/home/case/repo",
      mcp_servers: [],
    }),
    base({
      event_id: "e_inv",
      event_type: "tool.invoked",
      tool_call_id: "tc_1",
      tool_name: "mcp__filesystem__read_text_file",
      mcp_server: "filesystem",
      parameters: { path: "/home/case/repo/notes.md" },
    }),
    base({
      event_id: "e_done",
      event_type: "tool.completed",
      tool_call_id: "tc_1",
      duration_ms: 12,
      status: "success",
      response_bytes: 340,
    }),
    base({
      event_id: "e_read",
      event_type: "file.read",
      path: "/home/case/repo/notes.md",
      bytes: 340,
    }),
    base({
      event_id: "e_write",
      event_type: "file.written",
      path: "/home/case/repo/out.md",
      bytes: 120,
    }),
    base({
      event_id: "e_risk",
      event_type: "risk.detected",
      interceptor: "analyzer",
      severity: "HIGH",
      category: "sensitive_path_read",
      description: "read a sensitive path",
      related_event_id: "tc_1",
      rule_id: "rule_sensitive_path",
    }),
  ];
}

/** The counters and row counts that a duplicate must not move. */
async function snapshot(store, sessionId) {
  const session = await store.getSession(sessionId);
  return {
    tool_call_count: session.tool_call_count,
    file_read_count: session.file_read_count,
    file_write_count: session.file_write_count,
    risk_score: session.risk_score,
    tool_calls: (await store.listToolCalls(sessionId)).length,
    file_events: (await store.listFileEvents(sessionId)).length,
    risk_events: (await store.listRiskEvents(sessionId)).length,
  };
}

for (const kind of ["in-memory", "sqlite"]) {
  test(`applying the same events twice is a no-op (${kind})`, async () => {
    let store;
    let root;
    if (kind === "sqlite") {
      root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }

    const projector = new Projector(store);
    const events = sessionEvents();

    for (const e of events) await projector.apply(e);
    const once = await snapshot(store, "sess_idem");

    assert.deepEqual(once, {
      tool_call_count: 1,
      file_read_count: 1,
      file_write_count: 1,
      risk_score: 0.7, // one HIGH finding
      tool_calls: 1,
      file_events: 2,
      risk_events: 1,
    });

    // Second pass over the identical events.
    for (const e of events) await projector.apply(e);
    const twice = await snapshot(store, "sess_idem");

    assert.deepEqual(twice, once, "a second pass must not change the model");

    await store.close();
  });

  test(`a duplicated tool call does not inflate tool_call_count (${kind})`, async () => {
    // Two hook shims firing for one tool call mint different event_ids but
    // carry the same tool_use_id, so tool_call_id is the key that matters.
    let store;
    if (kind === "sqlite") {
      const root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }
    const projector = new Projector(store);

    const invoked = base({
      event_id: "e_a",
      event_type: "tool.invoked",
      tool_call_id: "tc_dup",
      tool_name: "Read",
      mcp_server: "builtin",
      parameters: { file_path: "/home/case/repo/a.md" },
    });

    await projector.apply(invoked);
    await projector.apply({ ...invoked, event_id: "e_b" });

    const session = await store.getSession("sess_idem");
    assert.equal(session.tool_call_count, 1);
    assert.equal((await store.listToolCalls("sess_idem")).length, 1);

    await store.close();
  });

  test(`the same finding reported twice scores once (${kind})`, async () => {
    // A finding is keyed on session, rule and target, not on the event that
    // reported it: two analyzer passes over one tool call mint different
    // event_ids for what is the same finding.
    let store;
    if (kind === "sqlite") {
      const root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }
    const projector = new Projector(store);

    const risk = base({
      event_id: "r_a",
      event_type: "risk.detected",
      interceptor: "analyzer",
      severity: "CRITICAL",
      category: "credential_exfiltration",
      description: "credential sent to a third party",
      related_event_id: "tc_1",
      rule_id: "rule_cred_exfil",
    });

    await projector.apply(risk);
    await projector.apply({ ...risk, event_id: "r_b", occurred_at: "2026-09-18T12:05:00.000Z" });

    const session = await store.getSession("sess_idem");
    assert.equal(session.risk_score, 1.0, "one finding, scored once");
    assert.equal((await store.listRiskEvents("sess_idem")).length, 1);

    await store.close();
  });

  test(`distinct events are still counted separately (${kind})`, async () => {
    // The dedup must key on identity, not on shape. Reading one file twice
    // in a session is two reads.
    let store;
    if (kind === "sqlite") {
      const root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }
    const projector = new Projector(store);

    const read = base({
      event_id: "f_a",
      event_type: "file.read",
      path: "/home/case/repo/same.md",
      bytes: 10,
    });

    await projector.apply(read);
    await projector.apply({
      ...read,
      event_id: "f_b",
      occurred_at: "2026-09-18T12:09:00.000Z",
    });

    const session = await store.getSession("sess_idem");
    assert.equal(session.file_read_count, 2);
    assert.equal((await store.listFileEvents("sess_idem")).length, 2);

    await store.close();
  });
}

test("an existing database migrates forward and collapses duplicate findings", async () => {
  const root = await mkTmp();
  const dbPath = path.join(root, "traces.db");

  // Build a database in the pre-migration shape: no event_id column and no
  // natural keys, holding the duplicate rows this fix prevents.
  const { DatabaseSync } = await import("node:sqlite");
  const legacy = new DatabaseSync(dbPath);
  legacy.exec(`
    CREATE TABLE sessions (
      session_id TEXT PRIMARY KEY, user TEXT NOT NULL, project_path TEXT NOT NULL,
      mcp_servers_json TEXT NOT NULL, interceptor TEXT NOT NULL DEFAULT 'unknown',
      started_at TEXT NOT NULL, ended_at TEXT, duration_ms INTEGER, status TEXT NOT NULL,
      tool_call_count INTEGER NOT NULL DEFAULT 0, file_read_count INTEGER NOT NULL DEFAULT 0,
      file_write_count INTEGER NOT NULL DEFAULT 0, risk_score INTEGER NOT NULL DEFAULT 0,
      last_event_at TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE file_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
      direction TEXT NOT NULL, path TEXT NOT NULL, bytes INTEGER NOT NULL, at TEXT NOT NULL
    );
    CREATE TABLE tool_calls (
      tool_call_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tool_name TEXT NOT NULL,
      mcp_server TEXT NOT NULL, parameters_json TEXT NOT NULL, started_at TEXT NOT NULL,
      ended_at TEXT, duration_ms INTEGER, status TEXT NOT NULL, response_bytes INTEGER,
      error_message TEXT
    );
    CREATE TABLE risk_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
      related_event_id TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, rule_id TEXT NOT NULL, detected_at TEXT NOT NULL
    );
    INSERT INTO sessions (session_id, user, project_path, mcp_servers_json, started_at, status)
      VALUES ('legacy_sess', 'case', '/home/case/repo', '[]', '${AT}', 'completed');
    INSERT INTO file_events (session_id, direction, path, bytes, at)
      VALUES ('legacy_sess', 'read', '/home/case/repo/a.md', 10, '${AT}'),
             ('legacy_sess', 'read', '/home/case/repo/b.md', 20, '${AT}');
    INSERT INTO risk_events (session_id, related_event_id, severity, category, description, rule_id, detected_at)
      VALUES ('legacy_sess', 'tc_1', 'HIGH', 'c', 'd', 'rule_x', '${AT}'),
             ('legacy_sess', 'tc_1', 'HIGH', 'c', 'd', 'rule_x', '${AT}');
  `);
  legacy.close();

  const store = new SqliteReadModelStore({ dbPath });
  await store.init();

  // Legacy file events keep their identity, so neither is lost to the new
  // unique index even though both arrived without an event_id.
  const files = await store.listFileEvents("legacy_sess");
  assert.equal(files.length, 2);
  assert.equal(new Set(files.map((f) => f.event_id)).size, 2);

  // The duplicate finding is collapsed onto the earliest row.
  const risks = await store.listRiskEvents("legacy_sess");
  assert.equal(risks.length, 1);

  // And the migrated database now rejects a repeat.
  const projector = new Projector(store);
  await projector.apply(
    base({
      session_id: "legacy_sess",
      event_id: "r_new",
      event_type: "risk.detected",
      interceptor: "analyzer",
      severity: "HIGH",
      category: "c",
      description: "d",
      related_event_id: "tc_1",
      rule_id: "rule_x",
    }),
  );
  assert.equal((await store.listRiskEvents("legacy_sess")).length, 1);

  await store.close();
});
