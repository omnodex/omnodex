import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { InMemoryReadModelStore, Projector, SqliteReadModelStore, inTransaction } from "../dist/index.js";

/**
 * A rebuild runs as one write transaction: committed when it finishes, rolled
 * back when it fails, and serialized against another process replaying the
 * same file rather than interleaved with it.
 */

const AT = "2026-10-20T12:00:00.000Z";

function session(id) {
  return {
    session_id: id,
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
    interceptor: "claude-code-hook",
    started_at: AT,
    ended_at: null,
    duration_ms: null,
    status: "in_progress",
    tool_call_count: 0,
    file_read_count: 0,
    file_write_count: 0,
    risk_score: 0,
    last_event_at: AT,
    source_root: null,
    platform: null,
  };
}

async function openStore(t, dbPath) {
  const dir = dbPath ? null : await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-tx-"));
  const store = new SqliteReadModelStore({ dbPath: dbPath ?? path.join(dir, "traces.db") });
  await store.init();
  t.after(async () => {
    await store.close();
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });
  return store;
}

test("a transaction commits what it wrote", async (t) => {
  const store = await openStore(t);
  const result = await store.transaction(async () => {
    await store.upsertSession(session("sess_a"));
    return "done";
  });
  assert.equal(result, "done");
  assert.equal((await store.listSessions()).length, 1);
});

test("a transaction that throws is rolled back", async (t) => {
  const store = await openStore(t);
  await store.upsertSession(session("sess_before"));
  await assert.rejects(
    store.transaction(async () => {
      await store.upsertSession(session("sess_lost"));
      throw new Error("boom");
    }),
    /boom/,
  );
  assert.deepEqual((await store.listSessions()).map((s) => s.session_id), ["sess_before"]);
  // The store is usable afterwards.
  await store.transaction(async () => store.upsertSession(session("sess_after")));
  assert.equal((await store.listSessions()).length, 2);
});

test("a nested transaction joins the outer one", async (t) => {
  const store = await openStore(t);
  await assert.rejects(
    store.transaction(async () => {
      await store.transaction(async () => store.upsertSession(session("sess_inner")));
      throw new Error("outer fails");
    }),
  );
  assert.equal((await store.listSessions()).length, 0);
});

test("reset inside a transaction is refused", async (t) => {
  const store = await openStore(t);
  await assert.rejects(store.transaction(async () => store.reset()), /inside a transaction/);
});

test("a write waits for another process's transaction on the same file instead of failing as busy", async (t) => {
  const store = await openStore(t);
  const dbPath = store["dbPath"];
  // Another process takes the write lock and holds it for 300 ms.
  const holder = spawn(process.execPath, ["-e", `
    const { DatabaseSync } = require("node:sqlite");
    const db = new DatabaseSync(${JSON.stringify(dbPath)});
    db.exec("BEGIN IMMEDIATE");
    process.stdout.write("locked\\n");
    setTimeout(() => { db.exec("COMMIT"); db.close(); }, 300);
  `], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((resolve) => holder.stdout.once("data", resolve));
  const started = Date.now();
  await store.transaction(async () => store.upsertSession(session("sess_waited")));
  assert.ok(Date.now() - started >= 200, "the write waited for the other transaction");
  assert.equal((await store.listSessions()).length, 1);
  await new Promise((resolve) => holder.once("exit", resolve));
});

test("replay runs in one transaction, and inTransaction falls back for stores without one", async (t) => {
  const store = await openStore(t);
  const events = [
    { schema_version: 1, event_id: "e1", event_type: "session.started", session_id: "sess_r", occurred_at: AT, recorded_at: AT, interceptor: "claude-code-hook", user: "case", project_path: "/home/case/repo", mcp_servers: [] },
  ];
  let calls = 0;
  const original = store.transaction.bind(store);
  store.transaction = (fn) => { calls++; return original(fn); };
  await new Projector(store).replay(events);
  assert.equal(calls, 1);
  assert.equal((await store.listSessions()).length, 1);

  const memory = new InMemoryReadModelStore();
  assert.equal(await inTransaction(memory, async () => 7), 7);
});
