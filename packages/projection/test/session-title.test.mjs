/**
 * Tests for session titles in the read model, for both stores: the latest
 * session.renamed is the title, a later session.started keeps it, and a
 * rename for a session not yet seen creates the session.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore, Projector, SqliteReadModelStore } from "../dist/index.js";

const AT = "2026-10-01T12:00:00.000Z";

function event(overrides) {
  return {
    schema_version: 1,
    session_id: "sess_title",
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
  mcp_servers: [],
});
const rename = (id, title) => event({ event_id: id, event_type: "session.renamed", title });

async function sqliteStore(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-title-"));
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
  test(`${name}: the latest rename is the session's title`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    await projector.apply(START);
    assert.ok(!("title" in (await store.getSession("sess_title"))), "no rename, no field");
    await projector.apply(rename("e_r1", "first"));
    await projector.apply(rename("e_r2", "fs015_2"));
    const session = await store.getSession("sess_title");
    assert.equal(session.title, "fs015_2");
    assert.equal(session.project_path, "/home/case/repo");
  });

  test(`${name}: a repeated session.started keeps the title`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    await projector.apply(START);
    await projector.apply(rename("e_r1", "kept"));
    await projector.apply({ ...START, event_id: "e_start_again" });
    assert.equal((await store.getSession("sess_title")).title, "kept");
  });

  test(`${name}: a rename before any other event creates the session`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    await projector.apply(rename("e_r1", "early"));
    await projector.apply(START);
    const session = await store.getSession("sess_title");
    assert.equal(session.title, "early");
    assert.equal(session.project_path, "/home/case/repo");
  });
}
