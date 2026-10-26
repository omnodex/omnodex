/**
 * Tests for the model in the read model, for both stores: session.started
 * sets it, session.model_changed updates it and adds to the distinct list,
 * a repeated session.started keeps the list, and a change for a session not
 * yet seen creates the session.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore, Projector, SqliteReadModelStore } from "../dist/index.js";

const AT = "2026-10-26T12:00:00.000Z";

function event(overrides) {
  return {
    schema_version: 1,
    session_id: "sess_model",
    occurred_at: AT,
    recorded_at: AT,
    interceptor: "codex-hook",
    ...overrides,
  };
}

const start = (id, model) => event({
  event_id: id,
  event_type: "session.started",
  user: "codex",
  project_path: "/home/case/repo",
  mcp_servers: [],
  ...(model ? { model } : {}),
});
const changed = (id, model, previous) => event({
  event_id: id, event_type: "session.model_changed", model, source: "hook", ...(previous ? { previous } : {}),
});

async function sqliteStore(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-model-"));
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
  test(`${name}: session.started sets the model, changes update it and the list`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    await projector.apply(start("e1", "gpt-6.1-sol"));
    let s = await store.getSession("sess_model");
    assert.equal(s.model, "gpt-6.1-sol");
    assert.deepEqual(s.models, ["gpt-6.1-sol"]);

    await projector.apply(changed("e2", "gpt-5.3-codex", "gpt-6.1-sol"));
    await projector.apply(changed("e3", "gpt-6.1-sol", "gpt-5.3-codex"));
    s = await store.getSession("sess_model");
    assert.equal(s.model, "gpt-6.1-sol");
    assert.deepEqual(s.models, ["gpt-6.1-sol", "gpt-5.3-codex"]);
  });

  test(`${name}: a repeated session.started keeps the list and moves the model`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    await projector.apply(start("e1", "model-a"));
    await projector.apply(start("e2", "model-b"));
    const s = await store.getSession("sess_model");
    assert.equal(s.model, "model-b");
    assert.deepEqual(s.models, ["model-a", "model-b"]);
  });

  test(`${name}: no model reported, no field; a later report sets it`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    await projector.apply(start("e1"));
    let s = await store.getSession("sess_model");
    assert.ok(!("model" in s) && !("models" in s));
    await projector.apply(changed("e2", "claude-opus-5-5"));
    s = await store.getSession("sess_model");
    assert.equal(s.model, "claude-opus-5-5");
    assert.deepEqual(s.models, ["claude-opus-5-5"]);
  });

  test(`${name}: a change for an unseen session creates it`, async (t) => {
    const store = await makeStore(t);
    await new Projector(store).apply(changed("e1", "gemini-3.8-flash-low"));
    const s = await store.getSession("sess_model");
    assert.equal(s.status, "in_progress");
    assert.equal(s.model, "gemini-3.8-flash-low");
  });
}

