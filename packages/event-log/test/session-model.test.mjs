// Tests for session.model_changed: one event per change of the model a
// platform reports, none for a model session.started already carries.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { cleanModel, sessionModelChangedIfChanged } from "../dist/index.js";

async function home(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-session-model-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  return dir;
}

let n = 0;
const opts = (h, extra = {}) => ({
  home: h,
  sessionId: "sess-case",
  interceptor: "codex-hook",
  source: "hook",
  newEventId: () => `e${++n}`,
  nowIso: () => "2026-10-26T12:00:00.000Z",
  ...extra,
});

test("a model first seen after the session started is an event without previous", async (t) => {
  const h = await home(t);
  const e = await sessionModelChangedIfChanged("gpt-6.1-sol", opts(h));
  assert.equal(e.event_type, "session.model_changed");
  assert.equal(e.model, "gpt-6.1-sol");
  assert.equal(e.source, "hook");
  assert.equal(e.session_id, "sess-case");
  assert.ok(!("previous" in e));
});

test("a model session.started announced is recorded without an event", async (t) => {
  const h = await home(t);
  assert.equal(await sessionModelChangedIfChanged("gemini-3.8-flash-low", opts(h, { announced: true })), null);
  assert.equal(await sessionModelChangedIfChanged("gemini-3.8-flash-low", opts(h)), null);
  const changed = await sessionModelChangedIfChanged("gemini-3.8-flash-medium", opts(h));
  assert.equal(changed.model, "gemini-3.8-flash-medium");
  assert.equal(changed.previous, "gemini-3.8-flash-low");
});

test("a resumed session announcing a new model still records the change", async (t) => {
  const h = await home(t);
  await sessionModelChangedIfChanged("model-a", opts(h, { announced: true }));
  const e = await sessionModelChangedIfChanged("model-b", opts(h, { announced: true }));
  assert.equal(e.previous, "model-a");
});

test("the same model each turn is one event, not one per turn", async (t) => {
  const h = await home(t);
  const events = [];
  for (const m of ["a", "a", "a", "b", "b", "a"]) {
    const e = await sessionModelChangedIfChanged(m, opts(h));
    if (e) events.push(`${e.previous ?? "-"}>${e.model}`);
  }
  assert.deepEqual(events, ["->a", "a>b", "b>a"]);
});

test("sessions are tracked apart", async (t) => {
  const h = await home(t);
  await sessionModelChangedIfChanged("a", opts(h));
  const other = await sessionModelChangedIfChanged("b", opts(h, { sessionId: "other/../session" }));
  assert.ok(!("previous" in other));
});

test("no model, a malformed one, or an unwritable home: nothing, and no throw", async (t) => {
  const h = await home(t);
  for (const bad of [undefined, null, 7, "", "   ", "x".repeat(129), "a\nb"]) {
    assert.equal(await sessionModelChangedIfChanged(bad, opts(h)), null, String(bad));
  }
  const file = path.join(h, "not-a-dir");
  await writeFile(file, "");
  assert.equal(await sessionModelChangedIfChanged("a", opts(file)), null);
  assert.equal(cleanModel("  gpt-6.1-sol "), "gpt-6.1-sol");
});

test("the record is one small file per session", async (t) => {
  const h = await home(t);
  await sessionModelChangedIfChanged("claude-opus-5-5", opts(h));
  assert.deepEqual(JSON.parse(await readFile(path.join(h, "session-models", "sess-case.json"), "utf8")), { model: "claude-opus-5-5" });
});
