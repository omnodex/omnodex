/**
 * Capture pauses: state file, markers, and what writers and uploaders see.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  activePauses,
  applyCapturePause,
  endPause,
  localOnlySeen,
  outboundEvents,
  readPauseState,
  settleExpiredPauses,
  startPause,
} from "../dist/index.js";

const T0 = Date.parse("2026-06-02T12:00:00.000Z");
const MIN = 60_000;

async function tempHome(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-pause-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

function call(id) {
  return {
    schema_version: 1,
    event_id: `evt-${id}`,
    session_id: "sess-case",
    occurred_at: new Date(T0).toISOString(),
    recorded_at: new Date(T0).toISOString(),
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-${id}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: "/home/case/repo/README.md" },
  };
}

test("a missing state file means nothing is paused", async (t) => {
  const home = await tempHome(t);
  assert.deepEqual(await readPauseState(home), {});
  const events = [call(1)];
  const out = await applyCapturePause(events, home, T0);
  assert.equal(out.length, 1);
  assert.equal(out[0].local_only, undefined);
});

test("record pause writes nothing but markers", async (t) => {
  const home = await tempHome(t);
  const { entry, markers } = await startPause(home, "record", { untilMs: T0 + 60 * MIN, now: T0 });
  assert.equal(markers.length, 1);
  assert.equal(markers[0].event_type, "capture.paused");
  assert.equal(markers[0].kind, "record");
  assert.equal(markers[0].pause_id, entry.pause_id);
  assert.equal(markers[0].until, new Date(T0 + 60 * MIN).toISOString());
  assert.equal(markers[0].local_only, undefined);

  const out = await applyCapturePause([call(1), ...markers], home, T0 + MIN);
  assert.deepEqual(out.map((e) => e.event_type), ["capture.paused"]);
});

test("sync pause flags events local-only and remembers it", async (t) => {
  const home = await tempHome(t);
  await startPause(home, "sync", { untilMs: null, now: T0 });
  assert.equal(await localOnlySeen(home), false);
  const out = await applyCapturePause([call(1)], home, T0 + MIN);
  assert.equal(out.length, 1);
  assert.equal(out[0].local_only, true);
  assert.equal(await localOnlySeen(home), true);
});

test("an expired pause counts as resumed and writes its end marker once", async (t) => {
  const home = await tempHome(t);
  const until = T0 + 30 * MIN;
  const { entry } = await startPause(home, "sync", { untilMs: until, now: T0 });

  const out = await applyCapturePause([call(1)], home, until + 5 * MIN);
  assert.equal(out.length, 2);
  const [marker, event] = out;
  assert.equal(marker.event_type, "capture.resumed");
  assert.equal(marker.reason, "expired");
  assert.equal(marker.pause_id, entry.pause_id);
  // Stamped when the pause ended, not when it was noticed.
  assert.equal(marker.occurred_at, new Date(until).toISOString());
  assert.equal(event.local_only, undefined);

  assert.deepEqual(await settleExpiredPauses(home, until + 10 * MIN), []);
  assert.deepEqual(await readPauseState(home), {});
});

test("resume ends a pause with a marker; resuming again is a no-op", async (t) => {
  const home = await tempHome(t);
  const { entry } = await startPause(home, "record", { untilMs: null, now: T0 });
  const first = await endPause(home, "record", T0 + MIN);
  assert.equal(first.ended.pause_id, entry.pause_id);
  assert.equal(first.markers.length, 1);
  assert.equal(first.markers[0].reason, "command");
  assert.equal(first.markers[0].paused_at, entry.paused_at);
  const second = await endPause(home, "record", T0 + 2 * MIN);
  assert.equal(second.ended, null);
  assert.deepEqual(second.markers, []);
});

test("a new pause of the same kind replaces the old one", async (t) => {
  const home = await tempHome(t);
  const a = await startPause(home, "sync", { untilMs: null, now: T0 });
  const b = await startPause(home, "sync", { untilMs: T0 + 90 * MIN, now: T0 + MIN });
  assert.deepEqual(b.markers.map((m) => m.event_type), ["capture.resumed", "capture.paused"]);
  assert.equal(b.markers[0].pause_id, a.entry.pause_id);
  assert.equal(b.markers[0].reason, "replaced");
  assert.equal((await readPauseState(home)).sync.pause_id, b.entry.pause_id);
});

test("record and sync pauses are independent", async (t) => {
  const home = await tempHome(t);
  await startPause(home, "record", { untilMs: T0 + 10 * MIN, now: T0 });
  await startPause(home, "sync", { untilMs: null, now: T0 });
  const active = activePauses(await readPauseState(home), T0 + 20 * MIN);
  assert.equal(active.record, undefined);
  assert.ok(active.sync);
});

test("outboundEvents drops local-only events, and everything but markers while paused", async (t) => {
  const home = await tempHome(t);
  const flagged = { ...call(1), local_only: true };
  assert.deepEqual(await outboundEvents([flagged, call(2)], null), [call(2)]);

  const { markers } = await startPause(home, "sync", { untilMs: null, now: Date.now() });
  // A writer that skipped applyCapturePause still cannot leak an event.
  const out = await outboundEvents([call(3), ...markers], home);
  assert.deepEqual(out.map((e) => e.event_type), ["capture.paused"]);
});

test("an unreadable state file is ignored rather than blocking capture", async (t) => {
  const home = await tempHome(t);
  await fs.writeFile(path.join(home, "pause-state.json"), "{not json");
  const out = await applyCapturePause([call(1)], home, T0);
  assert.equal(out.length, 1);
  assert.equal(out[0].local_only, undefined);
});
