// Agents can read whether capture is paused and resume it, never pause it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { readPauseState, startPause } from "../../event-log/dist/index.js";
import { RESUME_TOOL, captureStatus, handleResume } from "../dist/capture-tool.js";

async function tempHome(t) {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-capture-tool-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  return home;
}

test("there is a resume tool and no pause tool", () => {
  assert.equal(RESUME_TOOL.name, "omnodex_resume");
  assert.deepEqual(RESUME_TOOL.inputSchema.properties.kind.enum, ["record", "sync"]);
  assert.doesNotMatch(RESUME_TOOL.name, /pause/);
});

test("status reports both switches", async (t) => {
  const home = await tempHome(t);
  const emitted = [];
  assert.deepEqual(await captureStatus(home, (e) => emitted.push(e)), {
    recording: { state: "on" }, uploads: { state: "on" },
  });
  await startPause(home, "sync", { untilMs: null });
  const status = await captureStatus(home, (e) => emitted.push(e));
  assert.equal(status.uploads.state, "paused");
  assert.equal(status.uploads.until, null);
  assert.equal(emitted.length, 0);
});

test("resume ends a pause and emits its end marker", async (t) => {
  const home = await tempHome(t);
  const { entry } = await startPause(home, "record", { untilMs: null });
  const emitted = [];
  const result = await handleResume({ kind: "record" }, home, (e) => emitted.push(e));
  assert.equal(result.status, "resumed");
  assert.deepEqual(await readPauseState(home), {});
  assert.deepEqual(emitted.map((e) => [e.event_type, e.pause_id]), [["capture.resumed", entry.pause_id]]);

  assert.equal((await handleResume({ kind: "record" }, home, () => {})).status, "not_paused");
  assert.equal((await handleResume({ kind: "everything" }, home, () => {})).status, "invalid");
});
