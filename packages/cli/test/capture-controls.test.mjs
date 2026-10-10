// `omnodex record pause|resume` and `omnodex sync pause|resume`: pausing
// needs a person at a terminal who types a confirmation; resuming does not.
// `omnodex status` shows both switches.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { readPauseState, startPause } from "../../event-log/dist/index.js";
import { EventLog } from "../../event-log/dist/index.js";
import {
  captureStatusLines,
  formatDuration,
  parseDuration,
  runCaptureControl,
} from "../dist/capture-controls.js";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));

async function tempHome(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-capture-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

/** A terminal that answers every question with `answer`. */
function fakeIo({ tty = true, answer = "pause" } = {}) {
  const out = [];
  const err = [];
  const asked = [];
  return {
    out, err, asked,
    stdinIsTTY: tty,
    stdoutIsTTY: tty,
    async ask(q) { asked.push(q); return answer; },
    log: (l) => out.push(l),
    error: (l) => err.push(l),
  };
}

async function markers(home) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  const events = await log.readSession("omnodex-capture-control");
  await log.close();
  return events;
}

test("durations", () => {
  assert.equal(parseDuration("30m"), 30 * 60_000);
  assert.equal(parseDuration("1h30m"), 90 * 60_000);
  assert.equal(parseDuration("2d"), 2 * 86_400_000);
  assert.equal(parseDuration("90s"), 90_000);
  for (const bad of ["", "1", "h", "1x", "-1h", "1.5h", "31d", "0m"]) assert.equal(parseDuration(bad), null, bad);
  assert.equal(formatDuration(90 * 60_000), "1h 30m");
  assert.equal(formatDuration(2 * 86_400_000), "2d");
});

test("pausing without a terminal is refused, so an agent cannot do it", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo({ tty: false });
  assert.equal(await runCaptureControl("record", ["pause", "1h"], { home, io }), 1);
  assert.match(io.err.join("\n"), /interactive terminal/);
  assert.equal(io.asked.length, 0);
  assert.deepEqual(await readPauseState(home), {});
});

test("pausing needs the typed confirmation", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo({ answer: "yes" });
  assert.equal(await runCaptureControl("sync", ["pause"], { home, io }), 1);
  assert.match(io.out.join("\n"), /not paused/);
  assert.deepEqual(await readPauseState(home), {});
});

test("a confirmed pause writes state and a marker, and pushes the marker", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo();
  const pushed = [];
  const now = Date.parse("2026-06-02T12:00:00.000Z");
  const code = await runCaptureControl("sync", ["pause", "2h"], {
    home, io, now, push: async (events) => { pushed.push(...events); },
  });
  assert.equal(code, 0);
  const state = await readPauseState(home);
  assert.equal(state.sync.until, "2026-06-02T14:00:00.000Z");
  assert.equal(state.sync.by, "cli");
  assert.match(io.out.join("\n"), /stay on this machine/);
  const written = await markers(home);
  assert.deepEqual(written.map((e) => e.event_type), ["capture.paused"]);
  assert.deepEqual(pushed.map((e) => e.event_id), written.map((e) => e.event_id));
});

test("an invalid duration is rejected before asking", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo();
  assert.equal(await runCaptureControl("record", ["pause", "soon"], { home, io }), 1);
  assert.equal(io.asked.length, 0);
});

test("resume needs no terminal and writes the end marker", async (t) => {
  const home = await tempHome(t);
  await startPause(home, "record", { untilMs: null });
  const io = fakeIo({ tty: false });
  assert.equal(await runCaptureControl("record", ["resume"], { home, io }), 0);
  assert.match(io.out.join("\n"), /capture is back on/);
  assert.deepEqual(await readPauseState(home), {});
  assert.deepEqual((await markers(home)).map((e) => e.event_type), ["capture.resumed"]);

  const again = fakeIo({ tty: false });
  assert.equal(await runCaptureControl("record", ["resume"], { home, io: again }), 0);
  assert.match(again.out.join("\n"), /was not paused/);
});

test("status lines show both switches and settle an expired pause", async (t) => {
  const home = await tempHome(t);
  const now = Date.parse("2026-06-02T12:00:00.000Z");
  await startPause(home, "record", { untilMs: now + 60_000, now });
  await startPause(home, "sync", { untilMs: null, now });
  const later = now + 5 * 60_000;
  const { lines, markers: ended } = await captureStatusLines(home, later);
  assert.match(lines[0], /recording:\s+on$/);
  assert.match(lines[1], /uploads:\s+paused since .*until resumed/);
  assert.deepEqual(ended.map((m) => [m.event_type, m.kind, m.reason]), [["capture.resumed", "record", "expired"]]);
});

test("the CLI refuses `record pause` from a non-interactive shell", async (t) => {
  const home = await tempHome(t);
  const omnodexHome = path.join(home, ".omnodex");
  const result = spawnSync(process.execPath, [CLI, "record", "pause", "1h"], {
    cwd: home,
    env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: omnodexHome, OMNODEX_SINGLE_ROOT: "1" },
    encoding: "utf8",
    input: "pause\n",
    timeout: 60_000,
  });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /interactive terminal/);
  assert.deepEqual(await readPauseState(omnodexHome), {});
});

test("`omnodex status` shows recording and uploads", async (t) => {
  const home = await tempHome(t);
  const omnodexHome = path.join(home, ".omnodex");
  await startPause(omnodexHome, "sync", { untilMs: Date.now() + 3_600_000 });
  const result = spawnSync(process.execPath, [CLI, "status"], {
    cwd: home,
    env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: omnodexHome, OMNODEX_SINGLE_ROOT: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\[status\] recording:\s+on/);
  assert.match(result.stdout, /\[status\] uploads:\s+paused until .*left\): events are still captured/);
});

test("`omnodex sync status` reports without running a sync", async (t) => {
  const home = await tempHome(t);
  const omnodexHome = path.join(home, ".omnodex");
  const result = spawnSync(process.execPath, [CLI, "sync", "status"], {
    cwd: home,
    env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: omnodexHome, OMNODEX_SINGLE_ROOT: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\[sync\] .*: on/);
});
