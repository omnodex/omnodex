// Tests for the session title helpers hook shims share: reading the tail of
// a JSONL file, and recording a title only when it changes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  claimTitleChange,
  cleanTitle,
  readJsonlTail,
  sessionRenamedIfChanged,
} from "../dist/index.js";

async function scratch(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-title-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test("readJsonlTail: a missing file reads as no records", async (t) => {
  const dir = await scratch(t);
  assert.deepEqual(await readJsonlTail(path.join(dir, "nope.jsonl")), []);
});

test("readJsonlTail: skips a truncated last line", async (t) => {
  const dir = await scratch(t);
  const file = path.join(dir, "t.jsonl");
  await writeFile(file, '{"n":1}\n{"n":2}\n{"n":3, "half', "utf8");
  assert.deepEqual(await readJsonlTail(file), [{ n: 1 }, { n: 2 }]);
});

test("readJsonlTail: a read that starts mid-file drops the partial first line", async (t) => {
  const dir = await scratch(t);
  const file = path.join(dir, "t.jsonl");
  const lines = ['{"n":"first-record-that-is-long"}', '{"n":2}', '{"n":3}'];
  await writeFile(file, lines.join("\n") + "\n", "utf8");
  // Fewer bytes than the file holds, starting inside the first record.
  const tail = await readJsonlTail(file, lines[1].length + lines[2].length + 10);
  assert.deepEqual(tail, [{ n: 2 }, { n: 3 }]);
});

test("cleanTitle: trims, collapses whitespace, caps length, rejects blanks", () => {
  assert.equal(cleanTitle("  fs015\n  part 2 "), "fs015 part 2");
  assert.equal(cleanTitle("   "), null);
  assert.equal(cleanTitle(42), null);
  assert.equal(cleanTitle("x".repeat(500)).length, 200);
});

test("claimTitleChange: new titles count once, and an auto title never replaces the user's", async (t) => {
  const home = await scratch(t);
  assert.equal(await claimTitleChange(home, "s1", { title: "Auto name", source: "auto" }), true);
  assert.equal(await claimTitleChange(home, "s1", { title: "Auto name", source: "auto" }), false);
  assert.equal(await claimTitleChange(home, "s1", { title: "mine", source: "user" }), true);
  assert.equal(await claimTitleChange(home, "s1", { title: "Auto name", source: "auto" }), false);
  assert.equal(await claimTitleChange(home, "s1", { title: "mine 2", source: "user" }), true);
  // Sessions are tracked separately.
  assert.equal(await claimTitleChange(home, "s2", { title: "mine 2", source: "user" }), true);
});

test("sessionRenamedIfChanged: emits a session.renamed event on a change only", async (t) => {
  const home = await scratch(t);
  const options = {
    home,
    sessionId: "s1",
    interceptor: "claude-code-hook",
    newEventId: () => "e1",
    nowIso: () => "2026-10-01T12:00:00.000Z",
  };
  assert.equal(await sessionRenamedIfChanged(null, options), null);
  assert.deepEqual(await sessionRenamedIfChanged({ title: "fs015_2", source: "user" }, options), {
    schema_version: 1,
    event_id: "e1",
    event_type: "session.renamed",
    session_id: "s1",
    occurred_at: "2026-10-01T12:00:00.000Z",
    recorded_at: "2026-10-01T12:00:00.000Z",
    interceptor: "claude-code-hook",
    title: "fs015_2",
  });
  assert.equal(await sessionRenamedIfChanged({ title: "fs015_2", source: "user" }, options), null);
});
