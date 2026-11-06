// Call ids for Copilot, which sends none that pair a post-hook with its pre-hook.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { callKeyFile, closeCall, openCall, payloadCallId } from "../dist/tool-ids.js";

async function dir(t) {
  const d = await mkdtemp(path.join(os.tmpdir(), "omnodex-copilot-ids-"));
  t.after(() => rm(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  return d;
}

test("a post-hook gets the id and duration of its pre-hook", async (t) => {
  const d = await dir(t);
  const file = callKeyFile(d, "s1", "Bash", { command: "ls" });
  await openCall(file, "call-a", 1000);
  assert.deepEqual(await closeCall(file, 1250), { id: "call-a", durationMs: 250 });
  assert.equal(await closeCall(file, 2000), null, "closed once");
});

test("identical calls in flight pair up oldest first", async (t) => {
  const d = await dir(t);
  const file = callKeyFile(d, "s1", "Bash", { command: "ls" });
  await openCall(file, "first", 1000);
  await openCall(file, "second", 1100);
  assert.equal((await closeCall(file, 1200)).id, "first");
  assert.equal((await closeCall(file, 1300)).id, "second");
});

test("different sessions, tools and inputs do not mix; key order in the input does not matter", async (t) => {
  const d = await dir(t);
  const a = callKeyFile(d, "s1", "Bash", { a: 1, b: 2 });
  assert.equal(a, callKeyFile(d, "s1", "Bash", { b: 2, a: 1 }));
  assert.notEqual(a, callKeyFile(d, "s2", "Bash", { a: 1, b: 2 }));
  assert.notEqual(a, callKeyFile(d, "s1", "Edit", { a: 1, b: 2 }));
  assert.notEqual(a, callKeyFile(d, "s1", "Bash", { a: 1, b: 3 }));
});

test("an entry whose post-hook never came is dropped after a day", async (t) => {
  const d = await dir(t);
  const file = callKeyFile(d, "s1", "Bash", {});
  await openCall(file, "old", Date.now() - 25 * 60 * 60 * 1000);
  assert.equal(await closeCall(file), null);
});

test("an id Copilot sends is used as it is", () => {
  assert.equal(payloadCallId({ tool_use_id: "x" }), "x");
  assert.equal(payloadCallId({ toolCallId: "y" }), "y");
  assert.equal(payloadCallId({}), undefined);
});
