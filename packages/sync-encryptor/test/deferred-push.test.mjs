// Deferred live push: a hook the agent waits on queues its events instead of
// pushing, and the next push from the machine sends them first, once.
//
// Run: node --test packages/sync-encryptor/test/deferred-push.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFile, mkdtemp, rm, stat } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { deferLivePush, takeDeferredPush, DEFERRED_PUSH_FILE } from "../dist/shim-push.js";

async function tempHome(t) {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-deferred-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  return home;
}
const ev = (id) => ({ event_id: id, event_type: "tool.invoked", session_id: "s" });

test("deferred events come back in order, once", async (t) => {
  const home = await tempHome(t);
  await deferLivePush([ev("a"), ev("b")], home);
  await deferLivePush([ev("c")], home);
  assert.deepEqual((await takeDeferredPush(home)).map((e) => e.event_id), ["a", "b", "c"]);
  assert.deepEqual(await takeDeferredPush(home), []);
  await assert.rejects(stat(path.join(home, DEFERRED_PUSH_FILE)));
});

test("a line torn by a crash is skipped, with whatever was appended to it", async (t) => {
  const home = await tempHome(t);
  await deferLivePush([ev("a")], home);
  await appendFile(path.join(home, DEFERRED_PUSH_FILE), '{"event_id": "tor');
  await deferLivePush([ev("b")], home);
  assert.deepEqual((await takeDeferredPush(home)).map((e) => e.event_id), ["a"]);
});

test("nothing deferred is an empty list, and deferring nothing writes nothing", async (t) => {
  const home = await tempHome(t);
  await deferLivePush([], home);
  assert.deepEqual(await takeDeferredPush(home), []);
});
