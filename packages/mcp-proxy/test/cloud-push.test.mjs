// Validation: the proxy's batching cloud push queue.
//
// The queue sits between the proxy's emit path and pushEventsToCloud. It has
// to batch, preserve emit order across batches, survive a failing push, and
// never keep the process alive.
//
// Run: node --test packages/mcp-proxy/test/cloud-push.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { createCloudPushQueue } from "../dist/cloud-push.js";

const HOME = "/home/case/.omnodex";

/** Collects batches and reports them as flat event ids. */
function recorder(impl) {
  const batches = [];
  const pushFn = async (events, home) => {
    batches.push({ ids: events.map((e) => e.event_id), home });
    if (impl) return impl(events);
    return true;
  };
  return { batches, pushFn };
}

function event(id) {
  return {
    schema_version: 1,
    event_id: id,
    session_id: "sess-push",
    occurred_at: "2026-09-17T00:00:00.000Z",
    recorded_at: "2026-09-17T00:00:00.000Z",
    interceptor: "mcp-proxy",
    event_type: "tool.invoked",
    tool_call_id: id,
    tool_name: "filesystem__read_file",
    parameters: {},
  };
}

test("events queued in one quiet period go out as a single batch", async () => {
  const { batches, pushFn } = recorder();
  const queue = createCloudPushQueue({ home: HOME, pushFn, flushDelayMs: 5 });

  queue.enqueue(event("a"));
  queue.enqueue(event("b"));
  queue.enqueue(event("c"));
  await queue.flush();

  assert.equal(batches.length, 1);
  assert.deepEqual(batches[0].ids, ["a", "b", "c"]);
  assert.equal(batches[0].home, HOME);
});

test("a full batch is sent without waiting for the quiet period", async () => {
  const { batches, pushFn } = recorder();
  // A delay long enough that the timer cannot be what sent the batch.
  const queue = createCloudPushQueue({
    home: HOME,
    pushFn,
    flushDelayMs: 60_000,
    maxBatchSize: 2,
  });

  queue.enqueue(event("a"));
  assert.equal(batches.length, 0, "a partial batch must wait");
  queue.enqueue(event("b"));
  await queue.flush();

  assert.deepEqual(batches.map((b) => b.ids), [["a", "b"]]);
});

test("the quiet period sends a partial batch on its own", async () => {
  const { batches, pushFn } = recorder();
  const queue = createCloudPushQueue({ home: HOME, pushFn, flushDelayMs: 5 });

  queue.enqueue(event("a"));
  await new Promise((r) => setTimeout(r, 40));

  assert.deepEqual(batches.map((b) => b.ids), [["a"]]);
  await queue.close();
});

test("batches reach the relay in emit order even when a push is slow", async () => {
  let first = true;
  const { batches, pushFn } = recorder(async () => {
    // Hold the first batch open so the second would overtake it if the queue
    // did not serialise pushes.
    if (first) {
      first = false;
      await new Promise((r) => setTimeout(r, 30));
    }
    return true;
  });
  const queue = createCloudPushQueue({
    home: HOME,
    pushFn,
    flushDelayMs: 60_000,
    maxBatchSize: 1,
  });

  queue.enqueue(event("a"));
  queue.enqueue(event("b"));
  await queue.close();

  assert.deepEqual(batches.map((b) => b.ids), [["a"], ["b"]]);
});

test("a rejecting push does not stop later batches or reject the caller", async () => {
  const { batches, pushFn } = recorder(async (events) => {
    if (events[0].event_id === "a") throw new Error("relay unreachable");
    return true;
  });
  const queue = createCloudPushQueue({
    home: HOME,
    pushFn,
    flushDelayMs: 60_000,
    maxBatchSize: 1,
  });

  queue.enqueue(event("a"));
  queue.enqueue(event("b"));
  // Resolving at all is the assertion: the proxy awaits this during shutdown.
  await queue.close();

  assert.deepEqual(batches.map((b) => b.ids), [["a"], ["b"]]);
});

test("flush with nothing queued resolves and sends nothing", async () => {
  const { batches, pushFn } = recorder();
  const queue = createCloudPushQueue({ home: HOME, pushFn, flushDelayMs: 5 });

  await queue.flush();

  assert.deepEqual(batches, []);
});

test("events enqueued after close are dropped", async () => {
  const { batches, pushFn } = recorder();
  const queue = createCloudPushQueue({ home: HOME, pushFn, flushDelayMs: 5 });

  queue.enqueue(event("a"));
  await queue.close();
  queue.enqueue(event("b"));
  await queue.flush();

  assert.deepEqual(batches.map((b) => b.ids), [["a"]]);
});

test("close is safe to call twice", async () => {
  const { batches, pushFn } = recorder();
  const queue = createCloudPushQueue({ home: HOME, pushFn, flushDelayMs: 5 });

  queue.enqueue(event("a"));
  await queue.close();
  await queue.close();

  assert.deepEqual(batches.map((b) => b.ids), [["a"]]);
});
