/**
 * Tests for EventLog.tail() -- the streaming read path.
 *
 * These tests verify the three core properties:
 *   1. tail() yields events that were already in the file at call time.
 *   2. tail() picks up events appended after it started polling.
 *   3. tail() stops cleanly when the AbortSignal is aborted.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../dist/index.js";

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-tail-"));
}

function makeToolEvent(sessionId, seq) {
  return {
    schema_version: 1,
    event_id: `evt_${sessionId}_${seq}`,
    session_id: sessionId,
    occurred_at: new Date(1700000000000 + seq * 100).toISOString(),
    recorded_at: new Date(1700000000000 + seq * 100).toISOString(),
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: `tc_${sessionId}_${seq}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: `/tmp/file_${seq}.txt` },
  };
}

// ---------------------------------------------------------------------------
// 1. Yields events already present when tail() is called
// ---------------------------------------------------------------------------

test("tail() yields events already in the file", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  await log.append(makeToolEvent("sess_pre", 1));
  await log.append(makeToolEvent("sess_pre", 2));
  await log.append(makeToolEvent("sess_pre", 3));

  const ctrl = new AbortController();
  const collected = [];

  for await (const event of log.tail("sess_pre", ctrl.signal, 20)) {
    collected.push(event);
    if (collected.length === 3) {
      ctrl.abort();
    }
  }

  assert.equal(collected.length, 3);
  assert.equal(collected[0].event_id, "evt_sess_pre_1");
  assert.equal(collected[2].event_id, "evt_sess_pre_3");

  await log.close();
});

// ---------------------------------------------------------------------------
// 2. Picks up events appended after tailing began
// ---------------------------------------------------------------------------

test("tail() picks up events appended after it started", async (t) => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  // Write one event before the tail starts.
  await log.append(makeToolEvent("sess_live", 1));

  const ctrl = new AbortController();
  const collected = [];

  // Start tailing with a fast poll interval (20 ms) so the test is quick.
  const tailPromise = (async () => {
    for await (const event of log.tail("sess_live", ctrl.signal, 20)) {
      collected.push(event);
      if (collected.length === 3) {
        ctrl.abort();
      }
    }
  })();

  // Append two more events after a short delay so the tail loop is running.
  await new Promise((resolve) => setTimeout(resolve, 50));
  await log.append(makeToolEvent("sess_live", 2));
  await log.append(makeToolEvent("sess_live", 3));

  await tailPromise;

  assert.equal(collected.length, 3);
  assert.equal(collected[0].event_id, "evt_sess_live_1");
  assert.equal(collected[1].event_id, "evt_sess_live_2");
  assert.equal(collected[2].event_id, "evt_sess_live_3");

  await log.close();
});

// ---------------------------------------------------------------------------
// 3. Stops cleanly on AbortSignal
// ---------------------------------------------------------------------------

test("tail() stops when AbortSignal is aborted", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  await log.append(makeToolEvent("sess_abort", 1));

  const ctrl = new AbortController();
  const collected = [];

  // Abort after a short delay -- tail should not hang indefinitely.
  const abortTimer = setTimeout(() => ctrl.abort(), 100);

  for await (const event of log.tail("sess_abort", ctrl.signal, 20)) {
    collected.push(event);
  }

  clearTimeout(abortTimer);

  // We must have exited the generator (no timeout / infinite loop).
  // We should have seen the one pre-existing event.
  assert.equal(collected.length, 1);
  assert.equal(collected[0].event_id, "evt_sess_abort_1");

  await log.close();
});

// ---------------------------------------------------------------------------
// 4. Handles the case where the file does not exist yet
// ---------------------------------------------------------------------------

test("tail() waits for a session file that does not exist yet", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  const ctrl = new AbortController();
  const collected = [];

  // Start tail before appending anything -- no session file exists.
  const tailPromise = (async () => {
    for await (const event of log.tail("sess_new", ctrl.signal, 20)) {
      collected.push(event);
      if (collected.length === 1) ctrl.abort();
    }
  })();

  // Create the session by appending after a delay.
  await new Promise((resolve) => setTimeout(resolve, 60));
  await log.append(makeToolEvent("sess_new", 1));

  await tailPromise;

  assert.equal(collected.length, 1);
  assert.equal(collected[0].event_id, "evt_sess_new_1");

  await log.close();
});

// ---------------------------------------------------------------------------
// 5. Does not re-yield events already yielded (offset advances)
// ---------------------------------------------------------------------------

test("tail() does not re-yield events already seen", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();

  await log.append(makeToolEvent("sess_offset", 1));
  await log.append(makeToolEvent("sess_offset", 2));

  const ctrl = new AbortController();
  const ids = [];

  // Append a third event mid-tail to ensure the generator resumes correctly.
  const tailPromise = (async () => {
    for await (const event of log.tail("sess_offset", ctrl.signal, 20)) {
      ids.push(event.event_id);
      if (ids.length === 2) {
        // Append a third event now
        await log.append(makeToolEvent("sess_offset", 3));
      }
      if (ids.length === 3) ctrl.abort();
    }
  })();

  await tailPromise;

  assert.deepEqual(ids, ["evt_sess_offset_1", "evt_sess_offset_2", "evt_sess_offset_3"]);
  // Each event id must appear exactly once -- no re-yields.
  const unique = new Set(ids);
  assert.equal(unique.size, ids.length);

  await log.close();
});
