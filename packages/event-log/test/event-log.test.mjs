import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../dist/index.js";

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-eventlog-"));
}

function makeEvent(sessionId, seq) {
  return {
    schema_version: 1,
    event_id: `evt_${sessionId}_${seq}`,
    session_id: sessionId,
    occurred_at: new Date(1700000000000 + seq).toISOString(),
    recorded_at: new Date(1700000000000 + seq).toISOString(),
    interceptor: "mock",
    event_type: "session.started",
    user: "tester",
    project_path: "/tmp/demo",
    mcp_servers: [],
  };
}

test("append and read single session", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();
  await log.append(makeEvent("sess_a", 1));
  await log.append(makeEvent("sess_a", 2));
  await log.close();

  const events = await log.readSession("sess_a");
  assert.equal(events.length, 2);
  assert.equal(events[0].event_id, "evt_sess_a_1");
  assert.equal(events[1].event_id, "evt_sess_a_2");
});

test("index records each session once across restarts", async () => {
  const root = await mkTmp();
  const first = new EventLog({ root });
  await first.init();
  await first.append(makeEvent("sess_b", 1));
  await first.append(makeEvent("sess_b", 2));
  await first.close();

  const second = new EventLog({ root });
  await second.init();
  await second.append(makeEvent("sess_b", 3));
  await second.append(makeEvent("sess_c", 1));
  await second.close();

  const listed = await (async () => {
    const l = new EventLog({ root });
    await l.init();
    return l.listSessions();
  })();
  assert.deepEqual(listed.sort(), ["sess_b", "sess_c"]);
});

test("readAll streams events across sessions", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();
  await log.append(makeEvent("sess_x", 1));
  await log.append(makeEvent("sess_y", 1));
  await log.append(makeEvent("sess_x", 2));
  await log.close();

  const out = [];
  for await (const ev of log.readAll()) out.push(ev);
  assert.equal(out.length, 3);
});

test("append rejects events with wrong schema_version", async () => {
  const root = await mkTmp();
  const log = new EventLog({ root });
  await log.init();
  await assert.rejects(
    log.append({ ...makeEvent("sess_q", 1), schema_version: 99 }),
    /schema_version=99/,
  );
  await log.close();
});
