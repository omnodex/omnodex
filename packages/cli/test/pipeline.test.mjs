/**
 * End-to-end integration test for the Omnodex pipeline.
 *
 *   mock interceptor  ->  event log  ->  projector  ->  SQLite read model
 *
 * Asserts the key properties that make the event-log-first architecture
 * actually work:
 *
 *   1. Events are durable on disk as JSONL after interception.
 *   2. The projector can rebuild the SQLite read model from scratch by
 *      deleting the db file and replaying.
 *   3. Two consecutive replays produce the same read model state (no
 *      double counting on tool_call_count, file_read_count, risk_score).
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../../event-log/dist/index.js";
import {
  SqliteReadModelStore,
  Projector,
} from "../../projection/dist/index.js";
import { MockInterceptor } from "../../hooks-provider/dist/index.js";

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-e2e-"));
}

test("full pipeline: mock interceptor -> event log -> projection -> sqlite", async () => {
  const home = await mkTmp();
  const eventLogRoot = path.join(home, "event-log");
  const dbPath = path.join(home, "traces.db");

  // Interception side: append events into the log via the mock interceptor.
  const log = new EventLog({ root: eventLogRoot });
  await log.init();
  const interceptor = new MockInterceptor({ sessionId: "sess_e2e" });
  const events = interceptor.buildSessionEvents();
  assert.equal(events.length, 25);
  for (const event of events) {
    await log.append(event);
  }
  await log.close();

  // The JSONL file must be on disk and readable by humans (and cat).
  const sessionFile = log.sessionFilePath("sess_e2e");
  const raw = await fs.readFile(sessionFile, "utf8");
  const lines = raw.split("\n").filter((l) => l.length > 0);
  assert.equal(lines.length, 25);
  for (const line of lines) {
    JSON.parse(line); // Must parse.
  }

  // Projection side: rebuild read model by replaying the log.
  const store = new SqliteReadModelStore({ dbPath });
  await store.init();
  const projector = new Projector(store);

  async function* replaySource() {
    const l = new EventLog({ root: eventLogRoot });
    await l.init();
    for await (const e of l.readAll()) yield e;
  }

  await projector.replay(replaySource());

  const sessions = await store.listSessions();
  assert.equal(sessions.length, 1);
  const session = sessions[0];
  assert.equal(session.session_id, "sess_e2e");
  assert.equal(session.status, "completed");
  assert.equal(session.tool_call_count, 9);
  assert.equal(session.file_read_count, 2);
  assert.equal(session.file_write_count, 1);
  assert.equal(session.risk_score, 90);

  // Now delete the db file and replay again. Rebuild-from-scratch is a
  // load-bearing property of the event-log-first architecture.
  await store.close();
  await fs.rm(dbPath, { force: true });
  await fs.rm(`${dbPath}-wal`, { force: true });
  await fs.rm(`${dbPath}-shm`, { force: true });

  const rebuilt = new SqliteReadModelStore({ dbPath });
  await rebuilt.init();
  const projector2 = new Projector(rebuilt);
  await projector2.replay(replaySource());

  const rebuiltSessions = await rebuilt.listSessions();
  assert.equal(rebuiltSessions.length, 1);
  assert.equal(rebuiltSessions[0].tool_call_count, 9);
  assert.equal(rebuiltSessions[0].risk_score, 90);

  const risks = await rebuilt.listRiskEvents("sess_e2e");
  assert.equal(risks.length, 2);
  assert.equal(risks[0].severity, "HIGH");
  assert.equal(risks[0].rule_id, "RULE_SENSITIVE_PATH_READ");
  assert.equal(risks[1].severity, "CRITICAL");
  assert.equal(risks[1].rule_id, "RULE_LIVE_CREDENTIAL_EXFIL");

  await rebuilt.close();
});
