// Capture pauses on the local dashboard: markers fold into one row per
// pause, the snapshot carries them, and the timeline shows where each began
// and ended, so a pause reads as a gap rather than as missing data.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore } from "../../projection/dist/index.js";
import { DashboardServer } from "../dist/dashboard-server.js";
import {
  ALL_SESSIONS,
  pauseRows,
  selectView,
  timelineEntries,
} from "../dist/dashboard-model/index.js";

const CONTROL = "omnodex-capture-control";

function marker(type, n, at, body) {
  return {
    schema_version: 1, event_id: `m${n}`, session_id: CONTROL, occurred_at: at, recorded_at: at,
    interceptor: "analyzer", event_type: type, ...body,
  };
}

const PAUSED = marker("capture.paused", 1, "2026-06-02T12:00:00.000Z", {
  pause_id: "p1", kind: "sync", until: "2026-06-02T13:00:00.000Z", machine_label: "case-laptop",
});
const EXPIRED_A = marker("capture.resumed", 2, "2026-06-02T13:00:00.000Z", {
  pause_id: "p1", kind: "sync", paused_at: "2026-06-02T12:00:00.000Z", reason: "expired",
});
// A second process noticed the same expiry a little later.
const EXPIRED_B = marker("capture.resumed", 3, "2026-06-02T13:00:05.000Z", {
  pause_id: "p1", kind: "sync", paused_at: "2026-06-02T12:00:00.000Z", reason: "command",
});
const OPEN = marker("capture.paused", 4, "2026-06-02T15:00:00.000Z", {
  pause_id: "p2", kind: "record", until: null,
});

test("markers fold into one row per pause; the earliest end wins", () => {
  const rows = pauseRows([EXPIRED_B, PAUSED, EXPIRED_A, OPEN]);
  assert.deepEqual(rows, [
    {
      pause_id: "p1", kind: "sync", paused_at: "2026-06-02T12:00:00.000Z", resumed_at: "2026-06-02T13:00:00.000Z",
      until: "2026-06-02T13:00:00.000Z", reason: "expired", machine_label: "case-laptop",
    },
    {
      pause_id: "p2", kind: "record", paused_at: "2026-06-02T15:00:00.000Z", resumed_at: null,
      until: null, reason: null, machine_label: null,
    },
  ]);
});

function session(id, started, ended) {
  return {
    session_id: id, user: "case", project_path: `/home/case/${id}`, mcp_servers: [], interceptor: "claude-code-hook",
    started_at: started, ended_at: ended, duration_ms: null, status: "completed", tool_call_count: 1,
    file_read_count: 0, file_write_count: 0, risk_score: 0, last_event_at: ended ?? started,
  };
}

function callRow(sid, at) {
  return {
    tool_call_id: `${sid}-c`, session_id: sid, tool_name: "Read", mcp_server: "builtin", parameters_json: "{}",
    started_at: at, ended_at: at, duration_ms: 1, status: "success", response_bytes: 1, error_message: null,
  };
}

test("the timeline places pause start and end entries among the calls", () => {
  const snapshot = {
    sessions: [session("a", "2026-06-02T11:00:00.000Z", "2026-06-02T14:00:00.000Z"),
      session("b", "2026-06-02T16:00:00.000Z", "2026-06-02T16:30:00.000Z")],
    tool_calls: { a: [callRow("a", "2026-06-02T12:30:00.000Z")], b: [callRow("b", "2026-06-02T16:10:00.000Z")] },
    file_events: {}, risk_events: {},
    pauses: pauseRows([PAUSED, EXPIRED_A, OPEN]),
  };
  const all = selectView(snapshot, ALL_SESSIONS);
  assert.equal(all.pauses.length, 2);
  const kinds = timelineEntries(all, false).map((e) => e.kind);
  assert.deepEqual(kinds, ["pause-start", "call", "pause-end", "pause-start", "call"]);

  // One session shows only the pauses that overlap it.
  assert.deepEqual(selectView(snapshot, "a").pauses.map((p) => p.pause_id), ["p1"]);
  assert.deepEqual(selectView(snapshot, "b").pauses.map((p) => p.pause_id), ["p2"]);
});

test("the snapshot API carries the pauses", async (t) => {
  const assetsDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-dash-pauses-"));
  await fs.writeFile(path.join(assetsDir, "dashboard.html"), "<!doctype html><title>t</title>");
  const server = new DashboardServer({
    store: new InMemoryReadModelStore(), port: 0, assetsDir, pauses: async () => pauseRows([PAUSED]),
  });
  await server.ready;
  t.after(async () => {
    server.close();
    await fs.rm(assetsDir, { recursive: true, force: true });
  });
  const body = await new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port: server.port, path: "/api/snapshot", headers: { host: `localhost:${server.port}` } }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
  const snapshot = JSON.parse(body);
  assert.deepEqual(snapshot.pauses.map((p) => p.pause_id), ["p1"]);
  assert.ok(Array.isArray(snapshot.sessions));
});
