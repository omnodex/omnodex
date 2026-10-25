// Validation: monitoring heartbeat
//
// The background pass sends the hosted service a metadata-only heartbeat:
// per platform, what the config check last found, plus pause state, open
// sessions, the CLI version and the unexplained-change count. Every 15
// minutes, sooner when the state changes, never more than once a minute.
// It flows under a sync pause. Offline is silent: no error, one debug line
// per stretch, one catch-up heartbeat on return. A refusal waits a day.
//
// Every machine is a scratch directory; nothing reads the real home, and
// every request goes to a fake fetch.
//
// Run: node --test packages/sync-encryptor/test/monitoring-heartbeat.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, utimes, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog, startPause } from "@omnodex/event-log";
import { CAPTURE_CONTROL_SESSION_ID, SCHEMA_VERSION } from "@omnodex/shared";
import {
  buildHeartbeat,
  sendMonitoringHeartbeat,
  readHeartbeatState,
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_MIN_GAP_MS,
  SESSION_OPEN_WINDOW_MS,
} from "../dist/monitoring-heartbeat.js";
import { runAutoSync, sendHeartbeat } from "../dist/auto-sync.js";

const PROJECT = "/home/case/repo";

async function scratch() {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-heartbeat-"));
  return { home, done: () => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }) };
}

/** The config check's last state, as monitoring-check.json keeps it. */
async function writeSlots(home, slots) {
  const at = new Date().toISOString();
  await writeFile(path.join(home, "monitoring-check.json"), JSON.stringify({ first_run_at: at, last_run_at: at, slots }));
}

async function writeEvents(home, sessionId, events) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  try {
    for (const e of events) {
      await log.append({
        schema_version: SCHEMA_VERSION,
        event_id: randomUUID(),
        session_id: sessionId,
        occurred_at: e.occurred_at ?? new Date().toISOString(),
        recorded_at: new Date().toISOString(),
        ...e,
      });
    }
  } finally {
    await log.close();
  }
  return path.join(home, "event-log", "sessions", `${sessionId}.jsonl`);
}

/** A fetch that records each request and answers with `status`, or throws. */
function fakeFetch(answer = 200) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    const status = typeof answer === "function" ? answer(calls.length) : answer;
    if (status === "throw") throw new Error("connect ECONNREFUSED");
    return new Response("{}", { status });
  };
  return { fn, calls };
}

const send = (home, fetch, now, env = {}) =>
  sendMonitoringHeartbeat(home, { apiUrl: "https://api.example.test/", apiToken: "omx_case", fetchFn: fetch.fn, now, env });

describe("buildHeartbeat", () => {
  it("summarizes each platform from the config check's last state, worst first", async () => {
    const m = await scratch();
    try {
      await writeSlots(m.home, {
        [`claude-code|hooks|project|${PROJECT}`]: "ok",
        "claude-code|hooks|user|": "hooks_missing",
        "claude-code|plugin|user|": "plugin_disabled",
        [`codex|hooks|project|${PROJECT}`]: "hooks_disabled",
        "antigravity|hooks|project|/home/case/gone": "project_gone",
        [`antigravity|mcp|project|${PROJECT}`]: "ok",
      });
      const h = await buildHeartbeat(m.home);
      assert.deepEqual(h.platforms, [
        { platform: "antigravity", hooks: "none", plugin: "none", mcp: "ok", installs: 1, session_open: false },
        { platform: "claude-code", hooks: "missing", plugin: "disabled", mcp: "none", installs: 3, session_open: false },
        { platform: "codex", hooks: "disabled", plugin: "none", mcp: "none", installs: 1, session_open: false },
      ]);
      assert.equal(h.record_paused, false);
      assert.equal(h.sync_paused, false);
      assert.equal(h.catch_up, false);
      assert.match(h.cli_version, /^\d+\.\d+\.\d+/);
    } finally {
      await m.done();
    }
  });

  it("carries no paths or content", async () => {
    const m = await scratch();
    try {
      await writeSlots(m.home, { [`claude-code|hooks|project|${PROJECT}`]: "hooks_missing" });
      await writeEvents(m.home, "s-content", [{
        event_type: "tool.invoked", interceptor: "claude-code-hook", tool_name: "Read", parameters: { file_path: `${PROJECT}/secret.txt` },
      }]);
      const text = JSON.stringify(await buildHeartbeat(m.home));
      assert.doesNotMatch(text, /home\/case|secret|Read/);
      assert.ok(!text.includes(m.home));
    } finally {
      await m.done();
    }
  });

  it("counts a session as open while it is recent and has not ended", async () => {
    const m = await scratch();
    try {
      await writeSlots(m.home, { "claude-code|hooks|user|": "ok", "codex|hooks|user|": "ok" });
      await writeEvents(m.home, "s-open", [{ event_type: "session.started", interceptor: "claude-code-hook" }]);
      await writeEvents(m.home, "s-ended", [
        { event_type: "session.started", interceptor: "codex-hook" },
        { event_type: "session.ended", interceptor: "codex-hook" },
      ]);
      const stale = await writeEvents(m.home, "s-stale", [{ event_type: "session.started", interceptor: "codex-hook" }]);
      const old = new Date(Date.now() - SESSION_OPEN_WINDOW_MS - 60_000);
      await utimes(stale, old, old);
      const h = await buildHeartbeat(m.home);
      assert.equal(h.session_open, true);
      assert.deepEqual(h.platforms.map((p) => [p.platform, p.session_open]), [["claude-code", true], ["codex", false]]);
    } finally {
      await m.done();
    }
  });

  it("counts a proxy-only session as open without crediting a platform's hooks", async () => {
    const m = await scratch();
    try {
      await writeSlots(m.home, { "claude-code|hooks|user|": "ok" });
      await writeEvents(m.home, "s-proxy", [{ event_type: "tool.invoked", interceptor: "mcp-proxy", tool_name: "x" }]);
      await writeEvents(m.home, CAPTURE_CONTROL_SESSION_ID, [{ event_type: "capture.paused", interceptor: "analyzer" }]);
      const h = await buildHeartbeat(m.home);
      assert.equal(h.session_open, true);
      assert.equal(h.platforms[0].session_open, false);
    } finally {
      await m.done();
    }
  });

  it("counts unexplained changes recorded after the given time only", async () => {
    const m = await scratch();
    try {
      await writeEvents(m.home, CAPTURE_CONTROL_SESSION_ID, [
        { event_type: "monitoring.unexplained_change", interceptor: "analyzer", occurred_at: "2026-10-01T00:00:00.000Z" },
        { event_type: "monitoring.unexplained_change", interceptor: "analyzer", occurred_at: "2026-10-02T00:00:00.000Z" },
        { event_type: "risk.detected", interceptor: "analyzer", occurred_at: "2026-10-02T00:00:00.000Z" },
      ]);
      assert.equal((await buildHeartbeat(m.home)).unexplained_changes, 2);
      assert.equal((await buildHeartbeat(m.home, { since: "2026-10-01T12:00:00.000Z" })).unexplained_changes, 1);
    } finally {
      await m.done();
    }
  });
});

describe("sendMonitoringHeartbeat", () => {
  it("posts the heartbeat with the token and machine id", async () => {
    const m = await scratch();
    try {
      await writeSlots(m.home, { "claude-code|hooks|user|": "ok" });
      const fetch = fakeFetch();
      assert.equal(await send(m.home, fetch), "sent");
      assert.equal(fetch.calls.length, 1);
      const { url, init, body } = fetch.calls[0];
      assert.equal(url, "https://api.example.test/api/v1/sync/monitoring/heartbeat");
      assert.equal(init.method, "POST");
      assert.equal(init.headers.Authorization, "Bearer omx_case");
      assert.match(init.headers["X-Omnodex-Machine-Id"], /^[0-9a-f]{16}$/);
      assert.equal(body.platforms[0].hooks, "ok");
      // Small enough to send every 15 minutes from every machine.
      assert.ok(init.body.length < 1024, `${init.body.length} bytes`);
    } finally {
      await m.done();
    }
  });

  it("goes out every 15 minutes, sooner when the state changes, never within a minute", async () => {
    const m = await scratch();
    try {
      await writeSlots(m.home, { "claude-code|hooks|user|": "ok" });
      const fetch = fakeFetch();
      const t0 = Date.parse("2026-10-25T12:00:00.000Z");
      const t1 = t0 + 5 * 60_000;
      assert.equal(await send(m.home, fetch, t0), "sent");
      assert.equal(await send(m.home, fetch, t1), "not-due");
      await writeSlots(m.home, { "claude-code|hooks|user|": "hooks_missing" });
      assert.equal(await send(m.home, fetch, t1), "sent");
      assert.equal(fetch.calls[1].body.platforms[0].hooks, "missing");
      await writeSlots(m.home, { "claude-code|hooks|user|": "hooks_disabled" });
      assert.equal(await send(m.home, fetch, t1 + HEARTBEAT_MIN_GAP_MS - 1), "not-due");
      assert.equal(await send(m.home, fetch, t1 + HEARTBEAT_MIN_GAP_MS), "sent");
      const t2 = t1 + HEARTBEAT_MIN_GAP_MS;
      assert.equal(await send(m.home, fetch, t2 + HEARTBEAT_INTERVAL_MS - 1), "not-due");
      assert.equal(await send(m.home, fetch, t2 + HEARTBEAT_INTERVAL_MS), "sent");
      assert.equal(fetch.calls.length, 4);
    } finally {
      await m.done();
    }
  });

  it("keeps going under a sync pause and reports it", async () => {
    const m = await scratch();
    try {
      await startPause(m.home, "sync", { untilMs: null });
      const fetch = fakeFetch();
      assert.equal(await send(m.home, fetch), "sent");
      assert.equal(fetch.calls[0].body.sync_paused, true);
      assert.equal(fetch.calls[0].body.record_paused, false);
    } finally {
      await m.done();
    }
  });

  it("stays silent offline and sends one catch-up heartbeat on return", async () => {
    const m = await scratch();
    try {
      const env = { OMNODEX_DEBUG: "1" };
      const fetch = fakeFetch((n) => (n <= 3 ? "throw" : 200));
      const t0 = Date.parse("2026-10-25T12:00:00.000Z");
      for (let i = 0; i < 3; i++) {
        assert.equal(await send(m.home, fetch, t0 + i * HEARTBEAT_INTERVAL_MS, env), "offline");
      }
      // Not retried before the next heartbeat is due.
      assert.equal(await send(m.home, fetch, t0 + 2 * HEARTBEAT_INTERVAL_MS + 60_000, env), "not-due");
      const log = await readFile(path.join(m.home, "launcher.log"), "utf8");
      assert.equal(log.trim().split("\n").length, 1, log);
      assert.match(log, /\[heartbeat\] heartbeat not delivered/);

      assert.equal(await send(m.home, fetch, t0 + 3 * HEARTBEAT_INTERVAL_MS, env), "sent");
      assert.equal(fetch.calls.length, 4);
      assert.equal(fetch.calls[3].body.catch_up, true);
      assert.equal(fetch.calls[3].body.offline_since, new Date(t0).toISOString());

      assert.equal(await send(m.home, fetch, t0 + 4 * HEARTBEAT_INTERVAL_MS, env), "sent");
      assert.equal(fetch.calls[4].body.catch_up, false);
      assert.equal(fetch.calls[4].body.offline_since, undefined);
      assert.equal((await readHeartbeatState(m.home)).offline_since, null);
    } finally {
      await m.done();
    }
  });

  it("writes no debug line without OMNODEX_DEBUG, and treats a server error as offline", async () => {
    const m = await scratch();
    try {
      assert.equal(await send(m.home, fakeFetch(503), undefined, {}), "offline");
      await assert.rejects(readFile(path.join(m.home, "launcher.log"), "utf8"));
    } finally {
      await m.done();
    }
  });

  it("waits a day after a refusal", async () => {
    const m = await scratch();
    try {
      const fetch = fakeFetch(403);
      const t0 = Date.parse("2026-10-25T12:00:00.000Z");
      assert.equal(await send(m.home, fetch, t0), "refused");
      assert.equal(await send(m.home, fetch, t0 + HEARTBEAT_INTERVAL_MS), "waiting");
      assert.equal(await send(m.home, fetch, t0 + 24 * 60 * 60_000), "refused");
      assert.equal(fetch.calls.length, 2);
    } finally {
      await m.done();
    }
  });

  it("reports unexplained changes since the last heartbeat that got through", async () => {
    const m = await scratch();
    try {
      const fetch = fakeFetch((n) => (n === 2 ? "throw" : 200));
      const t0 = Date.parse("2026-10-25T12:00:00.000Z");
      await send(m.home, fetch, t0);
      await writeEvents(m.home, CAPTURE_CONTROL_SESSION_ID, [
        { event_type: "monitoring.unexplained_change", interceptor: "analyzer", occurred_at: new Date(t0 + 60_000).toISOString() },
      ]);
      assert.equal(await send(m.home, fetch, t0 + 2 * 60_000), "offline");
      assert.equal(await send(m.home, fetch, t0 + 2 * 60_000 + HEARTBEAT_INTERVAL_MS), "sent");
      assert.deepEqual(fetch.calls.map((c) => c.body.unexplained_changes), [0, 1, 1]);
    } finally {
      await m.done();
    }
  });
});

describe("background pass", () => {
  it("sends nothing without an API token", async () => {
    const m = await scratch();
    try {
      const fetch = fakeFetch();
      assert.equal(await sendHeartbeat(m.home, fetch.fn), "no-credentials");
      assert.equal(fetch.calls.length, 0);
    } finally {
      await m.done();
    }
  });

  it("uses the stream's token and API address", async () => {
    const m = await scratch();
    try {
      await writeFile(path.join(m.home, "stream-config.json"), JSON.stringify({ api_token: "omx_case", api_url: "https://api.example.test" }));
      const fetch = fakeFetch();
      assert.equal(await sendHeartbeat(m.home, fetch.fn), "sent");
      assert.equal(fetch.calls[0].url, "https://api.example.test/api/v1/sync/monitoring/heartbeat");
    } finally {
      await m.done();
    }
  });

  it("sends the heartbeat after the config check, with sync turned off", async () => {
    const m = await scratch();
    const before = process.env.OMNODEX_AUTO_SYNC;
    process.env.OMNODEX_AUTO_SYNC = "0";
    try {
      await mkdir(m.home, { recursive: true });
      const order = [];
      const outcome = await runAutoSync(m.home, {
        refreshLicense: async () => {},
        checkMonitoring: async () => { order.push("check"); },
        sendHeartbeat: async () => { order.push("heartbeat"); },
        submitUsage: async () => {},
        submitSignals: async () => {},
      });
      assert.equal(outcome, "disabled");
      assert.deepEqual(order, ["check", "heartbeat"]);
    } finally {
      if (before === undefined) delete process.env.OMNODEX_AUTO_SYNC;
      else process.env.OMNODEX_AUTO_SYNC = before;
      await m.done();
    }
  });
});
