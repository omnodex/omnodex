// Validation: automatic background sync
//
// startBackgroundSync decides whether a session end should start a sync
// (settings, entitlement, throttle, lock) and spawns a detached child.
// runAutoSync runs the sync under a lock against a local HTTP server and
// records the outcome in auto-sync-state.json. With detection wired in, the
// child runs even where there is nothing to sync, and detection runs first.
//
// Run: node --test packages/sync-encryptor/test/auto-sync.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile, readFile, stat, utimes } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog } from "@omnodex/event-log";
import {
  startBackgroundSync,
  runAutoSync,
  backgroundPassDue,
  readAutoSyncState,
  readAutoSyncIntervalMs,
  includesSessionEnd,
  AUTO_SYNC_CHILD_ENV,
  DEFAULT_AUTO_SYNC_INTERVAL_SECONDS,
} from "../dist/auto-sync.js";

const CUSTOMER_ID = "cust_case";

async function writeJson(home, name, value) {
  await writeFile(path.join(home, name), JSON.stringify(value));
}

async function writeCredentials(home, extra = {}) {
  await writeJson(home, "stream-config.json", {
    api_token: "omx_test_case",
    passphrase: "case-passphrase",
    api_url: "http://127.0.0.1:1",
    ...extra,
  });
  await writeJson(home, "license-cache.json", {
    response: {
      customer_id: CUSTOMER_ID,
      tier: "hosted",
      features: ["encrypted_sync", "live_streaming"],
    },
    fetched_at: Date.now(),
  });
}

async function writeSession(home, sessionId) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  const now = new Date().toISOString();
  const base = {
    schema_version: 1,
    session_id: sessionId,
    occurred_at: now,
    recorded_at: now,
    interceptor: "claude-code-hook",
  };
  await log.append({
    ...base,
    event_id: randomUUID(),
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
  });
  await log.append({
    ...base,
    event_id: randomUUID(),
    event_type: "session.ended",
    duration_ms: 1000,
    status: "completed",
  });
  await log.close();
}

function recordingSpawn() {
  const calls = [];
  const fn = (command, args, env) => calls.push({ command, args, env });
  return { calls, fn };
}

/** Local stand-in for PUT /api/v1/sync/push. */
async function startSyncServer(status = 201) {
  const requests = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      requests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        bytes: Buffer.concat(chunks).length,
      });
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(
        status < 300
          ? JSON.stringify({ blob_id: "blob_case_1", received_at: new Date().toISOString(), payload_bytes: 1 })
          : JSON.stringify({ error: "server_error" }),
      );
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

describe("includesSessionEnd", () => {
  it("is true only when a session.ended event is present", () => {
    assert.equal(includesSessionEnd([{ event_type: "tool.invoked" }]), false);
    assert.equal(
      includesSessionEnd([{ event_type: "tool.completed" }, { event_type: "session.ended" }]),
      true,
    );
    assert.equal(includesSessionEnd([]), false);
  });
});

describe("readAutoSyncIntervalMs", () => {
  let home;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-autosync-interval-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  const DEFAULT_MS = DEFAULT_AUTO_SYNC_INTERVAL_SECONDS * 1000;

  it("falls back to the default when there is no config", async () => {
    assert.equal(await readAutoSyncIntervalMs(home), DEFAULT_MS);
  });

  it("uses a configured period", async () => {
    await writeJson(home, "stream-config.json", { auto_sync_interval_seconds: 120 });
    assert.equal(await readAutoSyncIntervalMs(home), 120_000);
  });

  it("ignores a period too short to be meant seriously", async () => {
    await writeJson(home, "stream-config.json", { auto_sync_interval_seconds: 1 });
    assert.equal(await readAutoSyncIntervalMs(home), DEFAULT_MS);
  });

  it("ignores values that are not usable numbers", async () => {
    for (const value of ["900", 0, -60, null, Number.NaN, Number.POSITIVE_INFINITY]) {
      await writeJson(home, "stream-config.json", { auto_sync_interval_seconds: value });
      assert.equal(await readAutoSyncIntervalMs(home), DEFAULT_MS, `value: ${String(value)}`);
    }
  });

  it("falls back to the default on unparseable config", async () => {
    await writeFile(path.join(home, "stream-config.json"), "{ not json");
    assert.equal(await readAutoSyncIntervalMs(home), DEFAULT_MS);
  });
});

describe("startBackgroundSync", () => {
  let home;
  let savedEnv;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-autosync-"));
    savedEnv = process.env.OMNODEX_AUTO_SYNC;
    delete process.env.OMNODEX_AUTO_SYNC;
  });

  afterEach(async () => {
    if (savedEnv === undefined) delete process.env.OMNODEX_AUTO_SYNC;
    else process.env.OMNODEX_AUTO_SYNC = savedEnv;
    await rm(home, { recursive: true, force: true });
  });

  it("spawns the given script detached with the child flag and records the attempt", async () => {
    await writeCredentials(home);
    const spawn = recordingSpawn();
    const now = Date.parse("2026-09-17T12:00:00Z");

    const decision = await startBackgroundSync({
      home, scriptPath: "/home/case/bin/claude-hook-shim.js", now, spawnFn: spawn.fn,
    });

    assert.equal(decision, "started");
    assert.equal(spawn.calls.length, 1);
    assert.equal(spawn.calls[0].command, process.execPath);
    assert.deepEqual(spawn.calls[0].args, ["/home/case/bin/claude-hook-shim.js"]);
    assert.equal(spawn.calls[0].env[AUTO_SYNC_CHILD_ENV], "1");
    const state = await readAutoSyncState(home);
    assert.equal(state.last_attempt_at, "2026-09-17T12:00:00.000Z");
  });

  it("does nothing without saved credentials", async () => {
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn }),
      "no-credentials",
    );
    assert.equal(spawn.calls.length, 0);
  });

  it("does nothing when the cached license lacks encrypted_sync", async () => {
    await writeCredentials(home);
    await writeJson(home, "license-cache.json", {
      response: { customer_id: CUSTOMER_ID, tier: "free", features: ["local_dashboard"] },
    });
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn }),
      "not-entitled",
    );
    assert.equal(spawn.calls.length, 0);
  });

  it("respects auto_sync: false in stream-config.json", async () => {
    await writeCredentials(home, { auto_sync: false });
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn }),
      "disabled",
    );
    assert.equal(spawn.calls.length, 0);
  });

  it("respects OMNODEX_AUTO_SYNC=0", async () => {
    await writeCredentials(home);
    process.env.OMNODEX_AUTO_SYNC = "0";
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn }),
      "disabled",
    );
    assert.equal(spawn.calls.length, 0);
  });

  it("throttles to the minimum interval", async () => {
    await writeCredentials(home, { auto_sync_min_interval_seconds: 120 });
    const spawn = recordingSpawn();
    const t0 = Date.parse("2026-09-17T12:00:00Z");

    assert.equal(await startBackgroundSync({ home, scriptPath: "s.js", now: t0, spawnFn: spawn.fn }), "started");
    assert.equal(await startBackgroundSync({ home, scriptPath: "s.js", now: t0 + 60_000, spawnFn: spawn.fn }), "too-soon");
    assert.equal(await startBackgroundSync({ home, scriptPath: "s.js", now: t0 + 121_000, spawnFn: spawn.fn }), "started");
    assert.equal(spawn.calls.length, 2);
  });

  it("skips while a fresh lock is held and ignores a stale one", async () => {
    await writeCredentials(home);
    const lockPath = path.join(home, "auto-sync.lock");
    await writeFile(lockPath, "{}");
    const spawn = recordingSpawn();

    assert.equal(
      await startBackgroundSync({ home, scriptPath: "s.js", spawnFn: spawn.fn }),
      "in-progress",
    );

    const old = new Date(Date.now() - 11 * 60 * 1000);
    await utimes(lockPath, old, old);
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "s.js", spawnFn: spawn.fn }),
      "started",
    );
  });
});

describe("runAutoSync", () => {
  let home;
  let server;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-autosync-run-"));
  });

  afterEach(async () => {
    await server?.close();
    server = undefined;
    await rm(home, { recursive: true, force: true });
  });

  it("pushes an encrypted blob, records success, and releases the lock", async () => {
    server = await startSyncServer();
    await writeCredentials(home, { api_url: server.url });
    await writeSession(home, "sess-case-1");

    const outcome = await runAutoSync(home);

    assert.equal(outcome, "synced");
    assert.equal(server.requests.length, 1);
    const push = server.requests[0];
    assert.equal(push.method, "PUT");
    assert.equal(push.url, "/api/v1/sync/push");
    assert.equal(push.headers.authorization, "Bearer omx_test_case");
    assert.deepEqual(JSON.parse(push.headers["x-omnodex-sessions"]), ["sess-case-1"]);
    assert.ok(push.bytes > 0);

    const state = await readAutoSyncState(home);
    assert.equal(state.last_blob_id, "blob_case_1");
    assert.equal(state.last_error, null);
    assert.ok(state.last_success_at);
    await assert.rejects(stat(path.join(home, "auto-sync.lock")));
    assert.ok((await readFile(path.join(home, "sync-salt.bin"))).length > 0);
  });

  it("records the error and releases the lock when the push fails", async () => {
    server = await startSyncServer(500);
    await writeCredentials(home, { api_url: server.url });
    await writeSession(home, "sess-case-2");

    const outcome = await runAutoSync(home);

    assert.equal(outcome, "failed");
    const state = await readAutoSyncState(home);
    assert.match(state.last_error, /HTTP 500/);
    assert.equal(state.last_success_at, undefined);
    await assert.rejects(stat(path.join(home, "auto-sync.lock")));
  });

  it("does not run while another sync holds the lock", async () => {
    server = await startSyncServer();
    await writeCredentials(home, { api_url: server.url });
    await writeFile(path.join(home, "auto-sync.lock"), "{}");

    assert.equal(await runAutoSync(home), "in-progress");
    assert.equal(server.requests.length, 0);
    // The other sync's lock is left in place.
    await stat(path.join(home, "auto-sync.lock"));
  });
});

describe("startBackgroundSync with detection", () => {
  let home;
  let saved;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-autosync-detect-"));
    saved = { sync: process.env.OMNODEX_AUTO_SYNC, detect: process.env.OMNODEX_AUTO_DETECT };
    delete process.env.OMNODEX_AUTO_SYNC;
    delete process.env.OMNODEX_AUTO_DETECT;
  });

  afterEach(async () => {
    for (const [name, value] of [["OMNODEX_AUTO_SYNC", saved.sync], ["OMNODEX_AUTO_DETECT", saved.detect]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(home, { recursive: true, force: true });
  });

  it("starts the child without credentials, so a free install is analyzed", async () => {
    const spawn = recordingSpawn();
    const decision = await startBackgroundSync({
      home, scriptPath: "shim.js", spawnFn: spawn.fn, detect: true,
    });
    assert.equal(decision, "started");
    assert.equal(spawn.calls.length, 1);
    assert.equal(spawn.calls[0].env[AUTO_SYNC_CHILD_ENV], "1");
  });

  it("starts the child when the license lacks encrypted_sync", async () => {
    await writeCredentials(home);
    await writeJson(home, "license-cache.json", {
      response: { customer_id: CUSTOMER_ID, tier: "free", features: ["local_dashboard"] },
    });
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn, detect: true }),
      "started",
    );
  });

  it("starts the child when sync is turned off", async () => {
    await writeCredentials(home, { auto_sync: false });
    process.env.OMNODEX_AUTO_SYNC = "0";
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn, detect: true }),
      "started",
    );
  });

  it("falls back to the sync decision when detection is turned off", async () => {
    process.env.OMNODEX_AUTO_DETECT = "0";
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "shim.js", spawnFn: spawn.fn, detect: true }),
      "no-credentials",
    );
    assert.equal(spawn.calls.length, 0);
  });

  it("throttles to the default minimum interval without credentials", async () => {
    const spawn = recordingSpawn();
    const t0 = Date.parse("2026-09-21T12:00:00Z");
    const start = (now) =>
      startBackgroundSync({ home, scriptPath: "s.js", now, spawnFn: spawn.fn, detect: true });

    assert.equal(await start(t0), "started");
    assert.equal(await start(t0 + 30_000), "too-soon");
    assert.equal(await start(t0 + 61_000), "started");
    assert.equal(spawn.calls.length, 2);
  });
});

describe("backgroundPassDue", () => {
  let home;
  let saved;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-pass-due-"));
    saved = { sync: process.env.OMNODEX_AUTO_SYNC, detect: process.env.OMNODEX_AUTO_DETECT };
    delete process.env.OMNODEX_AUTO_SYNC;
    delete process.env.OMNODEX_AUTO_DETECT;
  });

  afterEach(async () => {
    for (const [name, value] of [["OMNODEX_AUTO_SYNC", saved.sync], ["OMNODEX_AUTO_DETECT", saved.detect]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(home, { recursive: true, force: true });
  });

  it("is due when there has never been a pass", async () => {
    assert.equal(await backgroundPassDue(home), true);
  });

  it("is not due within the timer period and is due after it", async () => {
    const t0 = Date.parse("2026-09-21T12:00:00Z");
    await writeJson(home, "auto-sync-state.json", { last_attempt_at: new Date(t0).toISOString() });
    const period = DEFAULT_AUTO_SYNC_INTERVAL_SECONDS * 1000;

    assert.equal(await backgroundPassDue(home, t0 + period - 1000), false);
    assert.equal(await backgroundPassDue(home, t0 + period), true);
  });

  it("follows a configured timer period", async () => {
    const t0 = Date.parse("2026-09-21T12:00:00Z");
    await writeJson(home, "auto-sync-state.json", { last_attempt_at: new Date(t0).toISOString() });
    await writeJson(home, "stream-config.json", { auto_sync_interval_seconds: 120 });

    assert.equal(await backgroundPassDue(home, t0 + 119_000), false);
    assert.equal(await backgroundPassDue(home, t0 + 120_000), true);
  });

  it("is due after the minimum interval when a throttled pass is pending", async () => {
    const t0 = Date.parse("2026-09-21T12:00:00Z");
    const spawn = recordingSpawn();
    const start = (now) =>
      startBackgroundSync({ home, scriptPath: "s.js", now, spawnFn: spawn.fn, detect: true });

    assert.equal(await start(t0), "started");
    // A session ends 20 seconds later: throttled, so its tail is unanalyzed.
    assert.equal(await start(t0 + 20_000), "too-soon");
    assert.equal((await readAutoSyncState(home)).pass_pending, true);

    assert.equal(await backgroundPassDue(home, t0 + 30_000), false);
    assert.equal(await backgroundPassDue(home, t0 + 61_000), true);

    assert.equal(await start(t0 + 61_000), "started");
    assert.equal((await readAutoSyncState(home)).pass_pending, false);
    assert.equal(await backgroundPassDue(home, t0 + 122_000), false);
  });

  it("marks a pass pending when one is already running", async () => {
    await writeFile(path.join(home, "auto-sync.lock"), "{}");
    const spawn = recordingSpawn();
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "s.js", spawnFn: spawn.fn, detect: true }),
      "in-progress",
    );
    assert.equal((await readAutoSyncState(home)).pass_pending, true);
  });

  it("does not mark a pass pending for a sync-only request", async () => {
    await writeCredentials(home, { auto_sync_min_interval_seconds: 120 });
    const t0 = Date.parse("2026-09-21T12:00:00Z");
    const spawn = recordingSpawn();
    await startBackgroundSync({ home, scriptPath: "s.js", now: t0, spawnFn: spawn.fn });
    assert.equal(
      await startBackgroundSync({ home, scriptPath: "s.js", now: t0 + 10_000, spawnFn: spawn.fn }),
      "too-soon",
    );
    assert.equal((await readAutoSyncState(home)).pass_pending, false);
  });

  it("is never due when both detection and sync are turned off", async () => {
    process.env.OMNODEX_AUTO_SYNC = "0";
    process.env.OMNODEX_AUTO_DETECT = "0";
    assert.equal(await backgroundPassDue(home), false);
  });
});

describe("runAutoSync with detection", () => {
  let home;
  let server;
  let saved;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-autosync-run-detect-"));
    saved = { sync: process.env.OMNODEX_AUTO_SYNC, detect: process.env.OMNODEX_AUTO_DETECT };
    delete process.env.OMNODEX_AUTO_SYNC;
    delete process.env.OMNODEX_AUTO_DETECT;
  });

  afterEach(async () => {
    await server?.close();
    server = undefined;
    for (const [name, value] of [["OMNODEX_AUTO_SYNC", saved.sync], ["OMNODEX_AUTO_DETECT", saved.detect]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(home, { recursive: true, force: true });
  });

  const finding = { event_type: "risk.detected", event_id: "evt-case-risk", session_id: "sess-case" };

  function recordingPush() {
    const pushed = [];
    return { pushed, fn: async (events) => { pushed.push(...events); return true; } };
  }

  it("runs detection for a free install, pushes nothing to sync, and records it", async () => {
    let calls = 0;
    const push = recordingPush();

    const outcome = await runAutoSync(home, {
      detect: async () => { calls++; return [finding]; },
      pushFn: push.fn,
    });

    assert.equal(outcome, "no-credentials");
    assert.equal(calls, 1);
    assert.deepEqual(push.pushed, [finding]);
    const state = await readAutoSyncState(home);
    assert.equal(state.last_detect_findings, 1);
    assert.equal(state.last_detect_error, null);
    assert.ok(state.last_detect_at);
    await assert.rejects(stat(path.join(home, "auto-sync.lock")));
  });

  it("does not push when detection finds nothing", async () => {
    const push = recordingPush();
    await runAutoSync(home, { detect: async () => [], pushFn: push.fn });
    assert.equal(push.pushed.length, 0);
    assert.equal((await readAutoSyncState(home)).last_detect_findings, 0);
  });

  it("detects before it syncs for an entitled install", async () => {
    server = await startSyncServer();
    await writeCredentials(home, { api_url: server.url });
    await writeSession(home, "sess-case-3");
    const order = [];

    const outcome = await runAutoSync(home, {
      detect: async () => { order.push(`detect:${server.requests.length}`); return []; },
      pushFn: async () => true,
    });

    assert.equal(outcome, "synced");
    assert.deepEqual(order, ["detect:0"]);
    assert.equal(server.requests.length, 1);
  });

  it("still syncs when detection throws, and records the error", async () => {
    server = await startSyncServer();
    await writeCredentials(home, { api_url: server.url });
    await writeSession(home, "sess-case-4");

    const outcome = await runAutoSync(home, {
      detect: async () => { throw new Error("rule engine exploded"); },
    });

    assert.equal(outcome, "synced");
    assert.equal(server.requests.length, 1);
    assert.match((await readAutoSyncState(home)).last_detect_error, /rule engine exploded/);
  });

  it("skips the sync but still detects when sync is turned off", async () => {
    server = await startSyncServer();
    await writeCredentials(home, { api_url: server.url, auto_sync: false });
    let calls = 0;

    const outcome = await runAutoSync(home, {
      detect: async () => { calls++; return []; },
      pushFn: async () => true,
    });

    assert.equal(outcome, "disabled");
    assert.equal(calls, 1);
    assert.equal(server.requests.length, 0);
  });

  it("skips detection when OMNODEX_AUTO_DETECT=0", async () => {
    process.env.OMNODEX_AUTO_DETECT = "0";
    let calls = 0;
    await runAutoSync(home, { detect: async () => { calls++; return []; } });
    assert.equal(calls, 0);
    assert.equal((await readAutoSyncState(home)).last_detect_at, undefined);
  });
});
