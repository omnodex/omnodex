// Live push gate: clients stop pushing while no dashboard is watching.
//
// The relay answers a live push with `live: false` when no dashboard is
// connected. pushEventsToCloud (hook shims, the proxy) and StreamingTransport
// (the CLI dashboard) then skip pushes for a back-off window that doubles up
// to LIVE_BACKOFF_MAX_MS, and resume on the first push that reports a viewer.
//
// Run: node --test packages/sync-encryptor/test/live-gate.test.mjs

import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { webcrypto } from "node:crypto";
import {
  nextLiveGate,
  liveGateOpen,
  livePushAllowed,
  recordLivePush,
  LIVE_BACKOFF_MIN_MS,
  LIVE_BACKOFF_MAX_MS,
} from "../dist/live-gate.js";
import { pushEventsToCloud } from "../dist/shim-push.js";
import { StreamingTransport } from "../dist/streaming-transport.js";

const HOSTED = {
  customer_id: "cust_case",
  tier: "hosted",
  features: ["encrypted_sync", "live_streaming"],
  ttl_seconds: 86400,
};

/** Stand-in for the license and live-event endpoints; `live` is switchable. */
async function startApi() {
  const api = { live: false, status: 200, pushes: 0 };
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/api/v1/license/validate") {
        res.end(JSON.stringify(HOSTED));
        return;
      }
      if (req.url === "/api/v1/sync/events") {
        api.pushes++;
        res.statusCode = api.status;
        res.end(JSON.stringify({ accepted: 1, live: api.live, viewers: api.live ? 1 : 0 }));
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  api.url = `http://127.0.0.1:${server.address().port}`;
  api.close = () => new Promise((resolve) => server.close(resolve));
  return api;
}

function event(id) {
  return {
    schema_version: 1,
    event_id: id,
    session_id: "sess_case_gate",
    occurred_at: "2026-09-22T00:00:00.000Z",
    recorded_at: "2026-09-22T00:00:00.000Z",
    interceptor: "hooks",
    event_type: "tool.invoked",
    tool_call_id: id,
    tool_name: "Bash",
    parameters: {},
  };
}

describe("gate arithmetic", () => {
  it("backs off from the minimum, doubles to the cap, and resets on a viewer", () => {
    let s = nextLiveGate(null, "unwatched", 0);
    assert.deepEqual(s, { paused_until: LIVE_BACKOFF_MIN_MS, backoff_ms: LIVE_BACKOFF_MIN_MS });
    assert.equal(liveGateOpen(s, LIVE_BACKOFF_MIN_MS - 1), false);
    assert.equal(liveGateOpen(s, LIVE_BACKOFF_MIN_MS), true);

    const windows = [];
    for (let i = 0; i < 6; i++) {
      s = nextLiveGate(s, i % 2 ? "failed" : "unwatched", 0);
      windows.push(s.backoff_ms);
    }
    assert.deepEqual(windows, [120_000, 240_000, 300_000, 300_000, 300_000, 300_000]);
    assert.equal(LIVE_BACKOFF_MAX_MS, 300_000);

    assert.equal(nextLiveGate(s, "watched", 0), null);
  });
});

describe("shared gate file", () => {
  let home;
  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omx-live-gate-"));
  });
  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("is open with no file, closes on unwatched, and is removed by a viewer", async () => {
    assert.equal(await livePushAllowed(home, 0), true);
    await recordLivePush(home, "unwatched", 0);
    assert.equal(await livePushAllowed(home, 1), false);
    assert.equal(await livePushAllowed(home, LIVE_BACKOFF_MIN_MS), true);
    await recordLivePush(home, "watched", LIVE_BACKOFF_MIN_MS);
    await assert.rejects(readFile(path.join(home, "live-push-state.json")));
  });

  it("treats a garbled file as open", async () => {
    await writeFile(path.join(home, "live-push-state.json"), "{not json");
    assert.equal(await livePushAllowed(home, 0), true);
  });
});

describe("pushEventsToCloud behind the gate", () => {
  let home;
  let api;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omx-live-push-"));
    api = await startApi();
    await writeFile(
      path.join(home, "stream-config.json"),
      JSON.stringify({ api_token: "omx_test_case", passphrase: "case-passphrase", api_url: api.url }),
    );
  });
  afterEach(async () => {
    mock.timers.reset();
    await api.close();
    await rm(home, { recursive: true, force: true });
  });

  it("a 200-tool-call session with no dashboard costs a handful of pushes, then goes live when one opens", async () => {
    // Warm the streaming-key cache and license at real time, then freeze the clock.
    api.live = true;
    assert.equal(await pushEventsToCloud([event("warm")], home, 5000), true);
    api.live = false;
    api.pushes = 0;

    mock.timers.enable({ apis: ["Date"], now: 1_000_000 });
    // 200 tool calls over 30 minutes; each fires a pre and a post hook, and
    // each hook is its own shim process calling pushEventsToCloud once.
    const calls = 200;
    const spacingMs = (30 * 60 * 1000) / calls;
    for (let i = 0; i < calls; i++) {
      await pushEventsToCloud([event(`pre_${i}`)], home, 5000);
      await pushEventsToCloud([event(`post_${i}`)], home, 5000);
      mock.timers.tick(spacingMs);
    }
    // Before the gate this was 400 pushes, one per hook.
    const unwatchedPushes = api.pushes;
    assert.ok(unwatchedPushes <= 8, `expected at most 8 pushes, got ${unwatchedPushes}`);
    assert.ok(unwatchedPushes >= 2, "probes must keep going out");

    // A dashboard opens: the next probe finds it, and every event after that is live.
    api.live = true;
    api.pushes = 0;
    let firstLiveAt = null;
    for (let i = 0; i < 100; i++) {
      const before = api.pushes;
      await pushEventsToCloud([event(`live_${i}`)], home, 5000);
      if (firstLiveAt === null && api.pushes > before) firstLiveAt = i;
      mock.timers.tick(spacingMs);
    }
    assert.ok(firstLiveAt !== null && firstLiveAt * spacingMs <= LIVE_BACKOFF_MAX_MS);
    assert.equal(api.pushes, 100 - firstLiveAt);
  });

  it("backs off after a failed push too", async () => {
    api.status = 503;
    await pushEventsToCloud([event("a")], home, 5000);
    await pushEventsToCloud([event("b")], home, 5000);
    assert.equal(api.pushes, 1);
  });

  it("keeps pushing every event against a server that never reports live", async () => {
    // An older relay: no `live` field at all.
    api.live = undefined;
    for (let i = 0; i < 3; i++) await pushEventsToCloud([event(`e${i}`)], home, 5000);
    assert.equal(api.pushes, 3);
  });
});

describe("StreamingTransport behind the gate", () => {
  let api;
  beforeEach(async () => {
    api = await startApi();
  });
  afterEach(async () => {
    await api.close();
  });

  it("drops batches while unwatched and batches a burst into one request", async () => {
    const key = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const t = new StreamingTransport({ apiBase: api.url, apiToken: "omx_test_case", keyId: "abcd1234", streamingKey: key });

    for (let i = 0; i < 5; i++) await t.push(event(`burst_${i}`));
    await t.flush();
    assert.equal(api.pushes, 1, "a burst shares one request");

    for (let i = 0; i < 5; i++) await t.push(event(`quiet_${i}`));
    await t.flush();
    assert.equal(api.pushes, 1, "no pushes while no one watches");
    await t.stop();
  });
});
