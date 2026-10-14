// Validation: the client honors the cloud's minimum gap between syncs.
//
// The transports read the interval header and turn a 429 sync_too_soon into
// SyncTooSoonError; the background sync keeps the next allowed time in
// auto-sync-state.json and does not try before it. The cloud enforces the
// gap on its own; this only saves requests it would refuse.
//
// Run: node --test packages/sync-encryptor/test/sync-pacing.test.mjs

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { HttpSyncTransport, SyncTooSoonError, SYNC_INTERVAL_HEADER, syncTooSoon } from "../dist/transport.js";
import { HttpSegmentTransport } from "../dist/segment-transport.js";
import {
  readAutoSyncState,
  recordSyncOutcome,
  runAutoSync,
  startBackgroundSync,
  syncDeferred,
} from "../dist/auto-sync.js";

let home;
let original;
beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-sync-pacing-"));
  original = globalThis.fetch;
});
afterEach(async () => {
  globalThis.fetch = original;
  await rm(home, { recursive: true, force: true });
});

const answer = (status, body, headers = {}) => {
  globalThis.fetch = async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });
};

async function writeCredentials() {
  await writeFile(path.join(home, "stream-config.json"), JSON.stringify({
    api_token: "omx_test_case", passphrase: "case-passphrase", api_url: "http://127.0.0.1:1",
  }));
  await writeFile(path.join(home, "license-cache.json"), JSON.stringify({
    response: { customer_id: "cust_case", tier: "hosted", features: ["encrypted_sync"] }, fetched_at: Date.now(),
  }));
}

const segments = () => new HttpSegmentTransport({ baseUrl: "http://api.example.test", apiToken: "omx_t" });
const meta = { machineId: "m1", sessions: 1, firstAt: "2026-10-14T00:00:00Z", lastAt: "2026-10-14T01:00:00Z" };

test("a 429 sync_too_soon becomes SyncTooSoonError with the wait from Retry-After", async () => {
  answer(429, { error: "sync_too_soon", retry_after: 900 }, { "Retry-After": "1200", [SYNC_INTERVAL_HEADER]: "3600" });
  const t = segments();
  await assert.rejects(t.putSegment("seg_0000000000000001", new Uint8Array(8), meta), (err) => {
    assert.ok(err instanceof SyncTooSoonError);
    assert.equal(err.retryAfterSeconds, 1200);
    return true;
  });
  assert.equal(t.serverIntervalSeconds, 3600);
});

test("the wait falls back to the body, then to fifteen minutes", () => {
  assert.equal(syncTooSoon(new Response("", { status: 429 }), JSON.stringify({ retry_after: 61 })).retryAfterSeconds, 61);
  assert.equal(syncTooSoon(new Response("", { status: 429 }), "not json").retryAfterSeconds, 900);
  assert.equal(syncTooSoon(new Response("", { status: 503 }), ""), null);
});

test("the blob transport reads the interval and the 429 too", async () => {
  const t = new HttpSyncTransport({ baseUrl: "http://api.example.test", apiToken: "omx_t" });
  const req = {
    encrypted_payload: new Uint8Array(4), iv: new Uint8Array(12), kdf_salt: new Uint8Array(16),
    payload_bytes: 4, sessions_included: [], machine_id: "m1",
  };
  answer(200, { blob_id: "b1", r2_key: "k" }, { [SYNC_INTERVAL_HEADER]: "1800" });
  await t.push(req);
  assert.equal(t.serverIntervalSeconds, 1800);
  answer(429, { error: "sync_too_soon" }, { "Retry-After": "300" });
  await assert.rejects(t.push(req), SyncTooSoonError);
});

test("a cloud that says nothing leaves the interval unknown", async () => {
  answer(201, { segment_id: "x" });
  const t = segments();
  await t.putSegment("seg_0000000000000001", new Uint8Array(8), meta);
  assert.equal(t.serverIntervalSeconds, null);
});

test("a sync's outcome sets, keeps or clears the next allowed time", async () => {
  const now = Date.parse("2026-10-14T12:00:00Z");
  await recordSyncOutcome(home, { blobId: "c1", blobBytes: 10, serverIntervalSeconds: 3600 }, now);
  assert.equal((await readAutoSyncState(home)).sync_not_before, "2026-10-14T13:00:00.000Z");

  await recordSyncOutcome(home, new SyncTooSoonError(600), now);
  const state = await readAutoSyncState(home);
  assert.equal(state.sync_not_before, "2026-10-14T12:10:00.000Z");
  assert.match(state.last_error, /wait 10 more minute/);

  await recordSyncOutcome(home, { blobId: "c2", blobBytes: 10, serverIntervalSeconds: 0 }, now);
  assert.equal((await readAutoSyncState(home)).sync_not_before, null);
});

test("no background sync is tried before the next allowed time; detection still runs", async () => {
  await writeCredentials();
  const later = new Date(Date.now() + 30 * 60_000).toISOString();
  await writeFile(path.join(home, "auto-sync-state.json"), JSON.stringify({ sync_not_before: later }));
  assert.equal(syncDeferred(await readAutoSyncState(home)), true);

  let spawned = 0;
  const decision = await startBackgroundSync({ home, scriptPath: "x", spawnFn: () => { spawned++; } });
  assert.equal(decision, "too-soon");
  assert.equal(spawned, 0);

  let detected = false;
  const outcome = await runAutoSync(home, {
    detect: async () => { detected = true; return []; },
    refreshLicense: async () => undefined,
    refreshRules: async () => undefined,
    submitUsage: async () => undefined,
  });
  assert.equal(outcome, "deferred");
  assert.equal(detected, true);
});
