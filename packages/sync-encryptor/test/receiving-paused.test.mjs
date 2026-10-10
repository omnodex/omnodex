// When the stream's owner pauses receiving in the dashboard, the server
// refuses uploads with 403 {"error":"receiving_paused"}. Live pushes back
// off for the longest window at once and remember why; blob and segment
// uploads fail with an error that says so, instead of a bare HTTP code.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  LIVE_BACKOFF_MAX_MS,
  isReceivingPaused,
  livePushOutcome,
  nextLiveGate,
  readLiveGate,
  recordLivePush,
} from "../dist/live-gate.js";
import { HttpSyncTransport, ReceivingPausedError } from "../dist/transport.js";
import { HttpSegmentTransport } from "../dist/segment-transport.js";

const PAUSED_BODY = JSON.stringify({ error: "receiving_paused", message: "Receiving is paused for this stream" });

test("a 403 receiving_paused is told apart from other refusals", async () => {
  assert.equal(isReceivingPaused(403, PAUSED_BODY), true);
  assert.equal(isReceivingPaused(403, JSON.stringify({ error: "forbidden" })), false);
  assert.equal(isReceivingPaused(401, PAUSED_BODY), false);
  assert.equal(isReceivingPaused(403, "not json"), false);
  assert.equal(await livePushOutcome(new Response(PAUSED_BODY, { status: 403 })), "receiving_paused");
  assert.equal(await livePushOutcome(new Response("", { status: 500 })), "failed");
});

test("receiving paused backs off for the longest window and is remembered", async (t) => {
  const now = Date.parse("2026-06-02T12:00:00.000Z");
  const gate = nextLiveGate(null, "receiving_paused", now);
  assert.equal(gate.backoff_ms, LIVE_BACKOFF_MAX_MS);
  assert.equal(gate.paused_until, now + LIVE_BACKOFF_MAX_MS);
  assert.equal(gate.receiving_paused, true);
  // An ordinary failure after it does not keep the reason.
  assert.equal(nextLiveGate(gate, "failed", now).receiving_paused, undefined);

  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-recvpause-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  await recordLivePush(home, "receiving_paused", now);
  assert.equal((await readLiveGate(home)).receiving_paused, true);
  // A push that reaches a viewer clears it.
  await recordLivePush(home, "watched", now);
  assert.equal(await readLiveGate(home), null);
});

function refuseWith(t, status, body) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(body, { status });
  t.after(() => { globalThis.fetch = original; });
}

test("a blob upload refused for receiving paused says why", async (t) => {
  refuseWith(t, 403, PAUSED_BODY);
  const transport = new HttpSyncTransport({ baseUrl: "https://api.example.test", apiToken: "omx_test_case" });
  await assert.rejects(
    () => transport.push({
      customer_id: "cust_case",
      encrypted_payload: new Uint8Array(64),
      iv: new Uint8Array(12),
      kdf_salt: new Uint8Array(16),
      payload_bytes: 64,
      sessions_included: ["sess-case"],
      machine_id: "m_case",
    }),
    (err) => err instanceof ReceivingPausedError && /paused receiving/.test(err.message),
  );
});

test("a segment upload refused for receiving paused says why", async (t) => {
  refuseWith(t, 403, PAUSED_BODY);
  const transport = new HttpSegmentTransport({ baseUrl: "https://api.example.test", apiToken: "omx_test_case" });
  await assert.rejects(
    () => transport.putSegment("seg_case", new Uint8Array(64), {
      machineId: "m_case", sessions: 1, firstAt: "2026-06-02T12:00:00.000Z", lastAt: "2026-06-02T12:00:00.000Z",
    }),
    (err) => err instanceof ReceivingPausedError,
  );
});
