// Validation: what a segment upload tells the cloud
//
// Only the machine ID, the sealed machine label and the latest activity,
// rounded up to the hour, travel outside the envelope.
//
// Run: node --test packages/sync-encryptor/test/segment-transport.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { HttpSegmentTransport, ceilToHour } from "../dist/segment-transport.js";

describe("ceilToHour", () => {
  it("rounds up to the next whole UTC hour, so retention never ages a segment early", () => {
    assert.equal(ceilToHour("2026-10-27T15:00:01.000Z"), "2026-10-27T16:00:00.000Z");
    assert.equal(ceilToHour("2026-10-27T23:59:59.999Z"), "2026-10-28T00:00:00.000Z");
    assert.equal(ceilToHour("2026-10-27T15:00:00.000Z"), "2026-10-27T15:00:00.000Z");
  });

  it("passes through a value that is not a time", () => {
    assert.equal(ceilToHour("not a time"), "not a time");
  });
});

describe("HttpSegmentTransport.putSegment", () => {
  it("sends no session count or first activity, and the latest activity by the hour", async (t) => {
    const original = globalThis.fetch;
    t.after(() => { globalThis.fetch = original; });
    let headers;
    globalThis.fetch = async (_url, init) => {
      headers = Object.fromEntries(new Headers(init.headers).entries());
      return new Response("{}", { status: 201 });
    };
    const transport = new HttpSegmentTransport({ baseUrl: "https://api.example.test", apiToken: "omx_case" });
    await transport.putSegment("seg_case_0000000001", new Uint8Array([1, 2, 3]), {
      machineId: "c0ffee00c0ffee01", sessions: 4, firstAt: "2026-10-27T09:12:00.000Z", lastAt: "2026-10-27T15:42:10.000Z",
    });
    assert.equal(headers["x-omnodex-last-at"], "2026-10-27T16:00:00.000Z");
    assert.equal(headers["x-omnodex-segment-sessions"], undefined);
    assert.equal(headers["x-omnodex-first-at"], undefined);
    assert.equal(headers["x-omnodex-machine-id"], "c0ffee00c0ffee01");
  });
});
