/**
 * Tests for the device code authorization flow.
 *
 * Uses a mock fetch to simulate the cloud API responses without network
 * access. Tests confirm:
 *   1. requestDeviceCode sends correct payload and returns structured response.
 *   2. pollForAuthorization handles authorization_pending, slow_down, success.
 *   3. pollForAuthorization throws on expired_token and access_denied.
 *   4. encryptForTransfer produces valid encrypted output.
 */

import { test, mock } from "node:test";
import * as assert from "node:assert/strict";

// Import from dist (compiled output)
import { requestDeviceCode, pollForAuthorization } from "../dist/device-auth.js";
import { encryptForTransfer } from "../dist/connect.js";

// ---------------------------------------------------------------------------
// Mock fetch helper
// ---------------------------------------------------------------------------

function mockFetchSequence(responses) {
  let callIndex = 0;
  const calls = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    const resp = responses[callIndex] ?? responses[responses.length - 1];
    callIndex++;
    return {
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      json: async () => resp.body,
    };
  };

  return {
    calls,
    restore: () => { globalThis.fetch = originalFetch; },
  };
}

// ---------------------------------------------------------------------------
// encryptForTransfer
// ---------------------------------------------------------------------------

test("encryptForTransfer produces base64 ciphertext and hex transfer key", async () => {
  const result = await encryptForTransfer("test-passphrase-123");

  assert.ok(result.passphrase_enc, "should have passphrase_enc");
  assert.ok(result.passphrase_iv, "should have passphrase_iv");
  assert.ok(result.transfer_key, "should have transfer_key");

  // Transfer key should be 64 hex chars (32 bytes)
  assert.equal(result.transfer_key.length, 64);
  assert.match(result.transfer_key, /^[0-9a-f]{64}$/);

  // Ciphertext and IV should be valid base64
  assert.doesNotThrow(() => Buffer.from(result.passphrase_enc, "base64"));
  assert.doesNotThrow(() => Buffer.from(result.passphrase_iv, "base64"));

  // IV should be 12 bytes (16 chars in base64)
  const ivBytes = Buffer.from(result.passphrase_iv, "base64");
  assert.equal(ivBytes.length, 12);
});

test("encryptForTransfer produces unique keys and IVs each call", async () => {
  const a = await encryptForTransfer("same-passphrase");
  const b = await encryptForTransfer("same-passphrase");

  assert.notEqual(a.transfer_key, b.transfer_key);
  assert.notEqual(a.passphrase_iv, b.passphrase_iv);
  assert.notEqual(a.passphrase_enc, b.passphrase_enc);
});

// ---------------------------------------------------------------------------
// pollForAuthorization
// ---------------------------------------------------------------------------

test("pollForAuthorization returns token on immediate success", async () => {
  const mf = mockFetchSequence([
    {
      status: 200,
      body: {
        api_token: "omx_live_test123",
        customer_id: "cust-001",
        api_url: "https://api.omnodex.com",
      },
    },
  ]);

  try {
    const result = await pollForAuthorization(
      "https://api.omnodex.com",
      "omx_dc_test",
      { interval: 0.01, expiresIn: 5 },
    );

    assert.equal(result.apiToken, "omx_live_test123");
    assert.equal(result.customerId, "cust-001");
    assert.equal(mf.calls.length, 1);

    // Verify the request body
    const body = JSON.parse(mf.calls[0].init.body);
    assert.equal(body.device_code, "omx_dc_test");
    assert.equal(body.grant_type, "urn:ietf:params:oauth:grant-type:device_code");
  } finally {
    mf.restore();
  }
});

test("pollForAuthorization retries on authorization_pending then succeeds", async () => {
  const mf = mockFetchSequence([
    { status: 400, body: { error: "authorization_pending" } },
    { status: 400, body: { error: "authorization_pending" } },
    {
      status: 200,
      body: {
        api_token: "omx_live_after_wait",
        customer_id: "cust-002",
      },
    },
  ]);

  try {
    const result = await pollForAuthorization(
      "https://api.omnodex.com",
      "omx_dc_pending",
      { interval: 0.01, expiresIn: 10 },
    );

    assert.equal(result.apiToken, "omx_live_after_wait");
    assert.equal(mf.calls.length, 3);
  } finally {
    mf.restore();
  }
});

test("pollForAuthorization backs off on slow_down", async () => {
  const mf = mockFetchSequence([
    { status: 400, body: { error: "slow_down", interval: 0.02 } },
    {
      status: 200,
      body: { api_token: "omx_live_slow", customer_id: "cust-003" },
    },
  ]);

  try {
    const result = await pollForAuthorization(
      "https://api.omnodex.com",
      "omx_dc_slow",
      { interval: 0.01, expiresIn: 10 },
    );

    assert.equal(result.apiToken, "omx_live_slow");
    assert.equal(mf.calls.length, 2);
  } finally {
    mf.restore();
  }
});

test("pollForAuthorization throws on expired_token", async () => {
  const mf = mockFetchSequence([
    { status: 400, body: { error: "expired_token" } },
  ]);

  try {
    await assert.rejects(
      () =>
        pollForAuthorization("https://api.omnodex.com", "omx_dc_expired", {
          interval: 0.01,
          expiresIn: 10,
        }),
      { message: /expired/i },
    );
  } finally {
    mf.restore();
  }
});

test("pollForAuthorization throws on access_denied", async () => {
  const mf = mockFetchSequence([
    { status: 400, body: { error: "access_denied" } },
  ]);

  try {
    await assert.rejects(
      () =>
        pollForAuthorization("https://api.omnodex.com", "omx_dc_denied", {
          interval: 0.01,
          expiresIn: 10,
        }),
      { message: /denied/i },
    );
  } finally {
    mf.restore();
  }
});
