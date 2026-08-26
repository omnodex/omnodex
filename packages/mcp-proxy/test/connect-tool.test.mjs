// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Unit tests for connect-tool.ts -- handleConnect and checkConnectionStatus.
// Runs against dist/; build the package before running.

import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, mkdir, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function withTmpHome(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-connect-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function setEnv(t, key, value) {
  const prev = process.env[key];
  process.env[key] = value;
  t.after(() => {
    if (prev === undefined) delete process.env[key];
    else process.env[key] = prev;
  });
}

function clearEnv(t, key) {
  const prev = process.env[key];
  delete process.env[key];
  t.after(() => {
    if (prev !== undefined) process.env[key] = prev;
  });
}

async function writeConfig(dir, config) {
  await mkdir(dir, { recursive: true });
  await writeFile(
    path.join(dir, "stream-config.json"),
    JSON.stringify(config, null, 2) + "\n",
  );
}

// ---------------------------------------------------------------------------
// checkConnectionStatus
// ---------------------------------------------------------------------------

test("checkConnectionStatus returns none when no credentials exist", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  clearEnv(t, "OMNODEX_API_TOKEN");
  clearEnv(t, "OMNODEX_SYNC_PASSPHRASE");
  clearEnv(t, "OMNODEX_API_URL");

  // Re-import to pick up env changes (ESM caches, so we use dynamic import
  // with a cache-busting query param per test)
  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-1`);
  const status = await mod.checkConnectionStatus();

  assert.equal(status.has_api_token, false);
  assert.equal(status.has_passphrase, false);
  assert.equal(status.token_source, "none");
  assert.equal(status.api_url, "https://api.omnodex.com");
});

test("checkConnectionStatus reads from env vars", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_test_tok");
  setEnv(t, "OMNODEX_SYNC_PASSPHRASE", "test-pass");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-2`);
  const status = await mod.checkConnectionStatus();

  assert.equal(status.has_api_token, true);
  assert.equal(status.has_passphrase, true);
  assert.equal(status.token_source, "env");
  assert.equal(status.api_url, "https://api.test.omnodex.com");
});

test("checkConnectionStatus reads from config file", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  clearEnv(t, "OMNODEX_API_TOKEN");
  clearEnv(t, "OMNODEX_SYNC_PASSPHRASE");
  clearEnv(t, "OMNODEX_API_URL");

  await writeConfig(home, {
    api_token: "omx_from_config",
    passphrase: "config-pass",
    api_url: "https://api.custom.omnodex.com",
  });

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-3`);
  const status = await mod.checkConnectionStatus();

  assert.equal(status.has_api_token, true);
  assert.equal(status.has_passphrase, true);
  assert.equal(status.token_source, "config");
  assert.equal(status.api_url, "https://api.custom.omnodex.com");
});

test("checkConnectionStatus env vars take precedence over config", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_env_tok");
  clearEnv(t, "OMNODEX_SYNC_PASSPHRASE");
  clearEnv(t, "OMNODEX_API_URL");

  await writeConfig(home, {
    api_token: "omx_config_tok",
    passphrase: "config-pass",
  });

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-4`);
  const status = await mod.checkConnectionStatus();

  assert.equal(status.token_source, "env");
});

// ---------------------------------------------------------------------------
// handleConnect
// ---------------------------------------------------------------------------

test("handleConnect initiates device code flow when no API token", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  clearEnv(t, "OMNODEX_API_TOKEN");
  clearEnv(t, "OMNODEX_SYNC_PASSPHRASE");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async (url, opts) => {
    if (String(url).includes("/device/code")) {
      return new Response(JSON.stringify({
        device_code: "dc_test123",
        user_code: "ABCD-1234",
        verification_url: "https://dashboard.omnodex.com/device",
        expires_in: 900,
        interval: 5,
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response("not found", { status: 404 });
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-5`);
  const result = await mod.handleConnect({});

  assert.equal(result.status, "device_code");
  assert.ok(result.user_code, "should return user_code");
  assert.ok(result.connect_url, "should return connect_url");

  // Cancel background poll so the test runner can exit
  for (const poll of mod.activePolls.values()) poll.cancel();
  mod.activePolls.clear();
});

test("handleConnect returns error when device code request fails", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  clearEnv(t, "OMNODEX_API_TOKEN");
  clearEnv(t, "OMNODEX_SYNC_PASSPHRASE");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async () => {
    return new Response(JSON.stringify({ message: "Rate limited" }), { status: 429 });
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-5b`);
  const result = await mod.handleConnect({});

  assert.equal(result.status, "error");
});

test("handleConnect creates claim and returns connect URL", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_test_token");
  setEnv(t, "OMNODEX_SYNC_PASSPHRASE", "test-passphrase");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  // Mock global fetch
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async (url, opts) => {
    assert.equal(url, "https://api.test.omnodex.com/api/v1/connect/claim");
    assert.equal(opts.method, "POST");
    assert.ok(opts.headers.Authorization.startsWith("Bearer omx_test_token"));

    const body = JSON.parse(opts.body);
    assert.ok(body.passphrase_enc, "should have encrypted passphrase");
    assert.ok(body.passphrase_iv, "should have IV");
    assert.equal(body.platform, "cowork-plugin");

    return new Response(JSON.stringify({
      claim_token: "ct_mock_123",
      expires_at: "2026-08-26T01:00:00Z",
      connect_url: "https://dashboard.omnodex.com/connect/ct_mock_123",
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-6`);
  const result = await mod.handleConnect({});

  assert.equal(result.status, "ok");
  assert.ok(result.connect_url.startsWith("https://dashboard.omnodex.com/connect/ct_mock_123#tk="));
  assert.equal(result.expires_at, "2026-08-26T01:00:00Z");
  // Transfer key should be 64 hex chars (32 bytes)
  const fragment = result.connect_url.split("#tk=")[1];
  assert.equal(fragment.length, 64);
  assert.match(fragment, /^[0-9a-f]{64}$/);
});

test("handleConnect passes custom platform param", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_test_token");
  setEnv(t, "OMNODEX_SYNC_PASSPHRASE", "test-passphrase");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  let capturedPlatform = "";
  globalThis.fetch = async (_url, opts) => {
    const body = JSON.parse(opts.body);
    capturedPlatform = body.platform;
    return new Response(JSON.stringify({
      claim_token: "ct_mock_456",
      expires_at: "2026-08-26T01:00:00Z",
      connect_url: "https://dashboard.omnodex.com/connect/ct_mock_456",
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-7`);
  await mod.handleConnect({ platform: "cli" });

  assert.equal(capturedPlatform, "cli");
});

test("handleConnect returns error on API failure", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_test_token");
  setEnv(t, "OMNODEX_SYNC_PASSPHRASE", "test-passphrase");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async () => {
    return new Response(JSON.stringify({
      error: "rate_limited",
      message: "Too many requests",
    }), { status: 429, headers: { "Content-Type": "application/json" } });
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-8`);
  const result = await mod.handleConnect({});

  assert.equal(result.status, "error");
  assert.ok(result.message.includes("Too many requests"));
});

test("handleConnect returns error on network failure", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_test_token");
  setEnv(t, "OMNODEX_SYNC_PASSPHRASE", "test-passphrase");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async () => {
    throw new Error("ECONNREFUSED");
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-9`);
  const result = await mod.handleConnect({});

  assert.equal(result.status, "error");
  assert.ok(result.message.includes("ECONNREFUSED"));
});

test("handleConnect auto-generates passphrase and writes config", async (t) => {
  const home = await withTmpHome(t);
  setEnv(t, "OMNODEX_HOME", home);
  setEnv(t, "OMNODEX_API_TOKEN", "omx_test_token");
  clearEnv(t, "OMNODEX_SYNC_PASSPHRASE");
  setEnv(t, "OMNODEX_API_URL", "https://api.test.omnodex.com");

  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async () => {
    return new Response(JSON.stringify({
      claim_token: "ct_auto",
      expires_at: "2026-08-26T01:00:00Z",
      connect_url: "https://dashboard.omnodex.com/connect/ct_auto",
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const mod = await import(`../dist/connect-tool.js?t=${Date.now()}-10`);
  const result = await mod.handleConnect({});

  assert.equal(result.status, "ok");

  // Should have written stream-config.json with the generated passphrase
  const written = JSON.parse(
    await readFile(path.join(home, "stream-config.json"), "utf-8"),
  );
  assert.equal(written.api_token, "omx_test_token");
  assert.ok(written.passphrase.length > 0, "passphrase should be generated");
  assert.equal(written.api_url, "https://api.test.omnodex.com");
});
