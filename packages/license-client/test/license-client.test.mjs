// @ts-check
/**
 * @omnodex/license-client tests.
 *
 * Uses node:test + a tiny HTTP server to mock the cloud API.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// We import from the source .ts via tsx, not from dist.
// Run with: npx tsx --test test/license-client.test.mjs
// Or after build: node --test test/license-client.test.mjs

/** @type {import("../dist/index.js")} */
const { validateLicense, clearCache, FREE_TIER_DEFAULTS } = await import("../dist/index.js");

// ---------------------------------------------------------------------------
// Mock server
// ---------------------------------------------------------------------------

/** @type {import("node:http").Server} */
let server;
let baseUrl = "";
let mockResponse = {};
let mockStatus = 200;
let requestCount = 0;

function resetMock() {
  mockResponse = {
    customer_id: "cust-test",
    tier: "pro",
    features: ["community_rules", "local_dashboard", "local_event_log", "encrypted_sync", "hosted_dashboard", "advanced_rules", "feature_extraction", "usage_analytics"],
    rule_decryption_key: "test-key-abc123",
    sync_endpoint: "http://localhost/api/v1/sync",
    ttl_seconds: 86400,
  };
  mockStatus = 200;
  requestCount = 0;
}

before(async () => {
  resetMock();
  server = createServer((req, res) => {
    requestCount++;
    if (req.url === "/api/v1/license/validate" && req.method === "POST") {
      res.writeHead(mockStatus, { "Content-Type": "application/json" });
      res.end(JSON.stringify(mockResponse));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(() => {
  server?.close();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("validateLicense", () => {
  it("returns free-tier defaults when no token is configured", async () => {
    const result = await validateLicense({ apiToken: "" });
    assert.equal(result.source, "defaults");
    assert.equal(result.license.tier, "free");
    assert.deepEqual(result.license.features, FREE_TIER_DEFAULTS.features);
  });

  it("fetches from the network and caches the result", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "omx-test-"));
    resetMock();

    try {
      const result = await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 2000,
      });

      assert.equal(result.source, "network");
      assert.equal(result.license.tier, "pro");
      assert.equal(result.license.rule_decryption_key, "test-key-abc123");
      assert.equal(requestCount, 1);

      // Verify cache file was written
      const cacheFile = join(cacheDir, "license-cache.json");
      const cached = JSON.parse(await readFile(cacheFile, "utf-8"));
      assert.equal(cached.response.tier, "pro");
      assert.ok(cached.fetched_at > 0);
    } finally {
      await rm(cacheDir, { recursive: true, force: true });
    }
  });

  it("returns cached response when cache is fresh (no network call)", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "omx-test-"));
    resetMock();

    try {
      // First call -- populates cache
      await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 2000,
      });
      assert.equal(requestCount, 1);

      // Second call -- should use cache
      const result = await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 2000,
      });

      assert.equal(result.source, "cache");
      assert.equal(result.license.tier, "pro");
      assert.equal(requestCount, 1); // no additional network call
    } finally {
      await rm(cacheDir, { recursive: true, force: true });
    }
  });

  it("falls back to free-tier defaults when network fails and no cache", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "omx-test-"));

    try {
      const result = await validateLicense({
        apiBaseUrl: "http://127.0.0.1:1", // unreachable port
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 500,
      });

      assert.equal(result.source, "defaults");
      assert.equal(result.license.tier, "free");
    } finally {
      await rm(cacheDir, { recursive: true, force: true });
    }
  });

  it("falls back to stale cache when network fails", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "omx-test-"));
    resetMock();

    try {
      // Populate cache via network
      await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 2000,
      });

      // Manually expire the cache by backdating fetched_at
      const cacheFile = join(cacheDir, "license-cache.json");
      const cached = JSON.parse(await readFile(cacheFile, "utf-8"));
      cached.fetched_at = Date.now() - (86400 * 1000 + 1000); // TTL + 1s
      const { writeFile: wf } = await import("node:fs/promises");
      await wf(cacheFile, JSON.stringify(cached), "utf-8");

      // Now request with unreachable server -- should use stale cache
      const result = await validateLicense({
        apiBaseUrl: "http://127.0.0.1:1",
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 500,
      });

      assert.equal(result.source, "cache_stale");
      assert.equal(result.license.tier, "pro");
    } finally {
      await rm(cacheDir, { recursive: true, force: true });
    }
  });

  it("handles API error responses gracefully", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "omx-test-"));
    resetMock();
    mockStatus = 401;

    try {
      const result = await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_bad_token",
        cacheDir,
        timeoutMs: 2000,
      });

      // Should fall back to defaults since there's no cache
      assert.equal(result.source, "defaults");
      assert.equal(result.license.tier, "free");
    } finally {
      await rm(cacheDir, { recursive: true, force: true });
    }
  });
});

describe("clearCache", () => {
  it("removes the cache file", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "omx-test-"));
    resetMock();

    try {
      // Create cache
      await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 2000,
      });

      // Clear it
      await clearCache(cacheDir);

      // Verify next call hits the network
      requestCount = 0;
      const result = await validateLicense({
        apiBaseUrl: baseUrl,
        apiToken: "omx_test_token",
        cacheDir,
        timeoutMs: 2000,
      });

      assert.equal(result.source, "network");
      assert.equal(requestCount, 1);
    } finally {
      await rm(cacheDir, { recursive: true, force: true });
    }
  });
});
