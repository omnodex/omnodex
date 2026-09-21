// Validation: license cache for live push and automatic sync
//
// A connected home without license-cache.json used to skip live push and
// automatic sync silently until a manual `omnodex sync` wrote the cache.
// readOrFetchLicense fetches a missing cache once; these tests cover it
// directly and through pushEventsToCloud and startBackgroundSync.
//
// Run: node --test packages/sync-encryptor/test/license-cache.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { readOrFetchLicense } from "../dist/license-cache.js";
import { pushEventsToCloud } from "../dist/shim-push.js";
import { startBackgroundSync } from "../dist/auto-sync.js";

const HOSTED = {
  customer_id: "cust_case",
  tier: "hosted",
  features: ["encrypted_sync", "live_streaming"],
  ttl_seconds: 86400,
};

/** Local stand-in for the license and live-event endpoints. */
async function startApi({ licenseStatus = 200, license = HOSTED } = {}) {
  const requests = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url });
      if (req.url === "/api/v1/license/validate") {
        res.writeHead(licenseStatus, { "Content-Type": "application/json" });
        res.end(licenseStatus < 300 ? JSON.stringify(license) : "{}");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    hits: (url) => requests.filter((r) => r.url === url).length,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function writeJson(home, name, value) {
  await writeFile(path.join(home, name), JSON.stringify(value));
}

async function readCache(home) {
  try {
    return JSON.parse(await readFile(path.join(home, "license-cache.json"), "utf8"));
  } catch {
    return null;
  }
}

function creds(api) {
  return { apiToken: "omx_test_case", apiUrl: api.url, timeoutMs: 2000 };
}

describe("readOrFetchLicense", () => {
  let home;
  let api;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-license-cache-"));
  });

  afterEach(async () => {
    await api?.close();
    api = undefined;
    await rm(home, { recursive: true, force: true });
  });

  it("uses an existing cache without a network call, even when expired", async () => {
    api = await startApi();
    await writeJson(home, "license-cache.json", {
      response: { ...HOSTED, customer_id: "cust_cached" },
      fetched_at: 0,
    });

    const license = await readOrFetchLicense(home, creds(api));

    assert.equal(license.customer_id, "cust_cached");
    assert.equal(api.requests.length, 0);
  });

  it("fetches a missing cache and writes it into the home", async () => {
    api = await startApi();

    const license = await readOrFetchLicense(home, creds(api));

    assert.equal(license.customer_id, "cust_case");
    assert.deepEqual(license.features, HOSTED.features);
    assert.equal(api.hits("/api/v1/license/validate"), 1);
    const cache = await readCache(home);
    assert.equal(cache.response.customer_id, "cust_case");
  });

  it("returns null and writes nothing when the fetch is refused", async () => {
    api = await startApi({ licenseStatus: 401 });

    assert.equal(await readOrFetchLicense(home, creds(api)), null);
    assert.equal(await readCache(home), null);
  });

  it("returns null without a network call when there is no token", async () => {
    api = await startApi();

    assert.equal(await readOrFetchLicense(home, { ...creds(api), apiToken: "" }), null);
    assert.equal(api.requests.length, 0);
  });
});

describe("a connected home without a license cache", () => {
  let home;
  let api;
  let savedEnv;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-missing-cache-"));
    api = await startApi();
    await writeJson(home, "stream-config.json", {
      api_token: "omx_test_case",
      passphrase: "case-passphrase",
      api_url: api.url,
    });
    savedEnv = process.env.OMNODEX_AUTO_SYNC;
    delete process.env.OMNODEX_AUTO_SYNC;
  });

  afterEach(async () => {
    if (savedEnv === undefined) delete process.env.OMNODEX_AUTO_SYNC;
    else process.env.OMNODEX_AUTO_SYNC = savedEnv;
    await api.close();
    await rm(home, { recursive: true, force: true });
  });

  it("live push fetches the license and sends the event", async () => {
    const now = new Date().toISOString();
    const event = {
      schema_version: 1,
      session_id: randomUUID(),
      event_id: randomUUID(),
      occurred_at: now,
      recorded_at: now,
      interceptor: "claude-code-hook",
      event_type: "session.started",
      user: "case",
      project_path: "/home/case/repo",
      mcp_servers: [],
    };

    const pushed = await pushEventsToCloud([event], home, 5000);

    assert.equal(pushed, true);
    assert.equal(api.hits("/api/v1/license/validate"), 1);
    assert.equal(api.hits("/api/v1/sync/events"), 1);
    assert.equal((await readCache(home)).response.customer_id, "cust_case");
  });

  it("automatic sync fetches the license and starts", async () => {
    const spawned = [];

    const decision = await startBackgroundSync({
      home,
      scriptPath: "/home/case/bin/claude-hook-shim.js",
      spawnFn: (command, args) => spawned.push({ command, args }),
    });

    assert.equal(decision, "started");
    assert.equal(spawned.length, 1);
    assert.equal(api.hits("/api/v1/license/validate"), 1);
  });

  it("automatic sync stays off when the license lacks encrypted sync", async () => {
    await api.close();
    api = await startApi({
      license: { ...HOSTED, tier: "free", features: ["local_dashboard"] },
    });
    await writeJson(home, "stream-config.json", {
      api_token: "omx_test_case",
      passphrase: "case-passphrase",
      api_url: api.url,
    });

    const decision = await startBackgroundSync({
      home,
      scriptPath: "/home/case/bin/claude-hook-shim.js",
      spawnFn: () => assert.fail("must not spawn"),
    });

    assert.equal(decision, "not-entitled");
  });
});
