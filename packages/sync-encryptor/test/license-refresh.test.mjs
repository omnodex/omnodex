// Validation: the background pass keeps the license cache current
//
// A plan change used to reach an install only when someone ran a CLI
// command: hooks and the background pass read license-cache.json as-is,
// expired or not. The background child now re-validates a cache past its
// TTL before anything reads the tier. Hooks still never make the request,
// and a failed check waits an hour before the next one.
//
// Run: node --test packages/sync-encryptor/test/license-refresh.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  runAutoSync,
  refreshStaleLicense,
  startBackgroundSync,
  readAutoSyncState,
  LICENSE_RETRY_MS,
} from "../dist/auto-sync.js";
import { pushEventsToCloud } from "../dist/shim-push.js";

const DAY_MS = 86_400_000;
const HOSTED = { customer_id: "cust_case", tier: "hosted", features: ["encrypted_sync", "live_streaming"], ttl_seconds: 86400 };
const PRO = { ...HOSTED, tier: "pro", features: [...HOSTED.features, "advanced_rules"] };

/** Local stand-in for the license endpoint; every other path answers 200 {}. */
async function startApi({ status = 200, license = PRO } = {}) {
  const requests = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      requests.push(req.url);
      if (req.url === "/api/v1/license/validate") {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(status < 300 ? JSON.stringify(license) : "{}");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    licenseHits: () => requests.filter((u) => u === "/api/v1/license/validate").length,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function writeJson(home, name, value) {
  await writeFile(path.join(home, name), JSON.stringify(value));
}

/** A connected home whose cached license is `license`, fetched `ageMs` ago. */
async function writeHome(home, api, { license = HOSTED, ageMs = 2 * DAY_MS } = {}) {
  await writeJson(home, "stream-config.json", {
    api_token: "omx_test_case",
    passphrase: "case-passphrase",
    api_url: api.url,
    auto_sync: false, // keep the pass to the license; sync is covered elsewhere
  });
  await writeJson(home, "license-cache.json", { response: license, fetched_at: Date.now() - ageMs });
}

async function cachedTier(home) {
  return JSON.parse(await readFile(path.join(home, "license-cache.json"), "utf8")).response.tier;
}

describe("background license re-validation", () => {
  let home;
  let api;
  let saved;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-license-refresh-"));
    saved = process.env.OMNODEX_AUTO_DETECT;
    process.env.OMNODEX_AUTO_DETECT = "1";
  });

  afterEach(async () => {
    await api?.close();
    api = undefined;
    if (saved === undefined) delete process.env.OMNODEX_AUTO_DETECT;
    else process.env.OMNODEX_AUTO_DETECT = saved;
    await rm(home, { recursive: true, force: true });
  });

  it("picks up an upgrade to Pro once the Hosted cache expires, before the rule refresh reads it", async () => {
    api = await startApi({ license: PRO });
    await writeHome(home, api);
    let tierSeenByRules;

    await runAutoSync(home, {
      detect: async () => [],
      refreshRules: async (h) => { tierSeenByRules = await cachedTier(h); },
    });

    assert.equal(api.licenseHits(), 1);
    assert.equal(await cachedTier(home), "pro");
    assert.equal(tierSeenByRules, "pro");
  });

  it("makes no request while the cache is within its TTL", async () => {
    api = await startApi();
    await writeHome(home, api, { ageMs: 60_000 });
    assert.equal(await refreshStaleLicense(home), "fresh");
    await runAutoSync(home, { detect: async () => [], refreshRules: async () => {} });
    assert.equal(api.licenseHits(), 0);
    assert.equal(await cachedTier(home), "hosted");
  });

  it("picks up a downgrade too", async () => {
    api = await startApi({ license: HOSTED });
    await writeHome(home, api, { license: PRO });
    assert.equal(await refreshStaleLicense(home), "refreshed");
    assert.equal(await cachedTier(home), "hosted");
  });

  it("after a failed check, waits an hour before asking again and keeps the old cache", async () => {
    api = await startApi({ status: 500 });
    await writeHome(home, api);
    const now = Date.now();

    assert.equal(await refreshStaleLicense(home, now), "failed");
    assert.equal(await refreshStaleLicense(home, now + 10 * 60_000), "waiting");
    assert.equal(api.licenseHits(), 1);
    assert.equal(await cachedTier(home), "hosted");
    assert.ok((await readAutoSyncState(home)).license_checked_at);

    assert.equal(await refreshStaleLicense(home, now + LICENSE_RETRY_MS), "failed");
    assert.equal(api.licenseHits(), 2);
  });

  it("does nothing for a home without credentials", async () => {
    assert.equal(await refreshStaleLicense(home), "no-credentials");
  });

  it("never makes the request on the hook path, even with an expired cache", async () => {
    api = await startApi();
    await writeHome(home, api);
    const spawned = [];

    await startBackgroundSync({ home, scriptPath: "shim.js", detect: true, spawnFn: (...args) => spawned.push(args) });
    // Live push reads the cache as-is too (it skips here: no viewer is watching).
    await pushEventsToCloud([], home, 2000);

    assert.equal(spawned.length, 1);
    assert.equal(api.licenseHits(), 0);
    assert.equal(await cachedTier(home), "hosted");
  });
});
