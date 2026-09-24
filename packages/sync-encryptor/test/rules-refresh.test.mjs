// Validation: the background pass keeps a Pro install's rule bundle and its
// key current, and costs everyone else nothing.
//
// Run: node --test packages/sync-encryptor/test/rules-refresh.test.mjs

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { refreshRuleBundle, RULE_BUNDLE_FILE } from "../dist/rules-refresh.js";
import { runAutoSync } from "../dist/auto-sync.js";

let home;
beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-rules-refresh-"));
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

const write = (file, value) => writeFile(path.join(home, file), JSON.stringify(value), "utf8");
const bundle = (version) => ({ manifest: { bundle_version: version, channel: "pro" }, signature: "sig", payload: "payload" });
const grant = (version) => ({ channel: "pro", bundle_version: version, content_key: `key-${version}`, not_after: "2099-01-01T00:00:00.000Z" });

async function setup({ tier = "pro", installed = null } = {}) {
  await write("stream-config.json", { api_token: "omx_case", passphrase: "p", api_url: "https://api.example.test/" });
  await write("license-cache.json", { response: { customer_id: "cus_case", tier, features: [] }, fetched_at: Date.now() });
  if (installed) {
    await mkdir(path.join(home, "rules"), { recursive: true });
    await write(RULE_BUNDLE_FILE, bundle(installed));
  }
}

/** A fake cloud: records requests, answers from a script. */
function cloud({ status = 200, version = "1.0.0", licensed = "1.0.0", tier = "pro", afterForce = null } = {}) {
  const calls = { fetch: [], validate: [] };
  return {
    calls,
    fetchFn: async (url, init) => {
      calls.fetch.push({ url, auth: init?.headers?.Authorization });
      if (status === "throw") throw new Error("offline");
      const body = status === 200 ? { channel: "pro", bundle_version: version, bundle: bundle(version) } : { error: "x" };
      return new Response(status === 304 ? null : JSON.stringify(body), { status });
    },
    validate: async (config) => {
      calls.validate.push(config);
      const v = config.force && afterForce ? afterForce : licensed;
      return { source: "network", license: { customer_id: "cus_case", tier, features: [], ttl_seconds: 86400, ...(v ? { rule_bundle: grant(v) } : {}) } };
    },
  };
}

const installed = async () => JSON.parse(await readFile(path.join(home, RULE_BUNDLE_FILE), "utf8")).manifest.bundle_version;

// ---------------------------------------------------------------------------

test("a free or Hosted install makes no request at all", async () => {
  for (const tier of ["free", "hosted"]) {
    await setup({ tier });
    const c = cloud();
    assert.equal(await refreshRuleBundle(home, c), "not-entitled");
    assert.deepEqual(c.calls, { fetch: [], validate: [] }, tier);
  }
});

test("an install with no API token makes no request", async () => {
  const c = cloud();
  assert.equal(await refreshRuleBundle(home, c), "no-credentials");
  assert.deepEqual(c.calls, { fetch: [], validate: [] });
});

test("a Pro install with no bundle fetches and installs one, authenticated", async () => {
  await setup();
  const c = cloud({ version: "1.0.0", licensed: "1.0.0" });
  assert.equal(await refreshRuleBundle(home, c), "updated");
  assert.equal(await installed(), "1.0.0");
  assert.equal(c.calls.fetch[0].url, "https://api.example.test/api/v1/rules/update");
  assert.equal(c.calls.fetch[0].auth, "Bearer omx_case");
  // The cached key already matches, so no second licence check.
  assert.equal(c.calls.validate.length, 1);
  assert.ok(!c.calls.validate[0].force);
});

test("a current install sends its version and changes nothing on a 304", async () => {
  await setup({ installed: "1.0.0" });
  const c = cloud({ status: 304, licensed: "1.0.0" });
  assert.equal(await refreshRuleBundle(home, c), "current");
  assert.match(c.calls.fetch[0].url, /\?since=1\.0\.0$/);
  assert.equal(await installed(), "1.0.0");
  assert.equal(c.calls.validate.length, 1);
});

test("a new bundle whose key is not cached yet asks the licence check again, forced", async () => {
  await setup({ installed: "1.0.0" });
  const c = cloud({ version: "1.1.0", licensed: "1.0.0", afterForce: "1.1.0" });
  assert.equal(await refreshRuleBundle(home, c), "updated");
  assert.equal(await installed(), "1.1.0");
  assert.equal(c.calls.validate.length, 2);
  assert.equal(c.calls.validate[1].force, true);
});

test("a subscription that lapsed makes no bundle request", async () => {
  await setup({ installed: "1.0.0" });
  const c = cloud({ tier: "free", licensed: null });
  assert.equal(await refreshRuleBundle(home, c), "not-entitled");
  assert.equal(c.calls.fetch.length, 0);
});

test("refusals and failures leave the installed bundle alone", async () => {
  for (const [status, outcome] of [[403, "not-entitled"], [404, "no-bundle"], [500, "failed"], ["throw", "failed"]]) {
    await setup({ installed: "1.0.0" });
    assert.equal(await refreshRuleBundle(home, cloud({ status })), outcome, String(status));
    assert.equal(await installed(), "1.0.0", String(status));
  }
});

test("OMNODEX_RULES_REFRESH=0 turns it off", async () => {
  await setup();
  process.env.OMNODEX_RULES_REFRESH = "0";
  try {
    const c = cloud();
    assert.equal(await refreshRuleBundle(home, c), "disabled");
    assert.equal(c.calls.fetch.length, 0);
  } finally {
    delete process.env.OMNODEX_RULES_REFRESH;
  }
});

test("the background pass refreshes rules before it detects", async () => {
  const order = [];
  await runAutoSync(home, {
    refreshRules: async () => order.push("refresh"),
    detect: async () => {
      order.push("detect");
      return [];
    },
    pushFn: async () => true,
  });
  assert.deepEqual(order, ["refresh", "detect"]);
  assert.ok(!existsSync(path.join(home, RULE_BUNDLE_FILE)));
});
