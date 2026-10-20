// Validation: a Pro install keeps its guardrails module and its key current,
// asks only for modules its interface can run, and everyone else costs
// nothing.
//
// Run: node --test packages/sync-encryptor/test/guardrails-refresh.test.mjs

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import {
  refreshGuardrailsModule,
  guardrailsEntitled,
  GUARDRAILS_MODULE_FILE,
} from "../dist/guardrails-refresh.js";

let home;
beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-guardrails-refresh-"));
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

const write = (file, value) => writeFile(path.join(home, file), JSON.stringify(value), "utf8");
const sealed = (version, iface = 1) => ({ manifest: { kind: "guardrails-module", module_version: version, interface: iface }, signature: "sig", payload: "p" });
const grant = (version) => ({ interface: 1, module_version: version, content_key: `key-${version}`, not_after: "2099-01-01T00:00:00.000Z" });

async function setup({ tier = "pro", installed = null } = {}) {
  await write("stream-config.json", { api_token: "omx_case", passphrase: "p", api_url: "https://api.example.test/" });
  await write("license-cache.json", { response: { customer_id: "cus_case", tier, features: [] }, fetched_at: Date.now() });
  if (installed) {
    await mkdir(path.join(home, "guardrails"), { recursive: true });
    await write(GUARDRAILS_MODULE_FILE, installed);
  }
}

function cloud({ status = 200, version = "1.0.0", licensed = "1.0.0", tier = "pro", afterForce = null } = {}) {
  const calls = { fetch: [], validate: [] };
  return {
    calls,
    fetchFn: async (url, init) => {
      calls.fetch.push({ url, auth: init?.headers?.Authorization });
      if (status === "throw") throw new Error("offline");
      const body = status === 200 ? { module_version: version, module: sealed(version) } : { error: "x" };
      return new Response(status === 304 ? null : JSON.stringify(body), { status });
    },
    validate: async (config) => {
      calls.validate.push(config);
      const v = config.force && afterForce ? afterForce : licensed;
      return { source: "network", license: { customer_id: "cus_case", tier, features: [], ttl_seconds: 86400, ...(v ? { guardrails_module: grant(v) } : {}) } };
    },
  };
}

const installedVersion = async () => JSON.parse(await readFile(path.join(home, GUARDRAILS_MODULE_FILE), "utf8")).manifest.module_version;

test("a free or Hosted install makes no request and is not entitled", async () => {
  for (const tier of ["free", "hosted"]) {
    await setup({ tier });
    const c = cloud();
    assert.equal(await refreshGuardrailsModule(home, c), "not-entitled");
    assert.deepEqual(c.calls, { fetch: [], validate: [] }, tier);
    assert.equal(await guardrailsEntitled(home), false);
  }
});

test("an install with no API token makes no request", async () => {
  const c = cloud();
  assert.equal(await refreshGuardrailsModule(home, c), "no-credentials");
  assert.deepEqual(c.calls, { fetch: [], validate: [] });
});

test("a Pro install fetches the module for its interface, authenticated", async () => {
  await setup();
  assert.equal(await guardrailsEntitled(home), true);
  const c = cloud();
  assert.equal(await refreshGuardrailsModule(home, c), "updated");
  assert.equal(await installedVersion(), "1.0.0");
  assert.equal(c.calls.fetch[0].url, "https://api.example.test/api/v1/guardrails/update?interface=1");
  assert.equal(c.calls.fetch[0].auth, "Bearer omx_case");
});

test("an installed module is named, and a 304 keeps it", async () => {
  await setup({ installed: sealed("1.2.0") });
  const c = cloud({ status: 304, licensed: "1.2.0" });
  assert.equal(await refreshGuardrailsModule(home, c), "current");
  assert.equal(c.calls.fetch[0].url, "https://api.example.test/api/v1/guardrails/update?interface=1&since=1.2.0");
});

test("a module for another interface is not named as installed", async () => {
  await setup({ installed: sealed("1.2.0", 2) });
  const c = cloud();
  await refreshGuardrailsModule(home, c);
  assert.equal(c.calls.fetch[0].url, "https://api.example.test/api/v1/guardrails/update?interface=1");
});

test("a newer module than the cached key asks for the key at once", async () => {
  await setup();
  const c = cloud({ version: "2.0.0", licensed: "1.0.0", afterForce: "2.0.0" });
  assert.equal(await refreshGuardrailsModule(home, c), "updated");
  assert.equal(c.calls.validate.length, 2);
  assert.equal(c.calls.validate[1].force, true);
});

test("after a current answer it waits, unless forced", async () => {
  await setup({ installed: sealed("1.0.0") });
  assert.equal(await refreshGuardrailsModule(home, cloud({ status: 304 })), "current");
  const c = cloud({ status: 304 });
  assert.equal(await refreshGuardrailsModule(home, c), "waiting");
  assert.equal(c.calls.fetch.length, 0);
  assert.equal(await refreshGuardrailsModule(home, { ...c, force: true }), "current");
});

test("nothing published, a refusal, or a failure leaves what was there", async () => {
  await setup({ installed: sealed("1.0.0") });
  assert.equal(await refreshGuardrailsModule(home, cloud({ status: 404 })), "no-module");
  assert.equal(await refreshGuardrailsModule(home, { ...cloud({ status: 403 }), force: true }), "not-entitled");
  assert.equal(await refreshGuardrailsModule(home, { ...cloud({ status: "throw" }), force: true }), "failed");
  assert.equal(await installedVersion(), "1.0.0");
});

test("a license that lapsed on revalidation stops before fetching", async () => {
  await setup();
  const c = cloud({ tier: "hosted" });
  assert.equal(await refreshGuardrailsModule(home, c), "not-entitled");
  assert.equal(c.calls.fetch.length, 0);
});

test("the installed module's expiry is named, so a renewal of the same version is offered", async () => {
  const held = sealed("1.2.0");
  held.manifest.not_after = "2026-11-18T22:17:35.216Z";
  await setup({ installed: held });
  const c = cloud({ version: "1.2.0", licensed: "1.2.0" });
  assert.equal(await refreshGuardrailsModule(home, c), "updated");
  assert.equal(
    c.calls.fetch[0].url,
    "https://api.example.test/api/v1/guardrails/update?interface=1&since=1.2.0&not_after=2026-11-18T22%3A17%3A35.216Z",
  );
  // Same version, so the cached key still opens it: no forced license check.
  assert.equal(c.calls.validate.length, 1);
});
