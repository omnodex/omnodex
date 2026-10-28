// Validation: the account's finding policy, sealed per stream and pulled
//
// A copy sealed with one stream's policy key opens only with that key. The
// pull keeps the last copy on 304, drops it on 404, makes no request
// without credentials or on the free plan, and never replaces a good copy
// with one it cannot open.
//
// Run: node --test packages/sync-encryptor/test/account-policy.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  derivePolicyKey,
  sealPolicy,
  openPolicy,
  pullAccountPolicy,
  readPulledPolicy,
  ACCOUNT_POLICY_FILE,
} from "../dist/account-policy.js";

const CUSTOMER_ID = "cust_case";
const PASSPHRASE = "case-passphrase";
const ENTRIES = [
  { id: "a1", match: { rule_id: "RULE_SENSITIVE_PATH_READ", target: { path: "~/work/app/.env.example" } }, effect: { verdict: "allow" }, created_by: "dashboard" },
  { id: "a2", match: { category: "unexpected_network_destination" }, effect: { severity: "CRITICAL" }, created_by: "dashboard" },
];

let key;
let home;
beforeEach(async () => {
  key ??= await derivePolicyKey(PASSPHRASE, CUSTOMER_ID);
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-policy-pull-"));
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

async function writeCredentials(tier = "hosted") {
  await writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_test_case", stream_secret: PASSPHRASE, api_url: "http://api.case.invalid" }));
  await writeFile(path.join(home, "license-cache.json"), JSON.stringify({ response: { customer_id: CUSTOMER_ID, tier } }));
}

/** A fetch that answers from a list and records what it was asked. */
function fakeFetch(answers) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, headers: init.headers });
    const a = answers.shift();
    return new Response(a.body === undefined ? null : JSON.stringify(a.body), { status: a.status });
  };
  return { fn, calls };
}

describe("sealing", () => {
  it("round-trips entries, and the ciphertext names none of them", async () => {
    const sealed = await sealPolicy(ENTRIES, key);
    assert.deepEqual(await openPolicy(sealed, key), ENTRIES);
    assert.equal(Buffer.from(sealed.ct, "base64").toString("latin1").includes("RULE_SENSITIVE_PATH_READ"), false);
  });

  it("does not open with another stream's key, or with the live stream key's passphrase scope", async () => {
    const sealed = await sealPolicy(ENTRIES, key);
    await assert.rejects(openPolicy(sealed, await derivePolicyKey(PASSPHRASE, "cust_other")));
    await assert.rejects(openPolicy(sealed, await derivePolicyKey("another-passphrase", CUSTOMER_ID)));
  });

  it("drops entries this client cannot read, one by one", async () => {
    const sealed = await sealPolicy([...ENTRIES, { id: "bad", match: {}, effect: { verdict: "deny" } }], key);
    assert.deepEqual((await openPolicy(sealed, key)).map((e) => e.id), ["a1", "a2"]);
  });
});

describe("pullAccountPolicy", () => {
  it("stores a new copy, then asks with its version and keeps it on 304", async () => {
    await writeCredentials();
    const sealed = await sealPolicy(ENTRIES, key);
    const f = fakeFetch([{ status: 200, body: { customer_id: CUSTOMER_ID, version: 3, ...sealed } }, { status: 304 }]);

    const first = await pullAccountPolicy(home, { fetchFn: f.fn });
    assert.deepEqual(first, { outcome: "updated", version: 3, entries: 2 });
    assert.equal(f.calls[0].url, "http://api.case.invalid/api/v1/policy");
    assert.equal(f.calls[0].headers.Authorization, "Bearer omx_test_case");
    assert.deepEqual((await readPulledPolicy(home)).entries, ENTRIES);

    const second = await pullAccountPolicy(home, { fetchFn: f.fn });
    assert.equal(second.outcome, "current");
    assert.equal(f.calls[1].headers["If-None-Match"], '"v3"');
    assert.equal((await readPulledPolicy(home)).version, 3);
  });

  it("drops the copy when the account no longer has one", async () => {
    await writeCredentials();
    await writeFile(path.join(home, ACCOUNT_POLICY_FILE), JSON.stringify({ version: 1, pulled_at: "", entries: ENTRIES }));
    const f = fakeFetch([{ status: 404, body: { error: "no_policy" } }]);
    assert.equal((await pullAccountPolicy(home, { fetchFn: f.fn })).outcome, "none");
    assert.equal(await readPulledPolicy(home), null);
  });

  it("keeps the last good copy when a new one cannot be opened or the request fails", async () => {
    await writeCredentials();
    await writeFile(path.join(home, ACCOUNT_POLICY_FILE), JSON.stringify({ version: 1, pulled_at: "", entries: ENTRIES }));
    const wrong = await sealPolicy([], await derivePolicyKey(PASSPHRASE, "cust_other"));
    const f = fakeFetch([{ status: 200, body: { version: 2, ...wrong } }, { status: 500, body: {} }]);
    assert.equal((await pullAccountPolicy(home, { fetchFn: f.fn })).outcome, "failed");
    assert.equal((await pullAccountPolicy(home, { fetchFn: f.fn })).outcome, "failed");
    const kept = JSON.parse(await readFile(path.join(home, ACCOUNT_POLICY_FILE), "utf8"));
    assert.equal(kept.version, 1);
  });

  it("makes no request without credentials, or on the free plan", async () => {
    const f = fakeFetch([]);
    assert.equal((await pullAccountPolicy(home, { fetchFn: f.fn })).outcome, "no-credentials");
    await writeCredentials("free");
    assert.equal((await pullAccountPolicy(home, { fetchFn: f.fn })).outcome, "none");
    assert.equal(f.calls.length, 0);
  });
});
