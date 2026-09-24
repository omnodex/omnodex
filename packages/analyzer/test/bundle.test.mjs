/**
 * Advanced rule bundle tests.
 *
 * A bundle is shared by every entitled customer and opened on their machine,
 * so the checks are the product: it must refuse anything we did not sign,
 * anything altered, and anything past its expiry, and it must never take a
 * host down by throwing. A refused bundle means community rules and a reason,
 * not an error.
 *
 * Run: node --test packages/analyzer/test/bundle.test.mjs
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

import {
  openBundle,
  loadAdvancedRules,
  bundlePath,
  describeRules,
  RULES_KEY_ENV,
  RULES_PUBLIC_KEY_ENV,
  TRUSTED_PUBLISHING_KEYS,
} from "../dist/bundle.js";
import {
  createEvaluator,
  loadRegistry,
  registryForHost,
  HOST_TIERS,
} from "../dist/evaluator.js";
import { COMMUNITY_RULES } from "../dist/rules/index.js";
import { makeBundle, signedByStranger, ADVANCED_RULE } from "./helpers/make-bundle.mjs";

let home;
beforeEach(() => {
  home = mkdtempSync(path.join(os.tmpdir(), "omnodex-bundle-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env[RULES_KEY_ENV];
  delete process.env[RULES_PUBLIC_KEY_ENV];
});

/** Install a sealed bundle into `home` and trust the key that signed it. */
function install(made = makeBundle()) {
  mkdirSync(path.dirname(bundlePath(home)), { recursive: true });
  writeFileSync(bundlePath(home), JSON.stringify(made.bundle), "utf8");
  process.env[RULES_PUBLIC_KEY_ENV] = made.publicKeyBase64;
  process.env[RULES_KEY_ENV] = made.keyBase64;
  return made;
}

const open = (made, opts = {}) =>
  openBundle(made.bundle, {
    key: Buffer.from(made.keyBase64, "base64"),
    env: { [RULES_PUBLIC_KEY_ENV]: made.publicKeyBase64 },
    ...opts,
  });

// ---------------------------------------------------------------------------

describe("openBundle", () => {
  it("opens a bundle we signed, with the key for it", () => {
    const made = makeBundle();
    const result = open(made);
    assert.equal(result.skipped, undefined);
    assert.equal(result.rules.length, 1);
    assert.equal(result.rules[0].rule_id, ADVANCED_RULE.rule_id);
    assert.equal(result.manifest.channel, "pro");
  });

  it("marks every rule in it advanced, whatever the payload claimed", () => {
    const made = makeBundle({
      rules: [{ ...ADVANCED_RULE, tier: "community" }],
    });
    assert.equal(open(made).rules[0].tier, "advanced");
  });

  it("refuses a bundle signed by a key this client does not trust", () => {
    const made = signedByStranger();
    assert.equal(open(made).skipped, "untrusted_signature");
  });

  it("refuses a bundle whose payload was altered after signing", () => {
    const made = makeBundle({ tamper: true });
    assert.equal(open(made).skipped, "payload_mismatch");
  });

  it("refuses a bundle past its not_after", () => {
    const made = makeBundle({ notAfter: new Date(Date.now() - 1000) });
    assert.equal(open(made).skipped, "expired");
    // And the same bundle is fine before that moment.
    const fresh = makeBundle({ notAfter: new Date(Date.now() + 60_000) });
    assert.equal(open(fresh).skipped, undefined);
  });

  it("reports a missing key separately from a wrong one", () => {
    const made = makeBundle();
    assert.equal(open(made, { key: null, env: { [RULES_PUBLIC_KEY_ENV]: made.publicKeyBase64 } }).skipped, "no_key");
    assert.equal(open(made, { key: crypto.randomBytes(32) }).skipped, "undecryptable");
  });

  it("refuses a payload that opens but is not rules", () => {
    const made = makeBundle({ rules: [{ nope: true }] });
    assert.equal(open(made).skipped, "malformed_rules");
  });

  it("refuses anything that is not a bundle at all, without throwing", () => {
    for (const junk of [null, undefined, 42, "text", {}, { manifest: {} }]) {
      assert.equal(openBundle(junk).skipped, "unreadable");
    }
  });

  it("trusts no publishing key until one is shipped", () => {
    // The production key lands with the distributor (ENG-342). Until then a
    // bundle opens only against a key named in the environment, which is how
    // advanced rules are developed before any cloud side exists.
    assert.deepEqual([...TRUSTED_PUBLISHING_KEYS], []);
    const made = makeBundle();
    assert.equal(openBundle(made.bundle, { key: made.contentKey, env: {} }).skipped, "untrusted_signature");
  });
});

describe("loadAdvancedRules", () => {
  it("reads the bundle a home has installed", () => {
    const made = install();
    const result = loadAdvancedRules(home);
    assert.equal(result.skipped, undefined);
    assert.equal(result.rules[0].rule_id, ADVANCED_RULE.rule_id);
    assert.equal(result.manifest.bundle_version, made.bundle.manifest.bundle_version);
  });

  it("says so when a home has none", () => {
    assert.equal(loadAdvancedRules(home).skipped, "none_cached");
  });

  it("says so when the file is not JSON", () => {
    mkdirSync(path.dirname(bundlePath(home)), { recursive: true });
    writeFileSync(bundlePath(home), "not json", "utf8");
    assert.equal(loadAdvancedRules(home).skipped, "unreadable");
  });

  it("reads a bundle from an explicit path, for local development", () => {
    const made = makeBundle();
    const file = path.join(home, "dev.bundle.json");
    writeFileSync(file, JSON.stringify(made.bundle), "utf8");
    const result = loadAdvancedRules(home, {
      file,
      key: made.contentKey,
      env: { [RULES_PUBLIC_KEY_ENV]: made.publicKeyBase64 },
    });
    assert.equal(result.skipped, undefined);
  });
});

describe("host tiers", () => {
  it("runs advanced rules in long-lived hosts and never in a hook", () => {
    assert.deepEqual(HOST_TIERS, {
      hook: ["community"],
      proxy: ["community", "advanced"],
      batch: ["community", "advanced"],
    });
  });

  it("gives a hook the community set even when a bundle is installed", () => {
    install();
    const rules = registryForHost("hook", home).getRules();
    assert.equal(rules.length, COMMUNITY_RULES.length);
    assert.ok(!rules.some((r) => r.tier === "advanced"));
  });

  it("gives the proxy and the batch pass the community set plus the bundle", () => {
    install();
    for (const host of ["proxy", "batch"]) {
      const rules = registryForHost(host, home).getRules();
      assert.equal(rules.length, COMMUNITY_RULES.length + 1, host);
      assert.equal(rules.filter((r) => r.tier === "advanced").length, 1, host);
    }
  });

  it("falls back to the community set when the bundle cannot be opened", () => {
    install(signedByStranger());
    const rules = registryForHost("proxy", home).getRules();
    assert.equal(rules.length, COMMUNITY_RULES.length);
  });

  it("an evaluator built without a registry picks the set its host may run", () => {
    install();
    const ids = (host) =>
      createEvaluator({ host, newEventId: () => "x", home }).rules.map((r) => r.rule_id);
    assert.ok(!ids("hook").includes(ADVANCED_RULE.rule_id));
    assert.ok(ids("batch").includes(ADVANCED_RULE.rule_id));
  });
});

describe("loadRegistry", () => {
  it("returns the community set on its own when handed nothing", () => {
    assert.equal(loadRegistry(home).getRules().length, COMMUNITY_RULES.length);
    assert.equal(loadRegistry(home, { advanced: [] }).getRules().length, COMMUNITY_RULES.length);
    assert.equal(loadRegistry(home, { advanced: null }).getRules().length, COMMUNITY_RULES.length);
  });

  it("appends advanced rules after the community ones, keeping both", () => {
    const registry = loadRegistry(home, { advanced: [{ ...ADVANCED_RULE }] });
    assert.equal(registry.getCommunityRules().length, COMMUNITY_RULES.length);
    assert.equal(registry.getAdvancedRules().length, 1);
  });
});

describe("describeRules", () => {
  it("says what is loaded", () => {
    const made = install();
    const line = describeRules(loadAdvancedRules(home), COMMUNITY_RULES.length);
    assert.match(line, new RegExp(`^${COMMUNITY_RULES.length} community, 1 advanced \\(pro bundle 1.0.0`));
    assert.ok(line.includes(made.bundle.manifest.not_after));
  });

  it("says why nothing is, in words a person can act on", () => {
    assert.match(
      describeRules(loadAdvancedRules(home), COMMUNITY_RULES.length),
      /no advanced rules \(none installed\)/,
    );
    install();
    delete process.env[RULES_KEY_ENV];
    assert.match(
      describeRules(loadAdvancedRules(home), COMMUNITY_RULES.length),
      /no advanced rules \(installed, but no key to open it \(subscription needed\)\)/,
    );
  });
});
