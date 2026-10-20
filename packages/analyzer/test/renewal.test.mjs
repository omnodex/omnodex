/**
 * Renewals: a renewal key may extend what a publishing key signed, and
 * nothing else.
 *
 * The renewal key lives on a server, so these tests are the boundary: a
 * renewal opens only with an in-date endorsement from a publishing key, an
 * origin the publishing key signed, a manifest that differs from it only in
 * not_after, and nothing this home has already seen superseded.
 *
 * Run: node --test packages/analyzer/test/renewal.test.mjs
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

import { openBundle, loadAdvancedRules, bundlePath, canonicalManifest, RULES_PUBLIC_KEY_ENV } from "../dist/bundle.js";
import { canonicalEndorsement, TRUST_STATE_FILE } from "../dist/renewal.js";
import { canonicalModuleManifest, loadGuardrailsModule } from "../dist/enforcement/module.js";
import { makeBundle } from "./helpers/make-bundle.mjs";
import { installModule } from "./helpers/make-module.mjs";

const DAY = 86_400_000;
const iso = (ms) => new Date(Date.now() + ms).toISOString();
const spki = (key) => key.export({ type: "spki", format: "der" }).toString("base64");

/** The publishing key every test trusts through the development variable. */
const publisher = crypto.generateKeyPairSync("ed25519");
const renewalKey = crypto.generateKeyPairSync("ed25519");

function endorse(overrides = {}, signer = publisher.privateKey) {
  const statement = {
    kind: "renewal-key-endorsement",
    serial: 1,
    public_key: spki(renewalKey.publicKey),
    valid_from: iso(-DAY),
    valid_until: iso(180 * DAY),
    allowed: ["guardrails-module", "rule-bundle"],
    ...overrides,
  };
  return { statement, signature: crypto.sign(null, canonicalEndorsement(statement), signer).toString("base64") };
}

/**
 * Re-sign a sealed artifact with a later not_after, as the cloud's renewal
 * job does. `change` edits the renewed manifest further, for the attacks.
 */
function renew(sealed, canonical, { notAfter = iso(30 * DAY), endorsement = endorse(), signer = renewalKey.privateKey, change = (m) => m } = {}) {
  const manifest = change({ ...sealed.manifest, not_after: notAfter });
  return {
    ...sealed,
    manifest,
    signature: crypto.sign(null, canonical(manifest), signer).toString("base64"),
    renewal: { endorsement, origin: { manifest: sealed.manifest, signature: sealed.signature } },
  };
}

let home;
beforeEach(() => {
  home = mkdtempSync(path.join(os.tmpdir(), "omnodex-renewal-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const env = { [RULES_PUBLIC_KEY_ENV]: spki(publisher.publicKey) };
/** A bundle published with the trusted key, already past its own expiry. */
const published = (overrides = {}) => makeBundle({ signingKey: publisher, notAfter: iso(-DAY), ...overrides });
const open = (made, bundle, extra = {}) => openBundle(bundle, { key: made.contentKey, env, home, ...extra });

describe("rule bundle renewal", () => {
  it("opens a renewal of a published bundle past its original expiry", () => {
    const made = published();
    assert.equal(open(made, made.bundle).skipped, "expired");
    const result = open(made, renew(made.bundle, canonicalManifest));
    assert.equal(result.skipped, undefined);
    assert.equal(result.rules.length, 1);
  });

  it("refuses a renewal key signature without an endorsement", () => {
    const made = published();
    const renewed = renew(made.bundle, canonicalManifest);
    delete renewed.renewal;
    assert.equal(open(made, renewed).skipped, "untrusted_signature");
  });

  it("refuses an endorsement no publishing key signed", () => {
    const stranger = crypto.generateKeyPairSync("ed25519");
    const made = published();
    const renewed = renew(made.bundle, canonicalManifest, { endorsement: endorse({}, stranger.privateKey) });
    assert.equal(open(made, renewed).skipped, "untrusted_signature");
  });

  it("refuses a signature by a key other than the endorsed one", () => {
    const made = published();
    const other = crypto.generateKeyPairSync("ed25519");
    assert.equal(open(made, renew(made.bundle, canonicalManifest, { signer: other.privateKey })).skipped, "untrusted_signature");
  });

  it("refuses an endorsement that does not cover rule bundles", () => {
    const made = published();
    const renewed = renew(made.bundle, canonicalManifest, { endorsement: endorse({ allowed: ["guardrails-module"] }) });
    assert.equal(open(made, renewed).skipped, "untrusted_signature");
  });

  it("refuses an endorsement out of date, or a renewal past the endorsement", () => {
    const made = published();
    for (const endorsement of [
      endorse({ valid_until: iso(-1000) }),
      endorse({ valid_from: iso(DAY) }),
      endorse({ valid_until: iso(10 * DAY) }),
    ]) {
      assert.equal(open(made, renew(made.bundle, canonicalManifest, { endorsement })).skipped, "untrusted_signature");
    }
  });

  it("refuses a renewal that changes anything but not_after", () => {
    const made = published();
    const changes = [
      (m) => ({ ...m, payload_sha256: crypto.createHash("sha256").update("other code").digest("hex") }),
      (m) => ({ ...m, bundle_version: "9.9.9" }),
      (m) => ({ ...m, channel: "enterprise" }),
      (m) => ({ ...m, created_at: iso(0) }),
      (m) => ({ ...m, rules: [...m.rules, { rule_id: "RULE_SMUGGLED", version: "1.0.0" }] }),
    ];
    for (const change of changes) {
      assert.equal(open(made, renew(made.bundle, canonicalManifest, { change })).skipped, "untrusted_signature");
    }
  });

  it("refuses an origin no publishing key signed", () => {
    const made = makeBundle({ notAfter: iso(-DAY) });
    assert.equal(open(made, renew(made.bundle, canonicalManifest)).skipped, "untrusted_signature");
  });

  it("a newer endorsement retires older ones on this home", () => {
    const made = published();
    assert.equal(open(made, renew(made.bundle, canonicalManifest, { endorsement: endorse({ serial: 2 }) })).skipped, undefined);
    assert.equal(JSON.parse(readFileSync(path.join(home, TRUST_STATE_FILE), "utf8")).endorsement_serial, 2);
    assert.equal(open(made, renew(made.bundle, canonicalManifest, { endorsement: endorse({ serial: 1 }) })).skipped, "untrusted_signature");
  });

  it("refuses a renewal of something a later publish replaced, and a revert moves the floor", () => {
    const old = published({ createdAt: iso(-20 * DAY), version: "1.0.0" });
    const newer = makeBundle({ signingKey: publisher, createdAt: iso(-DAY), version: "1.1.0" });
    assert.equal(open(newer, newer.bundle).skipped, undefined);
    assert.equal(open(old, renew(old.bundle, canonicalManifest)).skipped, "untrusted_signature");

    // Reverting is a publish: it opens whatever its version, and can be renewed.
    const revert = makeBundle({ signingKey: publisher, version: "1.0.0", notAfter: iso(-1000) });
    assert.equal(open(revert, renew(revert.bundle, canonicalManifest)).skipped, undefined);
  });

  it("never holds a publish to the floor", () => {
    const newer = makeBundle({ signingKey: publisher, createdAt: iso(-DAY) });
    assert.equal(open(newer, newer.bundle).skipped, undefined);
    const older = makeBundle({ signingKey: publisher, createdAt: iso(-20 * DAY) });
    assert.equal(open(older, older.bundle).skipped, undefined);
  });

  it("loadAdvancedRules applies this home's floors", () => {
    const made = published();
    mkdirSync(path.dirname(bundlePath(home)), { recursive: true });
    writeFileSync(bundlePath(home), JSON.stringify(renew(made.bundle, canonicalManifest, { endorsement: endorse({ serial: 3 }) })));
    const loaded = loadAdvancedRules(home, { key: made.contentKey, env });
    assert.equal(loaded.skipped, undefined);
    assert.equal(JSON.parse(readFileSync(path.join(home, TRUST_STATE_FILE), "utf8")).endorsement_serial, 3);
  });

  it("an unreadable trust state means no floors, not a failure", () => {
    writeFileSync(path.join(home, TRUST_STATE_FILE), "{ not json");
    const made = published();
    assert.equal(open(made, renew(made.bundle, canonicalManifest)).skipped, undefined);
  });
});

describe("guardrails module renewal", () => {
  it("opens a renewed module, and only with an endorsement that covers modules", async () => {
    const m = installModule(home, { signingKey: publisher, notAfter: iso(-DAY) });
    const moduleEnv = { OMNODEX_GUARDRAILS_PUBLIC_KEY: spki(publisher.publicKey), OMNODEX_GUARDRAILS_KEY: m.contentKey.toString("base64") };
    const file = path.join(home, "guardrails", "current.module.json");
    assert.equal((await loadGuardrailsModule(home, { env: moduleEnv })).skipped, "expired");

    writeFileSync(file, JSON.stringify(renew(m.sealed, canonicalModuleManifest, { endorsement: endorse({ allowed: ["rule-bundle"] }) })));
    assert.equal((await loadGuardrailsModule(home, { env: moduleEnv })).skipped, "untrusted_signature");

    writeFileSync(file, JSON.stringify(renew(m.sealed, canonicalModuleManifest)));
    const load = await loadGuardrailsModule(home, { env: moduleEnv });
    assert.equal(load.skipped, undefined);
    assert.equal(typeof load.module.decide, "function");
  });

  it("refuses a renewed module whose code changed", async () => {
    const m = installModule(home, { signingKey: publisher, notAfter: iso(-DAY) });
    const moduleEnv = { OMNODEX_GUARDRAILS_PUBLIC_KEY: spki(publisher.publicKey), OMNODEX_GUARDRAILS_KEY: m.contentKey.toString("base64") };
    const other = installModule(path.join(home, "other"), { source: "export const GUARDRAILS_INTERFACE = 1; export function decide() { return { action: 'alert_only', held: [], output: null }; }" });
    const swapped = renew(m.sealed, canonicalModuleManifest, { change: (man) => ({ ...man, payload_sha256: other.sealed.manifest.payload_sha256 }) });
    swapped.payload = other.sealed.payload;
    writeFileSync(path.join(home, "guardrails", "current.module.json"), JSON.stringify(swapped));
    assert.equal((await loadGuardrailsModule(home, { env: moduleEnv })).skipped, "untrusted_signature");
  });
});
