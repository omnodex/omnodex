// Validation: sealed labels
//
// The machine label leaves the machine sealed under a key derived from the
// stream secret. The fixed vector is shared with the hosted dashboard, which
// opens the same values in the browser.
//
// Run: node --test packages/sync-encryptor/test/machine-label.test.mjs

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import * as os from "node:os";
import * as path from "node:path";
import { promises as fs } from "node:fs";

import { SEALED_LABEL_RE, deriveLabelKey, openLabel, sealLabel, sealedMachineLabel } from "../dist/machine-label.js";

const SECRET = "case vector secret";
/** Sealed with SECRET, nonce 00 01 .. 0b, field machine_label. */
const VECTOR = { label: "case-laptop", sealed: "v1.AAECAwQFBgcICQoL.JeCZy4rYuO9qDxZfdMIm--DbEKGFVTF9-rek" };

describe("sealed labels", () => {
  it("match the shared vector", async () => {
    const key = await deriveLabelKey(SECRET);
    const iv = Uint8Array.from({ length: 12 }, (_, i) => i);
    assert.equal(await sealLabel(key, "machine_label", VECTOR.label, iv), VECTOR.sealed);
    assert.equal(await openLabel(key, "machine_label", VECTOR.sealed), VECTOR.label);
  });

  it("take a fresh nonce each time and open back to the label", async () => {
    const key = await deriveLabelKey(SECRET);
    const a = await sealLabel(key, "machine_label", "Case's Workstation");
    const b = await sealLabel(key, "machine_label", "Case's Workstation");
    assert.notEqual(a, b);
    for (const s of [a, b]) {
      assert.match(s, SEALED_LABEL_RE);
      assert.equal(await openLabel(key, "machine_label", s), "Case's Workstation");
    }
  });

  it("do not open under another secret, or when altered", async () => {
    const other = await deriveLabelKey("another case secret");
    assert.equal(await openLabel(other, "machine_label", VECTOR.sealed), undefined);
    const key = await deriveLabelKey(SECRET);
    const flipped = VECTOR.sealed.slice(0, -2) + (VECTOR.sealed.endsWith("A") ? "B" : "A") + VECTOR.sealed.slice(-1);
    assert.equal(await openLabel(key, "machine_label", flipped), undefined);
    assert.equal(await openLabel(key, "machine_label", "case-laptop"), undefined);
  });
});

describe("sealedMachineLabel", () => {
  const homes = [];
  after(async () => { for (const h of homes) await fs.rm(h, { recursive: true, force: true }); });

  it("seals the configured label, prefers an explicit one, and sends nothing without one", async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-label-"));
    homes.push(home);
    const key = await deriveLabelKey(SECRET);
    assert.equal(await sealedMachineLabel(SECRET, home), undefined);
    await fs.writeFile(path.join(home, "config.json"), JSON.stringify({ machine: { label: "case-desk" } }));
    assert.equal(await openLabel(key, "machine_label", await sealedMachineLabel(SECRET, home)), "case-desk");
    assert.equal(await openLabel(key, "machine_label", await sealedMachineLabel(SECRET, home, "case-other")), "case-other");
  });
});
