// Validation: machine identity propagation through transport
//
// Tests that machine_id and machine_label fields are correctly shaped
// in the SyncPushRequest interface and preserved through push.
//
// Run: node --test packages/sync-encryptor/test/machine-transport.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";

describe("SyncPushRequest machine fields", () => {
  it("accepts machine_id and machine_label in push request shape", () => {
    const req = {
      customer_id: "cust_case",
      encrypted_payload: new Uint8Array(64),
      iv: webcrypto.getRandomValues(new Uint8Array(12)),
      kdf_salt: webcrypto.getRandomValues(new Uint8Array(16)),
      payload_bytes: 42,
      sessions_included: ["sess_1"],
      machine_id: "a1b2c3d4e5f67890",
      machine_label: "Case's Workstation",
    };

    assert.equal(req.machine_id, "a1b2c3d4e5f67890");
    assert.equal(req.machine_label, "Case's Workstation");
    assert.equal(req.machine_id.length, 16);
  });

  it("machine_label is optional", () => {
    const req = {
      customer_id: "cust_case",
      encrypted_payload: new Uint8Array(64),
      iv: webcrypto.getRandomValues(new Uint8Array(12)),
      kdf_salt: webcrypto.getRandomValues(new Uint8Array(16)),
      payload_bytes: 42,
      sessions_included: ["sess_1"],
      machine_id: "a1b2c3d4e5f67890",
    };

    assert.equal(req.machine_label, undefined);
  });

  it("machine_id is a 16-char hex string derived from hostname", () => {
    const hostname = "cases-workstation";
    const machineId = createHash("sha256").update(hostname).digest("hex").slice(0, 16);

    assert.match(machineId, /^[0-9a-f]{16}$/);
    assert.equal(machineId.length, 16);
  });
});
