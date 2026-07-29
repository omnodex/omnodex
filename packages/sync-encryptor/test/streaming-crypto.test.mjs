// Streaming key derivation: HKDF from Argon2id master key
//
// Validates that deriveStreamingKey() and computeKeyId() produce
// deterministic, distinct keys for different (passphrase, customerId) pairs.
// The streaming key is used for per-event AES-256-GCM encryption in the
// live streaming pipeline (CLI → cloud → browser).
//
// Run: node --test packages/sync-encryptor/test/streaming-crypto.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { argon2id } from "hash-wasm";

const { subtle } = webcrypto;

// ---------------------------------------------------------------------------
// Mirror the production functions (same logic as crypto.ts)
// ---------------------------------------------------------------------------

const KDF_PARAMS = {
  parallelism: 1,
  iterations: 3,
  memorySize: 65536,
  hashLength: 32,
  outputType: "binary",
};

const STREAMING_FIXED_SALT = new TextEncoder().encode("omnodex-stream-v1");
const STREAMING_INFO = new TextEncoder().encode("omnodex-stream-aes256gcm-v1");

async function hkdfDerive(ikm, salt, info, length) {
  const baseKey = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

async function deriveStreamingKey(passphrase, customerId) {
  const masterBytes = await argon2id({
    password: passphrase,
    salt: STREAMING_FIXED_SALT,
    ...KDF_PARAMS,
  });

  const customerSalt = new Uint8Array(
    await subtle.digest("SHA-256", new TextEncoder().encode(customerId)),
  );
  const streamKeyBytes = await hkdfDerive(
    masterBytes,
    customerSalt,
    STREAMING_INFO,
    32,
  );

  return subtle.importKey(
    "raw",
    streamKeyBytes,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

async function computeKeyId(key) {
  const raw = await subtle.exportKey("raw", key);
  const hash = Array.from(new Uint8Array(await subtle.digest("SHA-256", raw)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hash.slice(0, 8);
}

async function exportKeyBytes(key) {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Streaming key derivation (HKDF from Argon2id)", () => {
  it("deriveStreamingKey is deterministic: same inputs → same key", async () => {
    const k1 = await deriveStreamingKey("my-passphrase", "cust_abc123");
    const k2 = await deriveStreamingKey("my-passphrase", "cust_abc123");
    assert.deepEqual(await exportKeyBytes(k1), await exportKeyBytes(k2));
  });

  it("different passphrases produce different streaming keys", async () => {
    const k1 = await deriveStreamingKey("passphrase-A", "cust_abc123");
    const k2 = await deriveStreamingKey("passphrase-B", "cust_abc123");
    assert.notDeepEqual(await exportKeyBytes(k1), await exportKeyBytes(k2));
  });

  it("different customer IDs produce different streaming keys", async () => {
    const k1 = await deriveStreamingKey("same-passphrase", "cust_111");
    const k2 = await deriveStreamingKey("same-passphrase", "cust_222");
    assert.notDeepEqual(await exportKeyBytes(k1), await exportKeyBytes(k2));
  });

  it("streaming key differs from blob-sync key (different salt)", async () => {
    const passphrase = "compare-keys";
    const streamKey = await deriveStreamingKey(passphrase, "cust_abc");

    // Blob-sync key uses a random salt; streaming uses fixed salt + HKDF.
    // Even with the same passphrase, the keys must differ.
    const randomSalt = webcrypto.getRandomValues(new Uint8Array(16));
    const blobKeyBytes = await argon2id({
      password: passphrase,
      salt: randomSalt,
      ...KDF_PARAMS,
    });
    assert.notDeepEqual(await exportKeyBytes(streamKey), blobKeyBytes);
  });

  it("streaming key can encrypt and decrypt", async () => {
    const key = await deriveStreamingKey("encrypt-test", "cust_xyz");
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify({ event: "tool.invoked", ts: 1234 }));

    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    assert.deepEqual(new Uint8Array(pt), plaintext);
  });

  it("computeKeyId returns 8 hex chars", async () => {
    const key = await deriveStreamingKey("keyid-test", "cust_123");
    const kid = await computeKeyId(key);
    assert.equal(kid.length, 8);
    assert.match(kid, /^[0-9a-f]{8}$/);
  });

  it("computeKeyId is deterministic", async () => {
    const k1 = await deriveStreamingKey("same", "cust_same");
    const k2 = await deriveStreamingKey("same", "cust_same");
    assert.equal(await computeKeyId(k1), await computeKeyId(k2));
  });

  it("computeKeyId differs for different keys", async () => {
    const k1 = await deriveStreamingKey("pass-A", "cust_A");
    const k2 = await deriveStreamingKey("pass-B", "cust_B");
    assert.notEqual(await computeKeyId(k1), await computeKeyId(k2));
  });

  it("logs streaming key derivation timing", async () => {
    const t0 = performance.now();
    await deriveStreamingKey("timing-test", "cust_perf");
    const ms = (performance.now() - t0).toFixed(1);
    console.log("    Streaming key derivation (Argon2id + HKDF): " + ms + "ms");
    assert.ok(true);
  });
});
