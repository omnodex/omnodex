// T025 validation: Argon2id KDF + AES-256-GCM pipeline
//
// Validates that the full zero-knowledge sync encryption pipeline works in
// Node.js 22 using Argon2id (hash-wasm) for key derivation and the built-in
// Web Crypto API for AES-256-GCM. No paid service tiers required -- this runs
// entirely client-side (local CLI or browser). The Cloudflare Worker only ever
// receives and stores the already-encrypted blob; it never runs the KDF.
//
// hash-wasm is the same WASM bundle used for browser-side KDF in the hosted
// dashboard. The deriveKey() function here is the intended final implementation
// for packages/sync-encryptor (T027) -- not a stand-in.
//
// Argon2id parameters chosen for the local CLI context:
//   memorySize: 64 MB  -- OWASP 2023 minimum for interactive login
//   iterations: 3      -- time cost, paired with memory
//   parallelism: 1     -- single-threaded; matches browser and CF Worker constraints
//   hashLength: 32     -- 256 bits for AES-256-GCM
//
// For browser dashboard use (T028), memorySize may be tuned down to 16-32 MB
// depending on observed latency on low-end hardware. Same interface, just a
// lower m_cost constant.
//
// Run: node --test packages/sync-encryptor/test/kdf-crypto.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { argon2id } from "hash-wasm";

const { subtle } = webcrypto;
const getRandomValues = (arr) => webcrypto.getRandomValues(arr);

// ---------------------------------------------------------------------------
// KDF + AES-256-GCM helpers (intended final API for T027 sync-encryptor)
// ---------------------------------------------------------------------------

const KDF_PARAMS = {
  parallelism: 1,
  iterations: 3,
  memorySize: 65536, // 64 MB
  hashLength: 32,    // 256-bit key
  outputType: "binary",
};

/** Generate a fresh random KDF salt (16 bytes). */
function randomSalt() {
  return getRandomValues(new Uint8Array(16));
}

/** Generate a fresh random AES-GCM IV (12 bytes -- standard for GCM). */
function randomIv() {
  return getRandomValues(new Uint8Array(12));
}

/**
 * Derive a 256-bit AES-GCM CryptoKey from a passphrase + salt using Argon2id.
 *
 * Argon2id is memory-hard (unlike PBKDF2), making it resistant to GPU and
 * ASIC brute-force attacks. This is the KDF that will be used in the final
 * sync-encryptor package and the hosted dashboard browser client.
 */
async function deriveKey(passphrase, salt) {
  const keyBytes = await argon2id({
    password: passphrase,
    salt,
    ...KDF_PARAMS,
  });
  return subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    true,  // extractable for test equality checks; production: false
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt a UTF-8 plaintext string with AES-256-GCM.
 * Returns { ciphertext: Uint8Array, iv: Uint8Array }.
 * Persist iv alongside ciphertext; it is not secret but must be unique per encrypt call.
 */
async function encrypt(key, plaintext) {
  const iv = randomIv();
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

/**
 * Decrypt AES-256-GCM ciphertext. Throws DOMException if the authentication
 * tag fails (wrong key, wrong IV, or tampered ciphertext -- all indistinguishable
 * by design).
 */
async function decrypt(key, iv, ciphertext) {
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext,
  );
  return new TextDecoder().decode(plaintext);
}

/** Export raw key bytes -- for test equality checks only. */
async function exportKeyBytes(key) {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Argon2id KDF + AES-256-GCM pipeline (T025)", () => {
  it("deriveKey is deterministic: same passphrase + salt -> same key bytes", async () => {
    const salt = randomSalt();
    const b1 = await exportKeyBytes(await deriveKey("correct-horse-battery-staple", salt));
    const b2 = await exportKeyBytes(await deriveKey("correct-horse-battery-staple", salt));
    assert.deepEqual(b1, b2);
  });

  it("different salts produce different keys for the same passphrase", async () => {
    const b1 = await exportKeyBytes(await deriveKey("same-passphrase", randomSalt()));
    const b2 = await exportKeyBytes(await deriveKey("same-passphrase", randomSalt()));
    assert.notDeepEqual(b1, b2);
  });

  it("different passphrases produce different keys for the same salt", async () => {
    const salt = randomSalt();
    const b1 = await exportKeyBytes(await deriveKey("passphrase-A", salt));
    const b2 = await exportKeyBytes(await deriveKey("passphrase-B", salt));
    assert.notDeepEqual(b1, b2);
  });

  it("encrypt + decrypt roundtrip recovers plaintext", async () => {
    const salt = randomSalt();
    const key = await deriveKey("my-sync-passphrase", salt);
    const plaintext = JSON.stringify({ session_id: "sess_abc", events: 42, risk_score: 0.7 });
    const { ciphertext, iv } = await encrypt(key, plaintext);
    const recovered = await decrypt(key, iv, ciphertext);
    assert.equal(recovered, plaintext);
  });

  it("ciphertext differs from plaintext and includes AES-GCM auth tag (16 bytes longer)", async () => {
    const key = await deriveKey("passphrase", randomSalt());
    const plaintext = "do not store me in the clear";
    const { ciphertext } = await encrypt(key, plaintext);
    const encoded = new TextEncoder().encode(plaintext);
    assert.notDeepEqual(ciphertext, encoded);
    assert.equal(ciphertext.length, encoded.length + 16, "GCM tag is exactly 16 bytes");
  });

  it("decrypt throws when the wrong passphrase is used", async () => {
    const salt = randomSalt();
    const goodKey = await deriveKey("correct-passphrase", salt);
    const badKey  = await deriveKey("wrong-passphrase",   salt);
    const { ciphertext, iv } = await encrypt(goodKey, "secret payload");
    await assert.rejects(() => decrypt(badKey, iv, ciphertext));
  });

  it("decrypt throws when the IV is wrong", async () => {
    const key = await deriveKey("passphrase", randomSalt());
    const { ciphertext } = await encrypt(key, "secret payload");
    await assert.rejects(() => decrypt(key, randomIv(), ciphertext));
  });

  it("decrypt throws when ciphertext is tampered", async () => {
    const key = await deriveKey("passphrase", randomSalt());
    const { ciphertext, iv } = await encrypt(key, "secret payload");
    ciphertext[0] ^= 0xff; // flip bits in first byte
    await assert.rejects(() => decrypt(key, iv, ciphertext));
  });

  it("randomSalt generates unique values", () => {
    const salts = Array.from({ length: 20 }, () => randomSalt().join(","));
    assert.equal(new Set(salts).size, 20);
  });

  it("logs Argon2id KDF timing at 64 MB memory cost", async () => {
    const t0 = performance.now();
    await deriveKey("timing-test", randomSalt());
    const ms = (performance.now() - t0).toFixed(1);
    console.log(`    Argon2id (64MB, 3 iter, parallelism=1): ${ms}ms`);
    // Not an assertion -- logged so we can document expected latency and
    // decide if we need to tune m_cost down for the browser dashboard (T028).
    assert.ok(true);
  });
});
