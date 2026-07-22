// Validation: v1 sync envelope encode/decode + full encrypt->envelope->decrypt
// round-trip. The second test mirrors exactly what the hosted browser
// dashboard does: decode the pulled blob, re-derive the key from the
// passphrase + embedded salt, and decrypt.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  encodeEnvelope,
  decodeEnvelope,
  ENVELOPE_MAGIC,
  ENVELOPE_VERSION,
  HEADER_LEN,
  SALT_LEN,
  IV_LEN,
  deriveKey,
  encrypt,
  decrypt,
  randomSalt,
} from "../dist/index.js";

test("encodeEnvelope + decodeEnvelope round-trips salt, iv, ciphertext", () => {
  const salt = new Uint8Array(SALT_LEN).fill(7);
  const iv = new Uint8Array(IV_LEN).fill(9);
  const ciphertext = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);

  const env = encodeEnvelope(salt, iv, ciphertext);
  assert.equal(env.length, HEADER_LEN + ciphertext.length);
  assert.deepEqual(env.slice(0, 4), ENVELOPE_MAGIC);
  assert.equal(env[4], ENVELOPE_VERSION);

  const dec = decodeEnvelope(env);
  assert.equal(dec.version, ENVELOPE_VERSION);
  assert.deepEqual(dec.salt, salt);
  assert.deepEqual(dec.iv, iv);
  assert.deepEqual(dec.ciphertext, ciphertext);
});

test("encrypt -> envelope -> decode -> decrypt recovers plaintext (browser-style)", async () => {
  const passphrase = "correct horse battery staple";
  const salt = randomSalt();
  const key = await deriveKey(passphrase, salt);

  const original = JSON.stringify({ hello: "world", n: 42, arr: [1, 2, 3] });
  const plaintext = new TextEncoder().encode(original);
  const { ciphertext, iv } = await encrypt(key, plaintext);

  // Client packs the envelope exactly as HttpSyncTransport.push does.
  const env = encodeEnvelope(salt, iv, ciphertext);

  // Browser side: decode, re-derive key from passphrase + embedded salt, decrypt.
  const dec = decodeEnvelope(env);
  const key2 = await deriveKey(passphrase, dec.salt);
  const recovered = await decrypt(key2, dec.iv, dec.ciphertext);

  assert.deepEqual(new Uint8Array(recovered), plaintext);
  assert.equal(new TextDecoder().decode(recovered), original);
});

test("decodeEnvelope rejects a too-short buffer", () => {
  assert.throws(() => decodeEnvelope(new Uint8Array(10)), /too short/);
});

test("decodeEnvelope rejects bad magic", () => {
  const bad = new Uint8Array(HEADER_LEN + 4);
  bad.set([0x00, 0x01, 0x02, 0x03], 0);
  assert.throws(() => decodeEnvelope(bad), /bad magic/);
});

test("decodeEnvelope rejects an unsupported version", () => {
  const env = encodeEnvelope(new Uint8Array(SALT_LEN), new Uint8Array(IV_LEN), new Uint8Array([1, 2, 3]));
  env[4] = 0x02; // bump to an unknown version
  assert.throws(() => decodeEnvelope(env), /unsupported version/);
});

test("encodeEnvelope validates salt and iv lengths", () => {
  assert.throws(
    () => encodeEnvelope(new Uint8Array(8), new Uint8Array(IV_LEN), new Uint8Array(1)),
    /salt must be/,
  );
  assert.throws(
    () => encodeEnvelope(new Uint8Array(SALT_LEN), new Uint8Array(4), new Uint8Array(1)),
    /iv must be/,
  );
});
