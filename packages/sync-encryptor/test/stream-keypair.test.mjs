// Stream private key wrapping: passphrase-derived key-wrapping key,
// AES-256-GCM wrap/unwrap, and the bindings that must fail closed.
//
// Run: node --test packages/sync-encryptor/test/stream-keypair.test.mjs

import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  WRAPPED_STREAM_KEY_VERSION,
  deriveStreamWrapKey,
  deriveStreamingKey,
  computeKeyId,
  wrapStreamPrivateKey,
  unwrapStreamPrivateKey,
  generateStreamKeyPair,
  sealEvent,
  openEvent,
} from "../dist/index.js";

const PASSPHRASE = "correct horse battery staple";
const CUSTOMER = "cus_case";

// Argon2id is slow on purpose; derive the shared wrap key once.
const wrapKeyPromise = deriveStreamWrapKey(PASSPHRASE, CUSTOMER);

test("wrap then unwrap returns the same keypair, and the blob holds no private key bytes", async () => {
  const wrapKey = await wrapKeyPromise;
  const pair = await generateStreamKeyPair();
  const wrapped = await wrapStreamPrivateKey(wrapKey, pair);

  assert.equal(wrapped.v, WRAPPED_STREAM_KEY_VERSION);
  assert.equal(wrapped.key_id, pair.keyId);
  assert.deepEqual(new Uint8Array(Buffer.from(wrapped.public_key, "base64")), pair.publicKey);
  assert.equal(Buffer.from(wrapped.iv, "base64").length, 12);
  assert.ok(!Buffer.from(wrapped.ct, "base64").includes(Buffer.from(pair.privateKey)));
  // JSON-safe for storage.
  assert.deepEqual(JSON.parse(JSON.stringify(wrapped)), wrapped);

  const unwrapped = await unwrapStreamPrivateKey(wrapKey, wrapped);
  assert.deepEqual(unwrapped.privateKey, pair.privateKey);
  assert.deepEqual(unwrapped.publicKey, pair.publicKey);
  assert.equal(unwrapped.keyId, pair.keyId);
});

test("an unwrapped key opens events sealed to its public key", async () => {
  const wrapKey = await wrapKeyPromise;
  const pair = await generateStreamKeyPair();
  const wrapped = await wrapStreamPrivateKey(wrapKey, pair);
  const wire = await sealEvent(pair.publicKey, {
    eventId: "evt_w",
    ts: 1,
    plaintext: new TextEncoder().encode("hello"),
  });

  const unwrapped = await unwrapStreamPrivateKey(await deriveStreamWrapKey(PASSPHRASE, CUSTOMER), wrapped);
  const pt = await openEvent({ keyId: unwrapped.keyId, privateKey: unwrapped.privateKey }, wire);
  assert.equal(new TextDecoder().decode(pt), "hello");
});

test("unwrap fails with a wrong passphrase or a different customer", async () => {
  const pair = await generateStreamKeyPair();
  const wrapped = await wrapStreamPrivateKey(await wrapKeyPromise, pair);
  await assert.rejects(unwrapStreamPrivateKey(await deriveStreamWrapKey("wrong passphrase", CUSTOMER), wrapped));
  await assert.rejects(unwrapStreamPrivateKey(await deriveStreamWrapKey(PASSPHRASE, "cus_other"), wrapped));
});

test("unwrap fails on a tampered blob or a swapped public key", async () => {
  const wrapKey = await wrapKeyPromise;
  const pair = await generateStreamKeyPair();
  const other = await generateStreamKeyPair();
  const wrapped = await wrapStreamPrivateKey(wrapKey, pair);

  const ct = Buffer.from(wrapped.ct, "base64");
  ct[3] ^= 0x01;
  await assert.rejects(unwrapStreamPrivateKey(wrapKey, { ...wrapped, ct: ct.toString("base64") }));

  // A swapped public key with its matching key_id still fails: both are associated data.
  await assert.rejects(
    unwrapStreamPrivateKey(wrapKey, {
      ...wrapped,
      public_key: Buffer.from(other.publicKey).toString("base64"),
      key_id: other.keyId,
    }),
  );
  // A key_id that does not match the public key is rejected before decryption.
  await assert.rejects(
    unwrapStreamPrivateKey(wrapKey, { ...wrapped, key_id: other.keyId }),
    /key_id does not match public key/,
  );
  await assert.rejects(unwrapStreamPrivateKey(wrapKey, { ...wrapped, v: 2 }), /Unsupported wrapped stream key version/);
});

test("the wrap key is independent of the streaming key from the same passphrase", async () => {
  // The streaming key is extractable, so its key_id can be compared; the wrap
  // key is not. Encrypting with the streaming key must not unwrap.
  const streaming = await deriveStreamingKey(PASSPHRASE, CUSTOMER);
  assert.match(await computeKeyId(streaming), /^[0-9a-f]{8}$/);

  const pair = await generateStreamKeyPair();
  const wrapped = await wrapStreamPrivateKey(await wrapKeyPromise, pair);
  await assert.rejects(unwrapStreamPrivateKey(streaming, wrapped));
});
