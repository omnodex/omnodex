// Write-only event encryption: stream keypair + per-event HPKE seal/open.
//
// Covers: the configured suite matches the RFC 9180 known-answer vector for
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM; the committed
// Omnodex wire vector opens (the cross-implementation check any other
// implementation repeats); round trips; and every binding that must fail closed.
//
// Run: node --test packages/sync-encryptor/test/hpke-event.test.mjs

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  HPKE_EVENT_INFO,
  HPKE_EVENT_SCHEME,
  createStreamSuite,
  hpkeEventAad,
  computePublicKeyId,
  generateStreamKeyPair,
  sealEvent,
  openEvent,
} from "../dist/index.js";

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));
const fromHex = (h) => new Uint8Array(Buffer.from(h, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => new TextDecoder().decode(b);

test("suite matches the RFC 9180 known-answer vector for X25519 / SHA-256 / AES-256-GCM", async () => {
  const kat = fixture("rfc9180-x25519-sha256-aes256gcm.json");
  const suite = createStreamSuite();
  assert.equal(suite.kem.id, kat.kem_id);
  assert.equal(suite.kdf.id, kat.kdf_id);
  assert.equal(suite.aead.id, kat.aead_id);

  const recipient = await suite.kem.deriveKeyPair(fromHex(kat.ikmR));
  assert.equal(toHex(new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey))), kat.pkRm);

  // The first encryption in the vector is a single-shot seal with sequence 0.
  const e = kat.encryptions[0];
  const sealed = await suite.seal(
    { recipientPublicKey: recipient.publicKey, info: fromHex(kat.info), ekm: fromHex(kat.ikmE) },
    fromHex(e.pt),
    fromHex(e.aad),
  );
  assert.equal(toHex(new Uint8Array(sealed.enc)), kat.enc);
  assert.equal(toHex(new Uint8Array(sealed.ct)), e.ct);

  const opened = await suite.open(
    { recipientKey: recipient, enc: fromHex(kat.enc), info: fromHex(kat.info) },
    fromHex(e.ct),
    fromHex(e.aad),
  );
  assert.equal(toHex(new Uint8Array(opened)), e.pt);
});

test("committed Omnodex wire vector opens and reproduces byte for byte", async () => {
  const v = fixture("hpke-event-vectors.json");
  const publicKey = fromHex(v.public_key_hex);
  assert.equal(await computePublicKeyId(publicKey), v.key_id);
  assert.equal(text(HPKE_EVENT_INFO), v.info_utf8);
  assert.equal(toHex(hpkeEventAad(v.wire.event_id, v.key_id)), v.aad_hex);
  assert.equal(v.wire.scheme, HPKE_EVENT_SCHEME);

  const pt = await openEvent({ keyId: v.key_id, privateKey: fromHex(v.private_key_hex) }, v.wire);
  assert.equal(text(pt), v.plaintext);

  // Same recipient and ephemeral key material give the same ciphertext.
  const suite = createStreamSuite();
  const recipient = await suite.kem.deriveKeyPair(fromHex(v.ikm_r_hex));
  const sealed = await suite.seal(
    { recipientPublicKey: recipient.publicKey, info: HPKE_EVENT_INFO, ekm: fromHex(v.ikm_e_hex) },
    utf8(v.plaintext),
    hpkeEventAad(v.wire.event_id, v.key_id),
  );
  assert.equal(Buffer.from(new Uint8Array(sealed.enc)).toString("base64"), v.wire.enc);
  assert.equal(Buffer.from(new Uint8Array(sealed.ct)).toString("base64"), v.wire.ct);
});

test("generateStreamKeyPair returns 32-byte keys and an 8-hex key_id of SHA-256(public key)", async () => {
  const pair = await generateStreamKeyPair();
  assert.equal(pair.publicKey.length, 32);
  assert.equal(pair.privateKey.length, 32);
  assert.match(pair.keyId, /^[0-9a-f]{8}$/);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", pair.publicKey));
  assert.equal(pair.keyId, toHex(digest).slice(0, 8));

  const other = await generateStreamKeyPair();
  assert.notDeepEqual(other.publicKey, pair.publicKey);
});

test("sealEvent needs only the public key; openEvent recovers the plaintext", async () => {
  const pair = await generateStreamKeyPair();
  const plaintext = utf8(JSON.stringify({ type: "tool.completed", user: "case" }));
  const wire = await sealEvent(pair.publicKey, { eventId: "evt_1", ts: 1789000000001, plaintext });

  assert.equal(wire.event_id, "evt_1");
  assert.equal(wire.scheme, HPKE_EVENT_SCHEME);
  assert.equal(wire.key_id, pair.keyId);
  assert.equal(wire.ts, 1789000000001);
  assert.equal(Buffer.from(wire.enc, "base64").length, 32);
  assert.equal(Buffer.from(wire.ct, "base64").length, plaintext.length + 16);

  const pt = await openEvent({ keyId: pair.keyId, privateKey: pair.privateKey }, wire);
  assert.deepEqual(pt, plaintext);
});

test("each event is sealed independently (fresh encapsulated key per event)", async () => {
  const pair = await generateStreamKeyPair();
  const plaintext = utf8("same payload");
  const a = await sealEvent(pair.publicKey, { eventId: "evt_a", ts: 1, plaintext });
  const b = await sealEvent(pair.publicKey, { eventId: "evt_a", ts: 1, plaintext });
  assert.notEqual(a.enc, b.enc);
  assert.notEqual(a.ct, b.ct);

  // Opening in reverse order works: no shared state between events.
  const key = { keyId: pair.keyId, privateKey: pair.privateKey };
  assert.deepEqual(await openEvent(key, b), plaintext);
  assert.deepEqual(await openEvent(key, a), plaintext);
});

test("opening fails when ciphertext is moved to another event_id", async () => {
  const pair = await generateStreamKeyPair();
  const wire = await sealEvent(pair.publicKey, { eventId: "evt_real", ts: 1, plaintext: utf8("x") });
  const key = { keyId: pair.keyId, privateKey: pair.privateKey };
  await assert.rejects(openEvent(key, { ...wire, event_id: "evt_other" }));
});

test("opening fails on tampered ciphertext or encapsulated key", async () => {
  const pair = await generateStreamKeyPair();
  const wire = await sealEvent(pair.publicKey, { eventId: "evt_t", ts: 1, plaintext: utf8("payload") });
  const key = { keyId: pair.keyId, privateKey: pair.privateKey };

  const ct = Buffer.from(wire.ct, "base64");
  ct[0] ^= 0x01;
  await assert.rejects(openEvent(key, { ...wire, ct: ct.toString("base64") }));

  const enc = Buffer.from(wire.enc, "base64");
  enc[5] ^= 0x01;
  await assert.rejects(openEvent(key, { ...wire, enc: enc.toString("base64") }));
});

test("opening fails with the wrong private key, even if relabelled with the event's key_id", async () => {
  const pair = await generateStreamKeyPair();
  const other = await generateStreamKeyPair();
  const wire = await sealEvent(pair.publicKey, { eventId: "evt_k", ts: 1, plaintext: utf8("x") });
  await assert.rejects(openEvent({ keyId: pair.keyId, privateKey: other.privateKey }, wire));
});

test("opening fails when the key_id label is swapped, and when no key matches", async () => {
  const pair = await generateStreamKeyPair();
  const other = await generateStreamKeyPair();
  const wire = await sealEvent(pair.publicKey, { eventId: "evt_l", ts: 1, plaintext: utf8("x") });

  // key_id is associated data: relabelling to another held key fails authentication.
  await assert.rejects(
    openEvent({ keyId: other.keyId, privateKey: pair.privateKey }, { ...wire, key_id: other.keyId }),
  );
  await assert.rejects(
    openEvent({ keyId: other.keyId, privateKey: other.privateKey }, wire),
    /No private key for key_id/,
  );
});

test("after rotation, a keyring opens events sealed to old and new keys", async () => {
  const oldPair = await generateStreamKeyPair();
  const newPair = await generateStreamKeyPair();
  const before = await sealEvent(oldPair.publicKey, { eventId: "evt_old", ts: 1, plaintext: utf8("old") });
  const after = await sealEvent(newPair.publicKey, { eventId: "evt_new", ts: 2, plaintext: utf8("new") });

  const keyring = [
    { keyId: newPair.keyId, privateKey: newPair.privateKey },
    { keyId: oldPair.keyId, privateKey: oldPair.privateKey },
  ];
  assert.equal(text(await openEvent(keyring, before)), "old");
  assert.equal(text(await openEvent(keyring, after)), "new");
});

test("unknown schemes are rejected before any decryption", async () => {
  const pair = await generateStreamKeyPair();
  const wire = await sealEvent(pair.publicKey, { eventId: "evt_s", ts: 1, plaintext: utf8("x") });
  await assert.rejects(
    openEvent({ keyId: pair.keyId, privateKey: pair.privateKey }, { ...wire, scheme: "aes256gcm" }),
    /Unsupported event scheme/,
  );
});
