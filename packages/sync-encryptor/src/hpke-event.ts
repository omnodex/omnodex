// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- write-only event encryption (HPKE)
 *
 * A stream keypair lets a writer that holds no passphrase encrypt events that
 * only the stream owner's clients can read. The writer gets the public key;
 * the private key never leaves the owner's clients except wrapped with a
 * passphrase-derived key (see stream-keypair.ts).
 *
 * Suite (RFC 9180, base mode): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM. Each event is sealed on its own with a fresh encapsulated key,
 * so a partial or reordered batch never affects the others.
 *
 * Associated data binds each ciphertext to its event_id and key_id, so a
 * server cannot move ciphertext between events or relabel the key.
 *
 * This module uses only globalThis.crypto and @hpke/core, so it runs
 * unchanged in Node, browsers and Cloudflare Workers.
 */

import {
  Aes256Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

/** Scheme label carried on every HPKE event on the wire. */
export const HPKE_EVENT_SCHEME = "hpke-x25519-sha256-aes256gcm" as const;

/** HPKE `info` for event sealing. Changing it makes old events unreadable. */
export const HPKE_EVENT_INFO = new TextEncoder().encode("omnodex-stream-event-v1");

const AAD_PREFIX = "omnodex-stream-event-aad-v1";

/** An event sealed to a stream public key, as sent over the wire. */
export interface HpkeEventWire {
  event_id: string;
  scheme: typeof HPKE_EVENT_SCHEME;
  /** key_id of the stream public key the event was sealed to. */
  key_id: string;
  /** base64 HPKE encapsulated key (32 bytes). */
  enc: string;
  /** base64 ciphertext including the 16-byte GCM tag. */
  ct: string;
  /** unix ms */
  ts: number;
}

/** A stream keypair as raw 32-byte X25519 keys. */
export interface StreamKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyId: string;
}

/** A private key a reader holds, labelled with the key_id it opens. */
export interface StreamPrivateKey {
  keyId: string;
  privateKey: Uint8Array;
}

/** The cipher suite every stream event uses. Exported for test vectors. */
export function createStreamSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
}

/**
 * Associated data for one event. NUL separators keep the fields
 * unambiguous, since neither an event_id nor a key_id contains NUL.
 */
export function hpkeEventAad(eventId: string, keyId: string): Uint8Array {
  return new TextEncoder().encode(`${AAD_PREFIX}\0${eventId}\0${keyId}`);
}

/**
 * key_id for a stream public key: first 8 hex characters of SHA-256 of the
 * raw 32-byte key, the same convention as the streaming key's key_id.
 */
export async function computePublicKeyId(publicKey: Uint8Array): Promise<string> {
  // Copy so the view is backed by a plain ArrayBuffer, as WebCrypto's types require.
  const hash = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(publicKey)),
  );
  return Array.from(hash.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Generate a fresh stream keypair. */
export async function generateStreamKeyPair(): Promise<StreamKeyPair> {
  const suite = createStreamSuite();
  const pair = await suite.kem.generateKeyPair();
  const publicKey = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  const privateKey = new Uint8Array(await suite.kem.serializePrivateKey(pair.privateKey));
  return { publicKey, privateKey, keyId: await computePublicKeyId(publicKey) };
}

/**
 * Seal one event's plaintext to a stream public key. The caller never needs
 * the private key, so this is safe to run anywhere events are produced.
 */
export async function sealEvent(
  publicKey: Uint8Array,
  event: { eventId: string; ts: number; plaintext: Uint8Array },
): Promise<HpkeEventWire> {
  const suite = createStreamSuite();
  const keyId = await computePublicKeyId(publicKey);
  const recipientPublicKey = await suite.kem.deserializePublicKey(publicKey);
  const { ct, enc } = await suite.seal(
    { recipientPublicKey, info: HPKE_EVENT_INFO },
    event.plaintext,
    hpkeEventAad(event.eventId, keyId),
  );
  return {
    event_id: event.eventId,
    scheme: HPKE_EVENT_SCHEME,
    key_id: keyId,
    enc: bytesToBase64(new Uint8Array(enc)),
    ct: bytesToBase64(new Uint8Array(ct)),
    ts: event.ts,
  };
}

/**
 * Open a sealed event. `keys` may hold several private keys (after a
 * rotation); the one whose keyId matches the event is used. Throws if the
 * scheme is unknown, no key matches, or authentication fails.
 */
export async function openEvent(
  keys: StreamPrivateKey | StreamPrivateKey[],
  wire: HpkeEventWire,
): Promise<Uint8Array> {
  if (wire.scheme !== HPKE_EVENT_SCHEME) {
    throw new Error(`Unsupported event scheme: ${String(wire.scheme)}`);
  }
  const key = (Array.isArray(keys) ? keys : [keys]).find((k) => k.keyId === wire.key_id);
  if (!key) {
    throw new Error(`No private key for key_id ${wire.key_id}`);
  }
  const suite = createStreamSuite();
  const recipientKey = await suite.kem.deserializePrivateKey(key.privateKey);
  const pt = await suite.open(
    { recipientKey, enc: base64ToBytes(wire.enc), info: HPKE_EVENT_INFO },
    base64ToBytes(wire.ct),
    hpkeEventAad(wire.event_id, wire.key_id),
  );
  return new Uint8Array(pt);
}

// ---------------------------------------------------------------------------
// base64 (btoa/atob exist in Node 16+, browsers and Workers)
// ---------------------------------------------------------------------------

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
