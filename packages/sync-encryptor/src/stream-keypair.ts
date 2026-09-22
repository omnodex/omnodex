// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- stream private key wrapping
 *
 * The stream private key is stored server-side only as an opaque blob,
 * encrypted with an AES-256-GCM key derived from the stream passphrase:
 * the same Argon2id master as the streaming key, then HKDF with its own
 * `info` label, so the two keys are independent. Clients that know the
 * passphrase unwrap it; the server never can.
 *
 * The public key travels in the blob in the clear (it is public) and is
 * bound to the ciphertext as associated data together with the key_id.
 */

import { webcrypto } from "node:crypto";
import { deriveStreamSubkeyBytes } from "./crypto.js";
import {
  base64ToBytes,
  bytesToBase64,
  computePublicKeyId,
  type StreamKeyPair,
} from "./hpke-event.js";

const subtle = webcrypto.subtle;

/** HKDF `info` for the key-wrapping key. Changing it orphans wrapped keys. */
const KEYWRAP_INFO = new TextEncoder().encode("omnodex-stream-keywrap-v1");

const WRAP_AAD_PREFIX = "omnodex-stream-keywrap-aad-v1";

/** Current wrapped-key format version. */
export const WRAPPED_STREAM_KEY_VERSION = 1;

/** A stream private key wrapped for server-side storage. JSON-safe. */
export interface WrappedStreamKey {
  v: typeof WRAPPED_STREAM_KEY_VERSION;
  key_id: string;
  /** base64 raw X25519 public key (32 bytes). */
  public_key: string;
  /** base64 AES-GCM IV (12 bytes). */
  iv: string;
  /** base64 wrapped private key including the GCM tag. */
  ct: string;
}

/** An imported key-wrapping key. Derive once per passphrase entry. */
export type StreamWrapKey = webcrypto.CryptoKey;

/**
 * Derive the key-wrapping key for a stream. Runs Argon2id, so it is slow by
 * design; derive once and reuse for wrap and unwrap.
 */
export async function deriveStreamWrapKey(
  passphrase: string,
  customerId: string,
): Promise<StreamWrapKey> {
  const bytes = await deriveStreamSubkeyBytes(passphrase, customerId, KEYWRAP_INFO);
  return subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

function wrapAad(keyId: string, publicKeyB64: string): Uint8Array {
  return new TextEncoder().encode(`${WRAP_AAD_PREFIX}\0${keyId}\0${publicKeyB64}`);
}

/** Wrap a stream keypair's private key for storage. */
export async function wrapStreamPrivateKey(
  wrapKey: StreamWrapKey,
  pair: StreamKeyPair,
): Promise<WrappedStreamKey> {
  const publicKeyB64 = bytesToBase64(pair.publicKey);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: wrapAad(pair.keyId, publicKeyB64) },
    wrapKey,
    pair.privateKey,
  );
  return {
    v: WRAPPED_STREAM_KEY_VERSION,
    key_id: pair.keyId,
    public_key: publicKeyB64,
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(ct)),
  };
}

/**
 * Unwrap a stored stream key. Throws on a wrong passphrase or customer ID,
 * a tampered blob, or a key_id that does not match the public key.
 */
export async function unwrapStreamPrivateKey(
  wrapKey: StreamWrapKey,
  wrapped: WrappedStreamKey,
): Promise<StreamKeyPair> {
  if (wrapped.v !== WRAPPED_STREAM_KEY_VERSION) {
    throw new Error(`Unsupported wrapped stream key version: ${String(wrapped.v)}`);
  }
  const publicKey = base64ToBytes(wrapped.public_key);
  if ((await computePublicKeyId(publicKey)) !== wrapped.key_id) {
    throw new Error("Wrapped stream key: key_id does not match public key");
  }
  const pt = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(wrapped.iv),
      additionalData: wrapAad(wrapped.key_id, wrapped.public_key),
    },
    wrapKey,
    base64ToBytes(wrapped.ct),
  );
  return { publicKey, privateKey: new Uint8Array(pt), keyId: wrapped.key_id };
}
