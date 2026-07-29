// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- crypto primitives
 *
 * Argon2id key derivation + AES-256-GCM encrypt/decrypt. Runs entirely
 * client-side (local CLI or browser). The cloud server never sees the
 * passphrase, derived key, or plaintext.
 *
 * Argon2id parameters (OWASP 2023 minimum for interactive login):
 *   memorySize: 64 MB, iterations: 3, parallelism: 1, hashLength: 32
 *
 * For browser dashboard use, memorySize may be tuned to 16-32 MB.
 */

import { argon2id } from "hash-wasm";
import { webcrypto } from "node:crypto";

// Use the Node.js webcrypto subtle implementation. The global CryptoKey
// type from lib.dom may diverge from node:crypto's version; we re-export
// a local alias so callers don't fight the mismatch.
const subtle = webcrypto.subtle;
const getRandomValues = (arr: Uint8Array): Uint8Array =>
  webcrypto.getRandomValues(arr);

/** Re-export for callers that need to type a derived key. */
export type AesGcmKey = webcrypto.CryptoKey;

export const KDF_PARAMS = {
  parallelism: 1,
  iterations: 3,
  memorySize: 65536, // 64 MB
  hashLength: 32,    // 256-bit key
  outputType: "binary" as const,
};

/** Generate a fresh random KDF salt (16 bytes). */
export function randomSalt(): Uint8Array {
  return getRandomValues(new Uint8Array(16));
}

/** Generate a fresh random AES-GCM IV (12 bytes, standard for GCM). */
export function randomIv(): Uint8Array {
  return getRandomValues(new Uint8Array(12));
}

/**
 * Derive a 256-bit AES-GCM CryptoKey from a passphrase + salt via Argon2id.
 * Memory-hard, resistant to GPU/ASIC brute-force.
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<AesGcmKey> {
  const keyBytes = await argon2id({
    password: passphrase,
    salt,
    ...KDF_PARAMS,
  });
  return subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false, // not extractable in production
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt plaintext bytes with AES-256-GCM.
 * Returns ciphertext (includes 16-byte auth tag) and a fresh IV.
 */
export async function encrypt(
  key: AesGcmKey,
  plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = randomIv();
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { ciphertext: new Uint8Array(ct), iv };
}

/**
 * Decrypt AES-256-GCM ciphertext. Throws if auth tag fails (wrong key,
 * wrong IV, or tampered ciphertext -- all indistinguishable by design).
 */
export async function decrypt(
  key: AesGcmKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const pt = await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(pt);
}

/** SHA-256 hex digest of arbitrary bytes. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


// ---------------------------------------------------------------------------
// Streaming key derivation (HKDF from Argon2id master key)
// ---------------------------------------------------------------------------

/** Fixed salt for the Argon2id step of streaming key derivation. */
const STREAMING_FIXED_SALT = new TextEncoder().encode('omnodex-stream-v1');

/** HKDF info string for streaming key extraction. */
const STREAMING_INFO = new TextEncoder().encode('omnodex-stream-aes256gcm-v1');

/**
 * HKDF-SHA256: extract-then-expand per RFC 5869.
 * Works in both Node.js (webcrypto) and browser (globalThis.crypto).
 */
async function hkdfDerive(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey(
    "raw",
    ikm,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Derive a 256-bit AES-GCM streaming key from passphrase + customer ID.
 *
 * Two-stage derivation avoids running expensive Argon2id per event:
 *   1. Argon2id(passphrase, fixed_salt) → master key material (slow, once)
 *   2. HKDF-SHA256(master, SHA256(customerId), info) → streaming key (fast)
 *
 * Both CLI and browser derive the same key independently.
 */
export async function deriveStreamingKey(
  passphrase: string,
  customerId: string,
): Promise<AesGcmKey> {
  // Stage 1: Argon2id with fixed salt → raw key material
  const masterBytes = await argon2id({
    password: passphrase,
    salt: STREAMING_FIXED_SALT,
    ...KDF_PARAMS,
  });

  // Stage 2: HKDF-SHA256 with customer-specific salt
  const customerSalt = new Uint8Array(
    await subtle.digest("SHA-256", new TextEncoder().encode(customerId)),
  );
  const streamKeyBytes = await hkdfDerive(
    masterBytes as Uint8Array,
    customerSalt,
    STREAMING_INFO,
    32,
  );

  return subtle.importKey(
    "raw",
    streamKeyBytes,
    { name: "AES-GCM", length: 256 },
    true, // extractable — needed for computeKeyId
    ["encrypt", "decrypt"],
  );
}

/**
 * Compute the key_id for a streaming key: first 8 hex chars of SHA-256.
 * Used by CLI (in event push) and browser (to detect key mismatch).
 */
export async function computeKeyId(key: AesGcmKey): Promise<string> {
  const raw = await subtle.exportKey("raw", key);
  const hash = await sha256Hex(new Uint8Array(raw));
  return hash.slice(0, 8);
}
