// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- sync blob envelope (v1)
 *
 * A self-describing binary container for an encrypted sync blob. The salt
 * and IV needed to derive the key and decrypt travel INSIDE the blob, so
 * the cloud stores opaque bytes (no schema for salt/IV) and any client --
 * the CLI or the hosted browser dashboard -- can reconstruct everything it
 * needs from the blob alone.
 *
 * Layout (bytes):
 *   0   4    magic   = ASCII "OMDX"
 *   4   1    version = 0x01
 *   5   16   kdf_salt  (Argon2id salt)
 *   21  12   iv        (AES-GCM IV)
 *   33  ...  ciphertext (AES-256-GCM; includes trailing 16-byte auth tag)
 *
 * There are no multi-byte integer fields, so byte order is irrelevant.
 * The version byte lets us evolve KDF params (e.g. a low-end 32 MB profile)
 * without breaking previously-synced blobs.
 */

export const ENVELOPE_MAGIC = Uint8Array.of(0x4f, 0x4d, 0x44, 0x58); // "OMDX"
export const ENVELOPE_VERSION = 0x01;

export const SALT_LEN = 16;
export const IV_LEN = 12;
export const MAGIC_LEN = ENVELOPE_MAGIC.length;
/** Fixed header size before the ciphertext: magic(4) + version(1) + salt(16) + iv(12). */
export const HEADER_LEN = MAGIC_LEN + 1 + SALT_LEN + IV_LEN; // 33

export interface DecodedEnvelope {
  version: number;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * Pack salt + IV + ciphertext into a v1 envelope buffer.
 * @throws if salt or IV are the wrong length.
 */
export function encodeEnvelope(
  salt: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (salt.length !== SALT_LEN) {
    throw new Error(`envelope: salt must be ${SALT_LEN} bytes, got ${salt.length}`);
  }
  if (iv.length !== IV_LEN) {
    throw new Error(`envelope: iv must be ${IV_LEN} bytes, got ${iv.length}`);
  }
  const out = new Uint8Array(HEADER_LEN + ciphertext.length);
  out.set(ENVELOPE_MAGIC, 0);
  out[MAGIC_LEN] = ENVELOPE_VERSION;
  out.set(salt, MAGIC_LEN + 1);
  out.set(iv, MAGIC_LEN + 1 + SALT_LEN);
  out.set(ciphertext, HEADER_LEN);
  return out;
}

/**
 * Parse a v1 envelope back into its parts.
 * @throws if the buffer is too short, the magic is wrong, or the version
 *         is unsupported.
 */
export function decodeEnvelope(bytes: Uint8Array): DecodedEnvelope {
  if (bytes.length < HEADER_LEN) {
    throw new Error(`envelope: too short (${bytes.length} < ${HEADER_LEN} bytes)`);
  }
  for (let i = 0; i < MAGIC_LEN; i++) {
    if (bytes[i] !== ENVELOPE_MAGIC[i]) {
      throw new Error("envelope: bad magic (not an Omnodex sync blob)");
    }
  }
  const version = bytes[MAGIC_LEN]!;
  if (version !== ENVELOPE_VERSION) {
    throw new Error(`envelope: unsupported version ${version}`);
  }
  const salt = bytes.slice(MAGIC_LEN + 1, MAGIC_LEN + 1 + SALT_LEN);
  const iv = bytes.slice(MAGIC_LEN + 1 + SALT_LEN, HEADER_LEN);
  const ciphertext = bytes.slice(HEADER_LEN);
  return { version, salt, iv, ciphertext };
}
