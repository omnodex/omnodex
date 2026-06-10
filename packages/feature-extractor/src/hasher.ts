// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/feature-extractor -- HMAC hashing
 *
 * Produces HMAC-SHA256 hashes of tool names and MCP server names using
 * a customer-specific salt. The salt is server-issued (from the license
 * validation response) for controlled rotation, with a locally-generated
 * fallback for offline use.
 *
 * The HMAC lets the cloud detect "same pattern across sessions for THIS
 * customer" without knowing the actual tool or server names. Different
 * customers use different salts, so cross-customer correlation works on
 * statistical patterns, not raw identifiers.
 */

import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;

/**
 * Import a hex-encoded HMAC salt as a CryptoKey suitable for HMAC-SHA256.
 */
export async function importHmacKey(saltHex: string): Promise<webcrypto.CryptoKey> {
  const keyBytes = hexToBytes(saltHex);
  return subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

/**
 * HMAC-SHA256 a single string value. Returns hex-encoded digest.
 */
export async function hmacSha256(
  key: webcrypto.CryptoKey,
  value: string,
): Promise<string> {
  const data = new TextEncoder().encode(value);
  const sig = await subtle.sign("HMAC", key, data);
  return bytesToHex(new Uint8Array(sig));
}

/**
 * HMAC-SHA256 an array of strings. Returns an array of hex digests,
 * preserving order and deduplicating inputs.
 */
export async function hmacBatch(
  key: webcrypto.CryptoKey,
  values: string[],
): Promise<string[]> {
  const unique = [...new Set(values)];
  return Promise.all(unique.map((v) => hmacSha256(key, v)));
}

/**
 * Generate a random 32-byte HMAC salt (hex-encoded) for offline fallback.
 */
export function generateLocalSalt(): string {
  const bytes = webcrypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
