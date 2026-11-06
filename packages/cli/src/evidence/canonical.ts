// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The pieces of the evidence format that a verifier must reproduce exactly:
 * RFC 8785 canonical JSON, the event hash, and the hash chain. This file
 * imports nothing from Omnodex, so an auditor can read it as the whole spec
 * of the arithmetic.
 */

import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

/** The head before any event: sixty-four zeros. */
export const GENESIS_HEAD = "0".repeat(64);

/**
 * RFC 8785 (JSON Canonicalization Scheme) for values that came from JSON.
 * Object keys sort by UTF-16 code unit, strings and numbers serialize as
 * ECMAScript does (which is what the RFC specifies), and there is no
 * whitespace. Non-finite numbers cannot be canonicalized and throw.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error("cannot canonicalize a non-finite number");
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
    }
    default:
      throw new Error("cannot canonicalize a " + typeof value);
  }
}

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 over the canonical form of a logged event, as lowercase hex. */
export function eventHash(event: unknown): string {
  return sha256Hex(Buffer.from(canonicalize(event), "utf8"));
}

/**
 * The head after one more event: SHA-256 over the previous head and the
 * event's hash, each as its 32 raw bytes.
 */
export function foldHead(previousHead: string, hashOfEvent: string): string {
  return sha256Hex(Buffer.concat([Buffer.from(previousHead, "hex"), Buffer.from(hashOfEvent, "hex")]));
}

/** DER prefix that turns a raw 32-byte Ed25519 public key into an SPKI key. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** A Node public key from the raw 32-byte Ed25519 key given as hex. */
export function publicKeyFromHex(hex: string): KeyObject {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}

/** The raw 32-byte public key, as hex, of an Ed25519 key. */
export function publicKeyHex(key: KeyObject): string {
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  return spki.subarray(spki.length - 32).toString("hex");
}

/** The short id a seal uses for its key: the first 16 hex digits of SHA-256 over the raw public key. */
export function keyIdFor(publicKey: string): string {
  return sha256Hex(Buffer.from(publicKey, "hex")).slice(0, 16);
}

/** Whether `signature` (hex) is an Ed25519 signature by `publicKey` (hex) over the canonical form of `body`. */
export function verifyBody(publicKey: string, body: unknown, signature: string): boolean {
  try {
    return cryptoVerify(null, Buffer.from(canonicalize(body), "utf8"), publicKeyFromHex(publicKey), Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
}
