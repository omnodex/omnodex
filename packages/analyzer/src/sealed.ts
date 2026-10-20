// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Opening a signed, sealed artifact: the checks advanced rule bundles and
 * paid modules share.
 *
 * Order matters: the signature over the manifest, then its expiry, then the
 * payload hash the manifest carries, and only then decryption, so nothing
 * unverified is ever handed to the cipher. Each artifact type signs its own
 * canonical manifest, which names its kind, so one type's signature never
 * passes as another's. A signature by a renewal key counts only when the
 * caller's renewal check passes (renewal.ts).
 */

import * as crypto from "node:crypto";
import { verifiesWith } from "./renewal.js";

export type OpenFailure =
  | "untrusted_signature"
  | "expired"
  | "payload_mismatch"
  | "no_key"
  | "undecryptable";

export type OpenResult =
  | { ok: true; plaintext: Buffer; /** Set when a renewal key signed it: the endorsement's serial. */ renewalSerial?: number }
  | { ok: false; reason: OpenFailure };

export interface OpenSignedInput {
  /** The canonical manifest bytes the signature covers. */
  signed: Buffer;
  /** Base64 Ed25519 signature. */
  signature: string;
  /** The manifest's not_after, ISO 8601. */
  notAfter: string;
  /** Base64 iv (12 bytes) || ciphertext || tag (16 bytes). */
  payload: string;
  /** SHA-256 of the sealed payload, hex, from the signed manifest. */
  payloadSha256: string;
  /** Raw 32-byte content key, or null when this install holds none. */
  key: Buffer | null;
  /** Base64 SPKI Ed25519 keys to accept. */
  trustedKeys: readonly string[];
  /**
   * When no trusted key signed it: whether a renewal key did, as the
   * endorsement's serial, or null. See checkRenewal in renewal.ts.
   */
  renewal?: () => number | null;
  at?: Date;
}

/** Check a sealed artifact and decrypt it. Never throws. */
export function openSigned(input: OpenSignedInput): OpenResult {
  let renewalSerial: number | undefined;
  if (!input.trustedKeys.some((k) => verifiesWith(input.signed, input.signature, k))) {
    renewalSerial = input.renewal?.() ?? undefined;
    if (renewalSerial === undefined) return { ok: false, reason: "untrusted_signature" };
  }

  const now = input.at ?? new Date();
  const notAfter = Date.parse(input.notAfter);
  if (!Number.isFinite(notAfter) || notAfter <= now.getTime()) return { ok: false, reason: "expired" };

  const payload = Buffer.from(input.payload, "base64");
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  if (digest !== input.payloadSha256) return { ok: false, reason: "payload_mismatch" };

  if (!input.key || input.key.length !== 32) return { ok: false, reason: "no_key" };
  try {
    const iv = payload.subarray(0, 12);
    const tag = payload.subarray(payload.length - 16);
    const body = payload.subarray(12, payload.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", input.key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
    return renewalSerial === undefined ? { ok: true, plaintext } : { ok: true, plaintext, renewalSerial };
  } catch {
    return { ok: false, reason: "undecryptable" };
  }
}
