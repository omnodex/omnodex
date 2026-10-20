// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Renewals: extending a signed artifact's validity without the publishing key.
 *
 * Advanced rule bundles and the guardrails module stop opening at their
 * not_after. Renewing one re-signs it with a later not_after, and that
 * signature may come from a renewal key instead of a publishing key, so it
 * can run unattended. A renewal key is trusted only through an endorsement:
 *
 *   endorsement   a publishing key's signature over the renewal key's public
 *                 key, a serial number, the dates it is valid between and the
 *                 kinds of artifact it may renew
 *   origin        the manifest as it was published, with its publishing-key
 *                 signature
 *
 * A renewal-key signature counts only when the endorsement verifies, is in
 * date and allows this kind; the origin verifies; the renewed manifest equals
 * the origin in everything but not_after; that not_after is within the
 * endorsement; and the client has not already seen something newer:
 *
 *   serial floor     the highest endorsement serial this home has accepted.
 *                    A new endorsement (a rotated key) retires the old ones.
 *   publish floor    per kind and channel, the newest created_at this home
 *                    has opened. A renewal of something older is refused, so
 *                    a renewal key cannot bring back what a later publish
 *                    replaced. A publish is never held to it: reverting means
 *                    publishing again, which moves the floor.
 *
 * So a renewal key can only extend what a publishing key signed, never ship
 * anything new. Floors live in OMNODEX_HOME/trust-state.json.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export const RENEWAL_ENDORSEMENT_KIND = "renewal-key-endorsement";
export const TRUST_STATE_FILE = "trust-state.json";

/** The artifacts a renewal key may be endorsed for. */
export type RenewableKind = "guardrails-module" | "rule-bundle";

export interface EndorsementStatement {
  kind: typeof RENEWAL_ENDORSEMENT_KIND;
  /** Higher serials retire lower ones. */
  serial: number;
  /** Base64 SPKI Ed25519 renewal key. */
  public_key: string;
  valid_from: string;
  valid_until: string;
  allowed: RenewableKind[];
}

export interface RenewalEndorsement {
  statement: EndorsementStatement;
  /** Base64 Ed25519 signature by a publishing key over the canonical statement. */
  signature: string;
}

/** What a renewed artifact carries beside its manifest and signature. */
export interface RenewalProof {
  endorsement: RenewalEndorsement;
  /** The manifest as published, and its publishing-key signature. */
  origin: { manifest: unknown; signature: string };
}

/** The bytes an endorsement signature covers. */
export function canonicalEndorsement(s: EndorsementStatement): Buffer {
  const ordered = {
    kind: RENEWAL_ENDORSEMENT_KIND,
    serial: s.serial,
    public_key: s.public_key,
    valid_from: s.valid_from,
    valid_until: s.valid_until,
    allowed: [...s.allowed].sort(),
  };
  return Buffer.from(JSON.stringify(ordered), "utf8");
}

export interface TrustFloor {
  endorsement_serial: number;
  /** `<kind>:<channel>` -> newest created_at opened. */
  published: Record<string, string>;
}

export function verifiesWith(signed: Buffer, signatureBase64: string, spkiBase64: string): boolean {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(spkiBase64, "base64"), format: "der", type: "spki" });
    return crypto.verify(null, signed, key, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

/** This home's floors. Missing or unreadable means none yet. */
export function readTrustFloor(home: string | undefined): TrustFloor {
  const empty: TrustFloor = { endorsement_serial: 0, published: {} };
  if (!home) return empty;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(home, TRUST_STATE_FILE), "utf8")) as Partial<TrustFloor>;
    const published: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw.published ?? {})) if (typeof v === "string") published[k] = v;
    return { endorsement_serial: Number.isInteger(raw.endorsement_serial) ? raw.endorsement_serial! : 0, published };
  } catch {
    return empty;
  }
}

/**
 * Raise this home's floors after an artifact opened. Writes only when a floor
 * moves; a failed write is left for the next open.
 */
export function raiseTrustFloor(home: string | undefined, scope: string, createdAt: string, serial?: number): void {
  if (!home) return;
  const floor = readTrustFloor(home);
  let moved = false;
  const current = floor.published[scope];
  if (!current || Date.parse(createdAt) > Date.parse(current)) {
    floor.published[scope] = createdAt;
    moved = true;
  }
  if (serial !== undefined && serial > floor.endorsement_serial) {
    floor.endorsement_serial = serial;
    moved = true;
  }
  if (!moved) return;
  try {
    const file = path.join(home, TRUST_STATE_FILE);
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(floor, null, 2) + "\n");
    fs.renameSync(tmp, file);
  } catch {
    // The floor is raised again on the next open.
  }
}

export interface RenewalCheckInput<M> {
  kind: RenewableKind;
  /** `<kind>:<channel>`, for the publish floor. */
  scope: string;
  manifest: M;
  canonical: (m: M) => Buffer;
  notAfter: string;
  createdAt: string;
  /** The renewed manifest's signature, by the renewal key. */
  signature: string;
  /** The artifact's `renewal` field, unchecked. */
  renewal: unknown;
  /** Publishing keys, which sign endorsements and origins. */
  trustedKeys: readonly string[];
  floor: TrustFloor;
  at: Date;
}

/** The endorsement serial when a renewal-key signature counts, else null. Never throws. */
export function checkRenewal<M>(input: RenewalCheckInput<M>): number | null {
  try {
    const proof = input.renewal as RenewalProof | null;
    const statement = proof?.endorsement?.statement;
    if (!statement || typeof proof.endorsement.signature !== "string" || typeof proof.origin?.signature !== "string") return null;
    if (statement.kind !== RENEWAL_ENDORSEMENT_KIND || !Array.isArray(statement.allowed) || !statement.allowed.includes(input.kind)) return null;
    if (!Number.isInteger(statement.serial) || statement.serial < input.floor.endorsement_serial) return null;

    const endorsed = canonicalEndorsement(statement);
    if (!input.trustedKeys.some((k) => verifiesWith(endorsed, proof.endorsement.signature, k))) return null;

    const now = input.at.getTime();
    const from = Date.parse(statement.valid_from);
    const until = Date.parse(statement.valid_until);
    if (!Number.isFinite(from) || !Number.isFinite(until) || now < from || now >= until) return null;
    if (!(Date.parse(input.notAfter) <= until)) return null;

    if (!verifiesWith(input.canonical(input.manifest), input.signature, statement.public_key)) return null;

    const origin = proof.origin.manifest as M;
    if (!origin || typeof origin !== "object") return null;
    const originSigned = input.canonical(origin);
    if (!input.trustedKeys.some((k) => verifiesWith(originSigned, proof.origin.signature, k))) return null;
    if (!input.canonical({ ...origin, not_after: input.notAfter }).equals(input.canonical(input.manifest))) return null;

    const published = input.floor.published[input.scope];
    if (published && !(Date.parse(input.createdAt) >= Date.parse(published))) return null;
    return statement.serial;
  } catch {
    return null;
  }
}
