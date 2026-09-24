// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Advanced rule bundles.
 *
 * Community rules ship in this package and are free. Advanced rules are
 * written once, published once and stored once: one sealed bundle per
 * version, the same bytes for every entitled customer. What is per customer
 * is the entitlement check at fetch time and a content key wrapped to them,
 * so the shared object is not readable by whoever happens to hold it.
 *
 * A bundle is a JSON file:
 *
 *   manifest    version, channel, validity, the rule ids it carries, and the
 *               SHA-256 of the sealed payload
 *   signature   Ed25519 over the canonical manifest, checked against a key
 *               compiled into this client
 *   payload     RuleDefinition[] sealed with AES-256-GCM under the content key
 *
 * The signature is checked before anything is opened, and it covers the
 * payload hash, so a tampered payload is refused without being decrypted. A
 * bundle past its not_after is refused too: that expiry, not the licence
 * cache, is what ends a lapsed subscription's access.
 *
 * Nothing here throws at a caller. `loadAdvancedRules` returns the rules or a
 * reason it has none, because every failure means the same thing: run the
 * community rules and say so. Design note:
 * planning/architecture/PAID_RULE_DELIVERY.md sections 4 and 7.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { RuleDefinition } from "./types.js";

/** Where a home keeps the sealed bundle it last fetched. */
export const RULES_DIR = "rules";
export const CURRENT_BUNDLE_FILE = "current.bundle.json";

/** Base64 content key, for a bundle fetched by hand or built locally. */
export const RULES_KEY_ENV = "OMNODEX_RULES_KEY";
/** Base64 SPKI public key, for development against a locally signed bundle. */
export const RULES_PUBLIC_KEY_ENV = "OMNODEX_RULES_PUBLIC_KEY";

/**
 * Publishing keys this client trusts, newest first, as base64 SPKI Ed25519.
 *
 * The matching private keys never touch a server: bundles are signed on the
 * publishing machine and only stored and served by the cloud, so a server
 * that is compromised cannot produce a bundle this client will open. To
 * rotate, add the new key at the front, publish with it, and remove the old
 * one in a later release, once clients holding it have updated.
 *
 * RULES_PUBLIC_KEY_ENV adds one more key for local development, which is
 * how a pack signed with a throwaway key is tried before it is published.
 */
export const TRUSTED_PUBLISHING_KEYS: readonly string[] = [
  // Production publishing key, created 2026-09-24.
  "MCowBQYDK2VwAyEASJqdj4+WnXXwfPEkOBkrbRJ4TkDUuhRfTgg3Vnd2IXM=",
];

export interface BundleManifest {
  bundle_version: string;
  /** Which rule set this is: the plan that receives it. */
  channel: string;
  created_at: string;
  /** After this the bundle is refused, however it was cached. */
  not_after: string;
  rules: { rule_id: string; version: string }[];
  /** SHA-256 of the sealed payload, hex. Signed, so tampering is caught first. */
  payload_sha256: string;
}

export interface SealedBundle {
  manifest: BundleManifest;
  /** Base64 Ed25519 signature over the canonical manifest. */
  signature: string;
  /** Base64 iv (12 bytes) || ciphertext || tag (16 bytes). */
  payload: string;
}

/** Why a bundle is not in use. Every value means: run community rules. */
export type BundleSkipReason =
  | "none_cached"
  | "no_key"
  | "unreadable"
  | "untrusted_signature"
  | "expired"
  | "payload_mismatch"
  | "undecryptable"
  | "malformed_rules";

export interface AdvancedRulesLoaded {
  rules: RuleDefinition[];
  manifest: BundleManifest;
  skipped?: undefined;
}

export interface AdvancedRulesSkipped {
  rules: readonly [];
  manifest?: undefined;
  skipped: BundleSkipReason;
}

export type AdvancedRulesResult = AdvancedRulesLoaded | AdvancedRulesSkipped;

const skip = (reason: BundleSkipReason): AdvancedRulesSkipped => ({ rules: [], skipped: reason });

/** The bytes the signature covers: the manifest, with its keys in order. */
export function canonicalManifest(manifest: BundleManifest): Buffer {
  const ordered = {
    bundle_version: manifest.bundle_version,
    channel: manifest.channel,
    created_at: manifest.created_at,
    not_after: manifest.not_after,
    payload_sha256: manifest.payload_sha256,
    rules: [...manifest.rules]
      .map((r) => ({ rule_id: r.rule_id, version: r.version }))
      .sort((a, b) => a.rule_id.localeCompare(b.rule_id)),
  };
  return Buffer.from(JSON.stringify(ordered), "utf8");
}

function trustedKeys(env: NodeJS.ProcessEnv): string[] {
  const fromEnv = env[RULES_PUBLIC_KEY_ENV];
  return fromEnv ? [fromEnv, ...TRUSTED_PUBLISHING_KEYS] : [...TRUSTED_PUBLISHING_KEYS];
}

function verifies(signed: Buffer, signature: Buffer, spkiBase64: string): boolean {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(spkiBase64, "base64"),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, signed, key, signature);
  } catch {
    return false;
  }
}

export interface OpenBundleOptions {
  /** Raw 32-byte content key. Defaults to OMNODEX_RULES_KEY, base64. */
  key?: Buffer | null;
  /** Defaults to now. */
  at?: Date;
  env?: NodeJS.ProcessEnv;
}

/**
 * Check and open one sealed bundle. Order matters: signature, then expiry,
 * then the payload hash, and only then decryption, so nothing unverified is
 * ever handed to the cipher.
 */
export function openBundle(sealed: unknown, opts: OpenBundleOptions = {}): AdvancedRulesResult {
  const env = opts.env ?? process.env;
  const bundle = sealed as SealedBundle | null;
  if (
    !bundle ||
    typeof bundle !== "object" ||
    !bundle.manifest ||
    typeof bundle.signature !== "string" ||
    typeof bundle.payload !== "string"
  ) {
    return skip("unreadable");
  }

  const keys = trustedKeys(env);
  const signed = canonicalManifest(bundle.manifest);
  const signature = Buffer.from(bundle.signature, "base64");
  if (!keys.some((k) => verifies(signed, signature, k))) return skip("untrusted_signature");

  const now = opts.at ?? new Date();
  const notAfter = Date.parse(bundle.manifest.not_after);
  if (!Number.isFinite(notAfter) || notAfter <= now.getTime()) return skip("expired");

  const payload = Buffer.from(bundle.payload, "base64");
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  if (digest !== bundle.manifest.payload_sha256) return skip("payload_mismatch");

  const rawKey = opts.key ?? (env[RULES_KEY_ENV] ? Buffer.from(env[RULES_KEY_ENV], "base64") : null);
  if (!rawKey || rawKey.length !== 32) return skip("no_key");

  let plaintext: Buffer;
  try {
    const iv = payload.subarray(0, 12);
    const tag = payload.subarray(payload.length - 16);
    const body = payload.subarray(12, payload.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", rawKey, iv);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    return skip("undecryptable");
  }

  let rules: RuleDefinition[];
  try {
    rules = JSON.parse(plaintext.toString("utf8")) as RuleDefinition[];
  } catch {
    return skip("malformed_rules");
  }
  if (!Array.isArray(rules) || rules.some((r) => !r || typeof r.rule_id !== "string")) {
    return skip("malformed_rules");
  }

  // The bundle says what tier it carries; a rule inside it does not get to
  // claim otherwise, so nothing can smuggle a community label past a check
  // that trusts it.
  return { rules: rules.map((r) => ({ ...r, tier: "advanced" })), manifest: bundle.manifest };
}

/** The sealed bundle this home last fetched. */
export function bundlePath(home: string): string {
  return path.join(home, RULES_DIR, CURRENT_BUNDLE_FILE);
}

export interface LoadAdvancedOptions extends OpenBundleOptions {
  /** Read this file instead of the home's cached bundle. */
  file?: string;
}

/**
 * The advanced rules this installation may run, or the reason it has none.
 * Reads the sealed bundle from disk; the opened rules are returned to the
 * caller and never written back out.
 */
export function loadAdvancedRules(
  home: string = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex"),
  opts: LoadAdvancedOptions = {},
): AdvancedRulesResult {
  const file = opts.file ?? bundlePath(home);
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return skip("none_cached");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return skip("unreadable");
  }
  return openBundle(parsed, opts);
}

/** One line for `omnodex status`: what this installation will judge with. */
export function describeRules(result: AdvancedRulesResult, communityCount: number): string {
  if (!result.skipped) {
    const m = result.manifest;
    return `${communityCount} community, ${result.rules.length} advanced (${m.channel} bundle ${m.bundle_version}, valid until ${m.not_after})`;
  }
  const why: Record<BundleSkipReason, string> = {
    none_cached: "none installed",
    no_key: "installed, but no key to open it (subscription needed)",
    unreadable: "installed bundle could not be read",
    untrusted_signature: "installed bundle is not signed by a key this client trusts",
    expired: "installed bundle has expired",
    payload_mismatch: "installed bundle failed its integrity check",
    undecryptable: "installed bundle did not open with the key held",
    malformed_rules: "installed bundle opened but held no usable rules",
  };
  return `${communityCount} community, no advanced rules (${why[result.skipped]})`;
}
