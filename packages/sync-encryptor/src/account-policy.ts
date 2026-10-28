// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- the account's finding policy, pulled
 *
 * Policy entries made in the hosted dashboard apply to every machine on the
 * account. The dashboard seals one copy per stream with a key derived from
 * that stream's passphrase, and the gateway stores ciphertext and a version:
 *
 *   GET /api/v1/policy   this stream's copy, or 304 when the version is the
 *                        one already pulled, or 404 when there is none
 *
 * The background pass pulls it (and `omnodex policy pull` does at once),
 * opens it here and writes the entries to OMNODEX_HOME/account-policy.json,
 * which the capture paths read beside this machine's own entries. A
 * machine's entries win over the account's at equal specificity.
 *
 * The key is the stream's passphrase run through the same Argon2id step as
 * the live stream key, then HKDF with its own label, so a policy key never
 * opens anything else. A copy is `{ v: 1, entries: [...] }` as JSON, sealed
 * with AES-256-GCM.
 *
 * Installs without credentials, or on the free plan, make no request. Never throws; a failure
 * leaves the last pulled policy in place.
 */

import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { webcrypto } from "node:crypto";
import { parsePolicy, type PolicyEntry } from "@omnodex/shared";
import { decrypt, deriveStreamSubkeyBytes, encrypt, type AesGcmKey } from "./crypto.js";

/** Where a home keeps the account policy it last pulled. Must match the analyzer's reader. */
export const ACCOUNT_POLICY_FILE = "account-policy.json";
/** Set to "0" to skip pulling. */
export const ACCOUNT_POLICY_PULL_ENV = "OMNODEX_POLICY_PULL";

const POLICY_INFO = new TextEncoder().encode("omnodex-policy-aes256gcm-v1");
const REQUEST_TIMEOUT_MS = 10_000;

/** A sealed copy, as the gateway stores it. */
export interface SealedPolicy {
  iv: string;
  ct: string;
}

/** What account-policy.json holds. */
export interface PulledPolicy {
  version: number;
  pulled_at: string;
  entries: PolicyEntry[];
}

export type PolicyPullOutcome = "disabled" | "no-credentials" | "none" | "current" | "updated" | "failed";

export interface PolicyPullResult {
  outcome: PolicyPullOutcome;
  /** The version now held, when one is. */
  version?: number;
  entries?: number;
}

export interface PolicyPullOptions {
  fetchFn?: typeof fetch;
  now?: () => Date;
}

/** The AES-256-GCM key for a stream's policy copies. */
export async function derivePolicyKey(passphrase: string, customerId: string): Promise<AesGcmKey> {
  const bytes = await deriveStreamSubkeyBytes(passphrase, customerId, POLICY_INFO);
  return webcrypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const toB64 = (u: Uint8Array): string => Buffer.from(u).toString("base64");
const fromB64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));

/** Seal policy entries for one stream, as the dashboard does. */
export async function sealPolicy(entries: readonly PolicyEntry[], key: AesGcmKey): Promise<SealedPolicy> {
  const plaintext = new TextEncoder().encode(JSON.stringify({ v: 1, entries }));
  const { ciphertext, iv } = await encrypt(key, plaintext);
  return { iv: toB64(iv), ct: toB64(ciphertext) };
}

/** Open a sealed copy. Throws when the key is wrong or the copy was tampered with. */
export async function openPolicy(sealed: SealedPolicy, key: AesGcmKey): Promise<PolicyEntry[]> {
  const plaintext = await decrypt(key, fromB64(sealed.iv), fromB64(sealed.ct));
  const doc = JSON.parse(new TextDecoder().decode(plaintext)) as { v?: unknown; entries?: unknown };
  if (doc.v !== 1) throw new Error("unknown policy format");
  // Entries this client cannot read are dropped one by one, as in the config file.
  return parsePolicy(doc.entries);
}

async function readJson(file: string): Promise<Record<string, unknown> | null> {
  try {
    const parsed = JSON.parse(await readFile(file, "utf8")) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** The account policy this home last pulled, or null. */
export async function readPulledPolicy(home: string): Promise<PulledPolicy | null> {
  const raw = await readJson(join(home, ACCOUNT_POLICY_FILE));
  if (!raw || typeof raw.version !== "number") return null;
  return { version: raw.version, pulled_at: String(raw.pulled_at ?? ""), entries: parsePolicy(raw.entries) };
}

async function writePulled(home: string, pulled: PulledPolicy): Promise<void> {
  const file = join(home, ACCOUNT_POLICY_FILE);
  await mkdir(home, { recursive: true });
  // Write then rename, so a capture path never reads a torn file.
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(pulled, null, 2) + "\n", "utf8");
  await rename(tmp, file);
}

/** Fetch this stream's copy of the account policy and keep it for the capture paths. */
export async function pullAccountPolicy(home: string, opts: PolicyPullOptions = {}): Promise<PolicyPullResult> {
  if (process.env[ACCOUNT_POLICY_PULL_ENV] === "0") return { outcome: "disabled" };
  try {
    const config = await readJson(join(home, "stream-config.json"));
    const apiToken = typeof config?.api_token === "string" ? config.api_token : "";
    // `stream_secret` is the current key; `passphrase` is the older name.
    const passphrase = String(config?.stream_secret || config?.passphrase || "");
    const license = (await readJson(join(home, "license-cache.json")))?.response as
      | { customer_id?: unknown; tier?: unknown }
      | undefined;
    const customerId = typeof license?.customer_id === "string" ? license.customer_id : "";
    if (!apiToken || !passphrase || !customerId) return { outcome: "no-credentials" };
    // Account policies come with the hosted dashboard; a free stream has none to pull.
    if (license?.tier === "free") return { outcome: "none" };
    const apiUrl = (typeof config?.api_url === "string" && config.api_url ? config.api_url : "https://api.omnodex.com")
      .replace(/\/$/, "");

    const held = await readPulledPolicy(home);
    const res = await (opts.fetchFn ?? fetch)(`${apiUrl}/api/v1/policy`, {
      headers: {
        Authorization: `Bearer ${apiToken}`,
        ...(held ? { "If-None-Match": `"v${held.version}"` } : {}),
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const now = (opts.now?.() ?? new Date()).toISOString();

    if (res.status === 304 && held) {
      await writePulled(home, { ...held, pulled_at: now });
      return { outcome: "current", version: held.version, entries: held.entries.length };
    }
    if (res.status === 404) {
      // The account has no policy for this stream (or it was removed).
      await rm(join(home, ACCOUNT_POLICY_FILE), { force: true });
      return { outcome: "none" };
    }
    if (res.status !== 200) return { outcome: "failed" };
    const body = (await res.json()) as { version?: unknown; iv?: unknown; ct?: unknown };
    if (typeof body.version !== "number" || typeof body.iv !== "string" || typeof body.ct !== "string") {
      return { outcome: "failed" };
    }
    const entries = await openPolicy({ iv: body.iv, ct: body.ct }, await derivePolicyKey(passphrase, customerId));
    await writePulled(home, { version: body.version, pulled_at: now, entries });
    return { outcome: "updated", version: body.version, entries: entries.length };
  } catch {
    return { outcome: "failed" };
  }
}
