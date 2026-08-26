// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- shim cloud push
 *
 * Lightweight cloud event push for hook shims. Encrypts a single event
 * with a cached streaming key and POSTs it to the cloud API. Designed
 * for short-lived shim processes: reads credentials and cached key from
 * disk, avoids expensive Argon2id re-derivation on every invocation.
 *
 * Fire-and-forget: errors are swallowed so the shim never blocks the
 * host AI agent. The local JSONL event log remains the source of truth;
 * cloud push is best-effort real-time delivery.
 *
 * Key caching:
 *   - Derived streaming key (raw bytes + key_id) is cached to
 *     OMNODEX_HOME/streaming-key-cache.json.
 *   - Cache is keyed by SHA-256(passphrase || customer_id). If
 *     credentials change, the cache is invalidated and re-derived.
 *   - Argon2id (64MB, 3 iterations) runs only on cache miss (~200-500ms).
 *   - Cache hit path is <5ms (JSON parse + AES-GCM import).
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { webcrypto } from "node:crypto";
import type { TraceEvent } from "@omnodex/shared";
import { deriveStreamingKey, computeKeyId } from "./crypto.js";
import type { AesGcmKey } from "./crypto.js";
import { encrypt } from "./crypto.js";

const subtle = webcrypto.subtle;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface StreamConfig {
  api_token: string;
  passphrase: string;
  api_url?: string;
}

interface LicenseCacheFile {
  response: {
    customer_id: string;
    tier: string;
    features: string[];
  };
  fetched_at: number;
}

interface KeyCache {
  /** SHA-256 hex of (passphrase + customer_id) for invalidation. */
  credentials_hash: string;
  /** Base64-encoded raw AES-256-GCM key bytes. */
  key_raw: string;
  /** First 8 hex chars of SHA-256(key). */
  key_id: string;
  /** ISO timestamp of when the key was derived. */
  cached_at: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function sha256Hex(input: string): Promise<string> {
  const hash = await subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(hash), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  // Use Buffer in Node.js for reliable base64
  return Buffer.from(bytes).toString("base64");
}

function base64ToUint8(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// ---------------------------------------------------------------------------
// Credential + cache readers
// ---------------------------------------------------------------------------

async function readStreamConfig(
  omnodexHome: string,
): Promise<StreamConfig | null> {
  try {
    const raw = await readFile(join(omnodexHome, "stream-config.json"), "utf-8");
    const parsed = JSON.parse(raw) as StreamConfig;
    if (!parsed.api_token || !parsed.passphrase) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function readLicenseCache(
  omnodexHome: string,
): Promise<LicenseCacheFile | null> {
  try {
    const raw = await readFile(join(omnodexHome, "license-cache.json"), "utf-8");
    return JSON.parse(raw) as LicenseCacheFile;
  } catch {
    return null;
  }
}

async function readKeyCache(omnodexHome: string): Promise<KeyCache | null> {
  try {
    const raw = await readFile(
      join(omnodexHome, "streaming-key-cache.json"),
      "utf-8",
    );
    return JSON.parse(raw) as KeyCache;
  } catch {
    return null;
  }
}

async function writeKeyCache(
  omnodexHome: string,
  cache: KeyCache,
): Promise<void> {
  await mkdir(omnodexHome, { recursive: true });
  await writeFile(
    join(omnodexHome, "streaming-key-cache.json"),
    JSON.stringify(cache, null, 2) + "\n",
    { mode: 0o600 },
  );
}

// ---------------------------------------------------------------------------
// Key resolution (cached or freshly derived)
// ---------------------------------------------------------------------------

async function resolveStreamingKey(
  passphrase: string,
  customerId: string,
  omnodexHome: string,
): Promise<{ key: AesGcmKey; keyId: string }> {
  const credHash = await sha256Hex(passphrase + "\0" + customerId);

  // Try cached key
  const cached = await readKeyCache(omnodexHome);
  if (cached && cached.credentials_hash === credHash) {
    const rawBytes = base64ToUint8(cached.key_raw);
    const key = await subtle.importKey(
      "raw",
      rawBytes,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"],
    );
    return { key, keyId: cached.key_id };
  }

  // Cache miss: derive (expensive Argon2id + HKDF)
  const key = await deriveStreamingKey(passphrase, customerId);
  const keyId = await computeKeyId(key);

  // Export and cache for future shim invocations
  const rawExported = new Uint8Array(await subtle.exportKey("raw", key));
  const cacheEntry: KeyCache = {
    credentials_hash: credHash,
    key_raw: Buffer.from(rawExported).toString("base64"),
    key_id: keyId,
    cached_at: new Date().toISOString(),
  };
  await writeKeyCache(omnodexHome, cacheEntry).catch(() => {});

  return { key, keyId };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Push a single trace event to the Omnodex cloud API.
 *
 * Designed for hook shims: reads credentials from disk, uses a cached
 * streaming key, encrypts the event, and POSTs it. Fire-and-forget --
 * never throws or blocks the caller. Returns true if the push was
 * attempted, false if skipped (no credentials, wrong tier, etc.).
 *
 * @param events - One or more trace events to push.
 * @param omnodexHome - Path to OMNODEX_HOME (e.g. ~/.omnodex).
 * @param timeoutMs - Network timeout in ms. Default: 3000.
 */
export async function pushEventsToCloud(
  events: TraceEvent[],
  omnodexHome: string,
  timeoutMs = 3000,
): Promise<boolean> {
  try {
    // 1. Read credentials
    const config = await readStreamConfig(omnodexHome);
    if (!config) return false;

    // 2. Read cached license for customer_id and feature check
    const licenseCache = await readLicenseCache(omnodexHome);
    if (!licenseCache?.response) return false;

    const { customer_id, features } = licenseCache.response;
    if (!features.includes("live_streaming")) return false;

    // 3. Resolve streaming key (cached or freshly derived)
    const { key, keyId } = await resolveStreamingKey(
      config.passphrase,
      customer_id,
      omnodexHome,
    );

    // 4. Encrypt each event
    const encryptedEvents: Array<{
      event_id: string;
      iv: string;
      ct: string;
      key_id: string;
      ts: number;
    }> = [];

    for (const event of events) {
      const plaintext = new TextEncoder().encode(JSON.stringify(event));
      const { ciphertext, iv } = await encrypt(key, plaintext);
      encryptedEvents.push({
        event_id: event.event_id,
        iv: uint8ToBase64(iv),
        ct: uint8ToBase64(ciphertext),
        key_id: keyId,
        ts: Date.now(),
      });
    }

    // 5. POST to cloud API (fire-and-forget with timeout)
    const apiUrl = (config.api_url || "https://api.omnodex.com").replace(
      /\/$/,
      "",
    );
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(apiUrl + "/api/v1/sync/events", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + config.api_token,
        },
        body: JSON.stringify({
          key_id: keyId,
          events: encryptedEvents,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        // Consume body to free resources, but don't throw
        await res.text().catch(() => {});
      }
    } finally {
      clearTimeout(timer);
    }

    return true;
  } catch {
    // Fire-and-forget: silently swallow all errors
    return false;
  }
}
