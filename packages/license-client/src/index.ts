// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/license-client
 *
 * Validates the user's subscription against the Omnodex cloud API and caches
 * the result locally.  Falls back gracefully when the network is unavailable:
 *
 *   1. If a cached (unexpired) response exists on disk  -> use it.
 *   2. If a cached (expired) response exists on disk    -> use it + warn.
 *   3. If no cache exists at all                        -> return free-tier defaults.
 *
 * The caller never blocks on a network timeout -- the worst case is a stale
 * or free-tier response while the user works offline.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { LicenseValidateResponse } from "@omnodex/shared";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface LicenseClientConfig {
  /** Cloud API base URL. Default: OMNODEX_API_URL env var, or https://api.omnodex.com */
  apiBaseUrl?: string;
  /** API token (omx_...).  Read from env OMNODEX_API_TOKEN if not provided. */
  apiToken?: string;
  /** Where to store the cached license response.  Default: ~/.omnodex/license-cache.json */
  cacheDir?: string;
  /** Network request timeout in ms.  Default: 5000. */
  timeoutMs?: number;
}

const DEFAULT_API_URL = process.env.OMNODEX_API_URL ?? "https://api.omnodex.com";
const DEFAULT_TIMEOUT_MS = 5_000;
const CACHE_FILENAME = "license-cache.json";

/** Returned when no token is configured or no cache exists. */
const FREE_TIER_DEFAULTS: LicenseValidateResponse = {
  customer_id: "local",
  tier: "free",
  features: ["community_rules", "local_dashboard", "local_event_log"],
  ttl_seconds: 86400,
};

// ---------------------------------------------------------------------------
// Cache helpers
// ---------------------------------------------------------------------------

interface CachedLicense {
  response: LicenseValidateResponse;
  fetched_at: number; // epoch ms
}

function cachePath(cacheDir: string): string {
  return join(cacheDir, CACHE_FILENAME);
}

async function readCache(cacheDir: string): Promise<CachedLicense | null> {
  try {
    const raw = await readFile(cachePath(cacheDir), "utf-8");
    return JSON.parse(raw) as CachedLicense;
  } catch {
    return null;
  }
}

async function writeCache(cacheDir: string, response: LicenseValidateResponse): Promise<void> {
  const entry: CachedLicense = { response, fetched_at: Date.now() };
  await mkdir(cacheDir, { recursive: true });
  await writeFile(cachePath(cacheDir), JSON.stringify(entry, null, 2), "utf-8");
}

function isCacheValid(entry: CachedLicense): boolean {
  const ageMs = Date.now() - entry.fetched_at;
  const ttlMs = (entry.response.ttl_seconds ?? 86400) * 1000;
  return ageMs < ttlMs;
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

async function fetchLicense(
  apiBaseUrl: string,
  apiToken: string,
  timeoutMs: number,
): Promise<LicenseValidateResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${apiBaseUrl}/api/v1/license/validate`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "Content-Type": "application/json",
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`License validation failed: HTTP ${res.status}`);
    }

    return (await res.json()) as LicenseValidateResponse;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ValidateResult {
  license: LicenseValidateResponse;
  source: "network" | "cache" | "cache_stale" | "defaults";
}

/**
 * Validate the current subscription.
 *
 * Tries the network first, falls back to cache, then to free-tier defaults.
 * Never throws -- the caller always gets a usable response.
 */
export async function validateLicense(
  config?: LicenseClientConfig,
): Promise<ValidateResult> {
  const apiBaseUrl = (config?.apiBaseUrl ?? DEFAULT_API_URL).replace(/\/$/, "");
  const apiToken = config?.apiToken ?? process.env.OMNODEX_API_TOKEN ?? "";
  const cacheDir = config?.cacheDir ?? join(homedir(), ".omnodex");
  const timeoutMs = config?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // No token configured -- free tier, no network call.
  if (!apiToken) {
    return { license: FREE_TIER_DEFAULTS, source: "defaults" };
  }

  // Try cache first to see if we even need to hit the network.
  const cached = await readCache(cacheDir);
  if (cached && isCacheValid(cached)) {
    return { license: cached.response, source: "cache" };
  }

  // Cache is missing or stale -- try the network.
  try {
    const response = await fetchLicense(apiBaseUrl, apiToken, timeoutMs);
    await writeCache(cacheDir, response).catch(() => {
      // Cache write failure is non-fatal.
    });
    return { license: response, source: "network" };
  } catch {
    // Network failed.  Use stale cache if we have one.
    if (cached) {
      return { license: cached.response, source: "cache_stale" };
    }
    // No cache at all -- return free-tier defaults.
    return { license: FREE_TIER_DEFAULTS, source: "defaults" };
  }
}

/**
 * Clear the local license cache.  Useful after logout or token rotation.
 */
export async function clearCache(cacheDir?: string): Promise<void> {
  const dir = cacheDir ?? join(homedir(), ".omnodex");
  const { unlink } = await import("node:fs/promises");
  await unlink(cachePath(dir)).catch(() => {});
}

export { FREE_TIER_DEFAULTS };
export type { LicenseValidateResponse };
