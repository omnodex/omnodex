// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- license cache for live push and auto-sync
 *
 * Live push and automatic sync need the customer ID and feature list from
 * OMNODEX_HOME/license-cache.json. `omnodex connect` writes that file, but a
 * home can still be without it: connected by an older CLI, or its token
 * copied in by hand. Rather than skip silently forever, a missing cache is
 * fetched once from the license endpoint and written to the same file.
 *
 * An existing cache is used as-is, expired or not, so the per-event cost
 * stays a file read. A failed fetch writes nothing and returns null; the
 * next event tries again.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { validateLicense } from "@omnodex/license-client";

export interface CachedLicense {
  customer_id: string;
  tier: string;
  features: string[];
}

export interface LicenseCredentials {
  apiToken: string;
  apiUrl: string;
  /** Timeout for the fetch when the cache is missing. */
  timeoutMs: number;
}

/**
 * Read the cached license in `home`, fetching and caching it when the file
 * is missing. Returns null when there is no cache and none could be fetched.
 */
export async function readOrFetchLicense(
  home: string,
  creds: LicenseCredentials,
): Promise<CachedLicense | null> {
  const cached = await readCachedLicense(home);
  if (cached) return cached;
  if (!creds.apiToken) return null;

  const result = await validateLicense({
    apiBaseUrl: creds.apiUrl,
    apiToken: creds.apiToken,
    cacheDir: home,
    timeoutMs: creds.timeoutMs,
  });
  // Anything but a network answer is the free-tier fallback, not a license.
  return result.source === "network" ? result.license : null;
}

async function readCachedLicense(home: string): Promise<CachedLicense | null> {
  try {
    const raw = await readFile(join(home, "license-cache.json"), "utf-8");
    const response = (JSON.parse(raw) as { response?: Partial<CachedLicense> }).response;
    if (typeof response?.customer_id !== "string" || !Array.isArray(response.features)) {
      return null;
    }
    return {
      customer_id: response.customer_id,
      tier: typeof response.tier === "string" ? response.tier : "",
      features: response.features,
    };
  } catch {
    return null;
  }
}
