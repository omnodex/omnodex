// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- advanced rule bundle refresh
 *
 * Keeps OMNODEX_HOME/rules/current.bundle.json current for a Pro or
 * Enterprise install, as part of the background pass, before detection runs.
 *
 * Two authenticated requests, kept separate on purpose:
 *
 *   GET  /api/v1/rules/update?since=<installed>   the sealed bundle, or 304
 *   POST /api/v1/license/validate                 the key that opens it
 *
 * Neither is any use without the other, and both need an entitled account.
 * The key is cached with the licence (license-cache.json), next to the API
 * token and passphrase that already live in this home; the opened rules are
 * never written anywhere.
 *
 * Revocation needs nothing here: the licence is re-validated when its cache
 * goes stale, a lapsed account gets the free answer with no key, and the
 * bundle already on disk stops opening. It also stops being accepted at its
 * own not_after, whatever the licence says.
 *
 * Installs whose cached licence is not Pro or Enterprise make no request at
 * all, so free and Hosted users cost the cloud nothing for this. Never
 * throws; every failure leaves whatever bundle and key were already there.
 */

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { validateLicense, type LicenseClientConfig, type ValidateResult } from "@omnodex/license-client";

/** Where a home keeps its sealed bundle. Must match the analyzer's bundlePath. */
export const RULE_BUNDLE_FILE = join("rules", "current.bundle.json");

/** Set to "0" to skip the refresh. */
export const RULES_REFRESH_ENV = "OMNODEX_RULES_REFRESH";

const REQUEST_TIMEOUT_MS = 10_000;
const ENTITLED_TIERS = new Set(["pro", "enterprise"]);

export type RulesRefreshOutcome =
  | "disabled"
  | "no-credentials"
  | "not-entitled"
  | "no-bundle"
  | "current"
  | "updated"
  | "failed";

export interface RulesRefreshOptions {
  /** HTTP, for tests. */
  fetchFn?: typeof fetch;
  /** Licence validation, for tests. */
  validate?: (config: LicenseClientConfig) => Promise<ValidateResult>;
}

async function readJson(file: string): Promise<Record<string, unknown> | null> {
  try {
    const parsed = JSON.parse(await readFile(file, "utf8")) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** The version of the bundle this home already holds, if any. */
async function installedVersion(home: string): Promise<string | null> {
  const bundle = await readJson(join(home, RULE_BUNDLE_FILE));
  const manifest = bundle?.manifest as { bundle_version?: unknown } | undefined;
  return typeof manifest?.bundle_version === "string" ? manifest.bundle_version : null;
}

/** Write the bundle in one step, so a reader never sees half a file. */
async function installBundle(home: string, bundle: unknown): Promise<void> {
  const file = join(home, RULE_BUNDLE_FILE);
  await mkdir(join(home, "rules"), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(bundle), "utf8");
  await rename(tmp, file);
}

/** Bring this home's advanced rule bundle and its key up to date. */
export async function refreshRuleBundle(
  home: string,
  opts: RulesRefreshOptions = {},
): Promise<RulesRefreshOutcome> {
  if (process.env[RULES_REFRESH_ENV] === "0") return "disabled";
  try {
    const config = await readJson(join(home, "stream-config.json"));
    const apiToken = typeof config?.api_token === "string" ? config.api_token : "";
    if (!apiToken) return "no-credentials";
    const apiUrl = (typeof config?.api_url === "string" && config.api_url ? config.api_url : "https://api.omnodex.com")
      .replace(/\/$/, "");

    // Decide from the cached licence first, so a free or Hosted install
    // never makes a request here.
    const cached = (await readJson(join(home, "license-cache.json")))?.response as { tier?: unknown } | undefined;
    if (!ENTITLED_TIERS.has(String(cached?.tier ?? ""))) return "not-entitled";

    const validate = opts.validate ?? validateLicense;
    const licenseConfig: LicenseClientConfig = { apiBaseUrl: apiUrl, apiToken, cacheDir: home };
    // Re-validates only when the cached licence is stale, which is also how
    // a cancelled subscription loses its key.
    let license = (await validate(licenseConfig)).license;
    if (!ENTITLED_TIERS.has(license.tier)) return "not-entitled";

    const installed = await installedVersion(home);
    const fetchFn = opts.fetchFn ?? fetch;
    const res = await fetchFn(
      `${apiUrl}/api/v1/rules/update${installed ? `?since=${encodeURIComponent(installed)}` : ""}`,
      {
        headers: { Authorization: `Bearer ${apiToken}` },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );

    let version: string;
    let outcome: RulesRefreshOutcome;
    if (res.status === 304 && installed) {
      version = installed;
      outcome = "current";
    } else if (res.status === 200) {
      const body = (await res.json()) as { bundle_version?: unknown; bundle?: unknown };
      if (typeof body.bundle_version !== "string" || !body.bundle) return "failed";
      await installBundle(home, body.bundle);
      version = body.bundle_version;
      outcome = "updated";
    } else if (res.status === 403) {
      return "not-entitled";
    } else if (res.status === 404) {
      return "no-bundle";
    } else {
      return "failed";
    }

    // A newer bundle than the cached key opens: ask for the key now rather
    // than waiting a day for the licence cache to go stale.
    if (license.rule_bundle?.bundle_version !== version) {
      license = (await validate({ ...licenseConfig, force: true })).license;
    }
    return outcome;
  } catch {
    return "failed";
  }
}
