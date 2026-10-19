// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- guardrails module refresh
 *
 * Keeps OMNODEX_HOME/guardrails/current.module.json current for a Pro or
 * Enterprise install, the way rules-refresh.ts keeps the advanced rule
 * bundle: the background pass checks it, and `omnodex enforce guardrails`
 * checks it at once.
 *
 *   GET  /api/v1/guardrails/update?interface=<n>&since=<installed>
 *                                         the sealed module, or 304
 *   POST /api/v1/license/validate         the key that opens it
 *
 * The client names the module interface it speaks, so the cloud never hands
 * it a module it cannot run. The module stays sealed on disk; the analyzer
 * opens it in memory (enforcement/module.ts).
 *
 * Installs whose cached license is not Pro or Enterprise make no request.
 * Never throws; every failure leaves whatever module and key were there.
 */

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { GUARDRAILS_INTERFACE } from "@omnodex/shared";
import { validateLicense, type LicenseClientConfig, type ValidateResult } from "@omnodex/license-client";

/** Where a home keeps its sealed module. Must match the analyzer's modulePath. */
export const GUARDRAILS_MODULE_FILE = join("guardrails", "current.module.json");
/** When the last check ran and what it found. */
export const GUARDRAILS_REFRESH_STATE_FILE = join("guardrails", "refresh-state.json");
/** Set to "0" to skip the refresh. */
export const GUARDRAILS_REFRESH_ENV = "OMNODEX_GUARDRAILS_REFRESH";

const REQUEST_TIMEOUT_MS = 10_000;
const ENTITLED_TIERS = new Set(["pro", "enterprise"]);

export type GuardrailsRefreshOutcome =
  | "disabled"
  | "waiting"
  | "no-credentials"
  | "not-entitled"
  | "no-module"
  | "current"
  | "updated"
  | "failed";

/** How long to wait after a check, by its answer. Others are retried on the next pass. */
const RECHECK_MS: Partial<Record<GuardrailsRefreshOutcome, number>> = {
  current: 60 * 60 * 1000,
  "no-module": 6 * 60 * 60 * 1000,
};

export interface GuardrailsRefreshOptions {
  /** Check now, whatever the last check found. */
  force?: boolean;
  now?: number;
  fetchFn?: typeof fetch;
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

async function installedVersion(home: string): Promise<string | null> {
  const manifest = (await readJson(join(home, GUARDRAILS_MODULE_FILE)))?.manifest as
    | { module_version?: unknown; interface?: unknown }
    | undefined;
  return typeof manifest?.module_version === "string" && manifest.interface === GUARDRAILS_INTERFACE
    ? manifest.module_version
    : null;
}

async function installModule(home: string, sealed: unknown): Promise<void> {
  const file = join(home, GUARDRAILS_MODULE_FILE);
  await mkdir(join(home, "guardrails"), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(sealed), "utf8");
  await rename(tmp, file);
}

/** Whether this home's cached license is a plan that includes guardrails. */
export async function guardrailsEntitled(home: string): Promise<boolean> {
  const cached = (await readJson(join(home, "license-cache.json")))?.response as { tier?: unknown } | undefined;
  return ENTITLED_TIERS.has(String(cached?.tier ?? ""));
}

/** Bring this home's guardrails module and its key up to date. */
export async function refreshGuardrailsModule(
  home: string,
  opts: GuardrailsRefreshOptions = {},
): Promise<GuardrailsRefreshOutcome> {
  if (process.env[GUARDRAILS_REFRESH_ENV] === "0") return "disabled";
  try {
    const config = await readJson(join(home, "stream-config.json"));
    const apiToken = typeof config?.api_token === "string" ? config.api_token : "";
    if (!apiToken) return "no-credentials";
    const apiUrl = (typeof config?.api_url === "string" && config.api_url ? config.api_url : "https://api.omnodex.com")
      .replace(/\/$/, "");

    if (!(await guardrailsEntitled(home))) return "not-entitled";
    const validate = opts.validate ?? validateLicense;
    const licenseConfig: LicenseClientConfig = { apiBaseUrl: apiUrl, apiToken, cacheDir: home };
    let license = (await validate(licenseConfig)).license;
    if (!ENTITLED_TIERS.has(license.tier)) return "not-entitled";

    const now = opts.now ?? Date.now();
    const last = await readJson(join(home, GUARDRAILS_REFRESH_STATE_FILE));
    const wait = RECHECK_MS[last?.outcome as GuardrailsRefreshOutcome];
    const checkedAt = typeof last?.checked_at === "string" ? Date.parse(last.checked_at) : NaN;
    if (!opts.force && wait !== undefined && !Number.isNaN(checkedAt) && now - checkedAt < wait) return "waiting";
    const remember = async (outcome: GuardrailsRefreshOutcome): Promise<GuardrailsRefreshOutcome> => {
      await mkdir(join(home, "guardrails"), { recursive: true });
      await writeFile(join(home, GUARDRAILS_REFRESH_STATE_FILE), JSON.stringify({ checked_at: new Date(now).toISOString(), outcome }), "utf8");
      return outcome;
    };

    const installed = await installedVersion(home);
    const query = `interface=${GUARDRAILS_INTERFACE}${installed ? `&since=${encodeURIComponent(installed)}` : ""}`;
    const res = await (opts.fetchFn ?? fetch)(`${apiUrl}/api/v1/guardrails/update?${query}`, {
      headers: { Authorization: `Bearer ${apiToken}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    let version: string;
    let outcome: GuardrailsRefreshOutcome;
    if (res.status === 304 && installed) {
      version = installed;
      outcome = "current";
    } else if (res.status === 200) {
      const body = (await res.json()) as { module_version?: unknown; module?: unknown };
      if (typeof body.module_version !== "string" || !body.module) return "failed";
      await installModule(home, body.module);
      version = body.module_version;
      outcome = "updated";
    } else if (res.status === 403) {
      return "not-entitled";
    } else if (res.status === 404) {
      return remember("no-module");
    } else {
      return "failed";
    }

    // A module newer than the cached key opens: ask for its key now.
    if (license.guardrails_module?.module_version !== version) {
      license = (await validate({ ...licenseConfig, force: true })).license;
    }
    return remember(outcome);
  } catch {
    return "failed";
  }
}
