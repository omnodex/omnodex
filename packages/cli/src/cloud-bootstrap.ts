// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Finish a cloud connection so the home streams and syncs straight away.
 *
 * A token in stream-config.json is not enough on its own: live push and
 * automatic sync read the customer ID and features from license-cache.json,
 * and existing sessions reach the hosted dashboard only through a blob sync.
 * After connect or install has a token, this validates the license into the
 * home's cache and, the first time, uploads the existing sessions.
 */

import {
  validateLicense,
  clearCache as clearLicenseCache,
} from "@omnodex/license-client";
import type { ValidateResult } from "@omnodex/license-client";
import { runAutoSync, readAutoSyncState } from "@omnodex/sync-encryptor";
import type { AutoSyncOutcome } from "@omnodex/sync-encryptor";

export interface BootstrapOptions {
  home: string;
  apiToken: string;
  apiUrl: string;
  /**
   * Drop any cached license first. Set when the token is new, so a cache
   * written for an earlier token is not reused.
   */
  refresh: boolean;
  /** Test overrides. */
  validate?: typeof validateLicense;
  sync?: (home: string) => Promise<AutoSyncOutcome>;
}

export type BootstrapResult =
  /** License could not be fetched; hooks fetch it on their next event. */
  | { status: "unverified" }
  /** Valid license without encrypted sync (for example the free tier). */
  | { status: "not-entitled"; tier: string }
  /** Entitled, and this home had already synced; nothing uploaded. */
  | { status: "ready"; tier: string }
  /** Entitled, and the initial sync ran. */
  | { status: "synced"; tier: string }
  | { status: "sync-failed"; tier: string; error: string };

export async function bootstrapCloudConnection(
  opts: BootstrapOptions,
): Promise<BootstrapResult> {
  if (opts.refresh) await clearLicenseCache(opts.home);

  const validate = opts.validate ?? validateLicense;
  const result: ValidateResult = await validate({
    apiBaseUrl: opts.apiUrl,
    apiToken: opts.apiToken,
    cacheDir: opts.home,
  });
  if (result.source === "defaults") return { status: "unverified" };

  const { tier, features } = result.license;
  if (!features.includes("encrypted_sync")) return { status: "not-entitled", tier };

  const state = await readAutoSyncState(opts.home);
  if (state.last_success_at) return { status: "ready", tier };

  const sync = opts.sync ?? runAutoSync;
  const outcome = await sync(opts.home);
  if (outcome === "synced") return { status: "synced", tier };
  // A hook or proxy started the same sync a moment earlier.
  if (outcome === "in-progress") return { status: "ready", tier };
  const after = await readAutoSyncState(opts.home);
  return {
    status: "sync-failed",
    tier,
    error: after.last_error ?? outcome,
  };
}

/** One line per outcome, prefixed like the command that called it. */
export function describeBootstrap(prefix: string, result: BootstrapResult): string[] {
  switch (result.status) {
    case "unverified":
      return [
        `[${prefix}] could not reach the license service; streaming starts once it can be reached`,
      ];
    case "not-entitled":
      return [
        `[${prefix}] tier "${result.tier}" does not include cloud sync; events stay local`,
      ];
    case "ready":
      return [`[${prefix}] cloud streaming and sync ready (${result.tier})`];
    case "synced":
      return [
        `[${prefix}] cloud streaming ready (${result.tier}); existing sessions uploaded`,
      ];
    case "sync-failed":
      return [
        `[${prefix}] cloud streaming ready (${result.tier}), but the initial upload failed: ${result.error}`,
        `[${prefix}] sessions upload at the next session end, or run: omnodex sync`,
      ];
  }
}
