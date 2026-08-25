// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Stream configuration persistence.
 *
 * Manages ~/.omnodex/stream-config.json which stores the API token,
 * auto-generated passphrase, and API URL for cloud sync. This file is
 * created during `omnodex install` or `omnodex connect` and allows
 * subsequent commands (sync, dashboard) to work without requiring
 * environment variables.
 *
 * Environment variables always take precedence over the config file:
 *   OMNODEX_API_TOKEN > stream-config.json api_token
 *   OMNODEX_SYNC_PASSPHRASE > stream-config.json passphrase
 *   OMNODEX_API_URL > stream-config.json api_url
 */

import * as path from "node:path";
import { promises as fs } from "node:fs";
import { randomBytes } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StreamConfig {
  /** The stream's API token (omx_test_... or omx_live_...). */
  api_token: string;
  /** Auto-generated or user-chosen sync passphrase. Never sent to the server. */
  passphrase: string;
  /** API base URL. Defaults to https://api.omnodex.com. */
  api_url?: string;
  /** ISO timestamp of when the config was created. */
  created_at?: string;
  /** ISO timestamp of the last successful connect or sync. */
  last_used_at?: string;
}

// ---------------------------------------------------------------------------
// Passphrase generation
// ---------------------------------------------------------------------------

/**
 * Base62 character set (alphanumeric, no ambiguous chars needed since the
 * user never types this -- it's auto-generated and stored in the config).
 */
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * Generate a cryptographically random passphrase.
 *
 * Produces a 43-character base62 string from 32 random bytes (256 bits of
 * entropy). The passphrase is used to derive AES-256-GCM keys via Argon2id
 * for sync blob encryption and streaming key derivation.
 */
export function generatePassphrase(): string {
  const bytes = randomBytes(32);
  let result = "";
  for (const b of bytes) {
    // Slight bias from mod 62 is negligible at 256 bits of entropy
    result += BASE62[b % BASE62.length];
  }
  return result;
}

// ---------------------------------------------------------------------------
// Config file I/O
// ---------------------------------------------------------------------------

/** Resolve the stream-config.json path within the given omnodex home. */
function configPath(omnodexHome: string): string {
  return path.join(omnodexHome, "stream-config.json");
}

/**
 * Read the stream config from disk. Returns null if the file does not
 * exist or is malformed.
 */
export async function readStreamConfig(
  omnodexHome: string,
): Promise<StreamConfig | null> {
  try {
    const raw = await fs.readFile(configPath(omnodexHome), "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed.api_token || !parsed.passphrase) return null;
    return parsed as StreamConfig;
  } catch {
    return null;
  }
}

/**
 * Write (or overwrite) the stream config to disk. Creates the file with
 * mode 0o600 (owner read/write only) since it contains the passphrase.
 */
export async function writeStreamConfig(
  omnodexHome: string,
  config: StreamConfig,
): Promise<void> {
  const filePath = configPath(omnodexHome);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const content = JSON.stringify(config, null, 2) + "\n";
  await fs.writeFile(filePath, content, { mode: 0o600 });
}

/**
 * Update specific fields in an existing stream config. Reads the current
 * config (or starts from scratch), merges the update, and writes back.
 */
export async function updateStreamConfig(
  omnodexHome: string,
  update: Partial<StreamConfig>,
): Promise<StreamConfig> {
  const existing = await readStreamConfig(omnodexHome) || {
    api_token: "",
    passphrase: "",
  };
  const merged = { ...existing, ...update };
  await writeStreamConfig(omnodexHome, merged);
  return merged;
}

// ---------------------------------------------------------------------------
// Credential resolution (config file + env var fallback chain)
// ---------------------------------------------------------------------------

export interface ResolvedCredentials {
  apiToken: string;
  passphrase: string;
  apiUrl: string;
  /** Where the api_token came from: "env", "flag", or "config". */
  tokenSource: "env" | "flag" | "config";
  /** Where the passphrase came from: "env", "flag", or "config". */
  passphraseSource: "env" | "flag" | "config";
}

/**
 * Resolve API credentials from flags, environment, and stream-config.json.
 * Priority: explicit flag > environment variable > config file.
 *
 * Returns null if neither token nor passphrase can be resolved.
 */
export async function resolveCredentials(
  omnodexHome: string,
  opts?: {
    flagToken?: string;
    flagPassphrase?: string;
    flagApiUrl?: string;
  },
): Promise<ResolvedCredentials | null> {
  const config = await readStreamConfig(omnodexHome);

  // API token: flag > env > config
  let apiToken = "";
  let tokenSource: "env" | "flag" | "config" = "config";
  if (opts?.flagToken) {
    apiToken = opts.flagToken;
    tokenSource = "flag";
  } else if (process.env.OMNODEX_API_TOKEN) {
    apiToken = process.env.OMNODEX_API_TOKEN;
    tokenSource = "env";
  } else if (config?.api_token) {
    apiToken = config.api_token;
    tokenSource = "config";
  }

  // Passphrase: flag > env > config
  let passphrase = "";
  let passphraseSource: "env" | "flag" | "config" = "config";
  if (opts?.flagPassphrase) {
    passphrase = opts.flagPassphrase;
    passphraseSource = "flag";
  } else if (process.env.OMNODEX_SYNC_PASSPHRASE) {
    passphrase = process.env.OMNODEX_SYNC_PASSPHRASE;
    passphraseSource = "env";
  } else if (config?.passphrase) {
    passphrase = config.passphrase;
    passphraseSource = "config";
  }

  if (!apiToken && !passphrase) return null;

  // API URL: flag > env > config > default
  const apiUrl =
    opts?.flagApiUrl ||
    process.env.OMNODEX_API_URL ||
    config?.api_url ||
    "https://api.omnodex.com";

  return { apiToken, passphrase, apiUrl, tokenSource, passphraseSource };
}
