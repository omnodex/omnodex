// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Where sealed capture is allowed to run, and where its settings come from.
 *
 * A hook command committed to a repository, or installed into a devcontainer
 * image, runs on every machine that uses the repository. It must stay silent
 * on laptops and capture only on the hosts it was meant for, so each provider
 * has an environment gate, and a missing or invalid configuration captures
 * nothing.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { computePublicKeyId, base64ToBytes } from "@omnodex/sync-encryptor/hpke-event";
import { parseIngestConfig, type IngestConfig } from "@omnodex/hooks-provider";

export type SealedProvider = "claude-code" | "copilot" | "cursor" | "codex" | "antigravity";

export const SEALED_PROVIDERS: readonly SealedProvider[] = ["claude-code", "copilot", "cursor", "codex", "antigravity"];

export function isSealedProvider(value: unknown): value is SealedProvider {
  return typeof value === "string" && (SEALED_PROVIDERS as readonly string[]).includes(value);
}

type Env = Record<string, string | undefined>;

const TRUTHY = /^(1|true|yes|on)$/i;

function isSet(value: string | undefined): boolean {
  return typeof value === "string" && value.length > 0 && !/^(0|false|no|off)$/i.test(value) && !value.startsWith("${");
}

/**
 * Whether this host is one that should capture.
 *
 *   OMNODEX_SEALED=0      never capture (off switch)
 *   OMNODEX_SEALED=1      capture here, whatever the host (devcontainers, dev
 *                         servers and tests set this)
 *   host marker           a file named ephemeral-host in the Omnodex home, written
 *                         by `omnodex install --ephemeral` on a host that was set
 *                         up to capture
 *   OMNODEX_SEALED_WHEN   name of an environment variable the host sets, for
 *                         surfaces whose marker is not built in; capture when
 *                         that variable is set and not 0 or false
 *   CLAUDE_CODE_REMOTE    set to "true" by Claude Code's cloud sessions
 *
 * Anywhere else the answer is no.
 */
export function shouldCapture(provider: SealedProvider, env: Env, hostMarker = false): boolean {
  const switchValue = env.OMNODEX_SEALED;
  if (switchValue !== undefined && /^(0|false|no|off)$/i.test(switchValue)) return false;
  if (switchValue !== undefined && TRUTHY.test(switchValue)) return true;
  if (hostMarker) return true;
  const when = env.OMNODEX_SEALED_WHEN;
  if (when && /^[A-Za-z_][A-Za-z0-9_]*$/.test(when) && isSet(env[when])) return true;
  if (provider === "claude-code" && env.CLAUDE_CODE_REMOTE === "true") return true;
  return false;
}

/** Name of the file, in the Omnodex home, that marks a host as set up to capture. */
export const HOST_MARKER_FILE = "ephemeral-host";

/** The provider a hook shim file name stands for, such as `claude-hook-shim.js`. */
export function providerFromShimName(file: string | undefined): SealedProvider | undefined {
  const base = file ? (file.split(/[\\/]/).pop() ?? "") : "";
  const m = /^(claude|codex|copilot|cursor|antigravity)-hook-shim\.js$/.exec(base);
  if (!m) return undefined;
  return m[1] === "claude" ? "claude-code" : (m[1] as SealedProvider);
}

/** The names under which settings can be given, as environment variables. */
export const ENV_NAMES = {
  config: "OMNODEX_INGEST_CONFIG",
  publicKey: "OMNODEX_INGEST_PUBLIC_KEY",
  keyId: "OMNODEX_INGEST_KEY_ID",
  sourceId: "OMNODEX_INGEST_SOURCE_ID",
  apiBase: "OMNODEX_INGEST_API_BASE",
  token: "OMNODEX_INGEST_TOKEN",
  redact: "OMNODEX_INGEST_REDACT",
} as const;

function readJson(file: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Candidate files, first match wins: explicit path, the project's, then the home's. */
function configFiles(env: Env, home: string, projectDirs: string[]): string[] {
  const files: string[] = [];
  if (isSet(env[ENV_NAMES.config])) files.push(env[ENV_NAMES.config]!);
  for (const dir of projectDirs) files.push(path.join(dir, ".omnodex", "ingest.json"));
  files.push(path.join(home, "ingest.json"));
  return files;
}

/**
 * Reads the settings: a JSON file (the same fields as a Cowork ingest.json,
 * with `version` and `ingest_token` optional) overlaid by environment
 * variables. Returns null when anything required is missing or invalid, so a
 * half-configured host captures nothing instead of sealing to a wrong key.
 *
 * The token is never needed here: when a proxy in front of the host attaches
 * the Authorization header, leave it out and nothing secret sits on the host.
 */
export async function loadSealedConfig(
  env: Env,
  options: { home: string; projectDirs?: string[] },
): Promise<IngestConfig | null> {
  let raw: Record<string, unknown> = {};
  for (const file of configFiles(env, options.home, options.projectDirs ?? [])) {
    const fromFile = readJson(file);
    if (fromFile) {
      raw = { ...fromFile };
      break;
    }
  }
  const set = (key: string, name: string): void => {
    if (isSet(env[name])) raw[key] = env[name];
  };
  set("public_key", ENV_NAMES.publicKey);
  set("key_id", ENV_NAMES.keyId);
  set("source_id", ENV_NAMES.sourceId);
  set("api_base", ENV_NAMES.apiBase);
  set("ingest_token", ENV_NAMES.token);
  if (isSet(env[ENV_NAMES.redact])) raw.redact_parameters = TRUTHY.test(env[ENV_NAMES.redact]!);
  if (raw.version === undefined) raw.version = 1;
  // A key_id is derived from the public key when not given.
  if (raw.key_id === undefined && typeof raw.public_key === "string") {
    try {
      raw.key_id = await computePublicKeyId(base64ToBytes(raw.public_key));
    } catch {
      return null;
    }
  }
  // An empty token is the same as none.
  if (raw.ingest_token === "") delete raw.ingest_token;
  return parseIngestConfig(raw, { tokenOptional: true });
}
