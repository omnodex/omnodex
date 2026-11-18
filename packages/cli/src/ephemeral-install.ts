// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex install --ephemeral`: set up a disposable host (dev server,
 * devcontainer, Codespace, self-hosted agent runner) with no human step.
 *
 * The host gets the sealed hook in place of each agent's usual shim, so every
 * hook event is sealed to the stream's public key and sent to write-only
 * ingest. Nothing secret is stored: the public key and source id are the only
 * settings written, and an ingest token is never written to disk. There is no
 * sign-in, no passphrase and no local event log to lose with the box.
 *
 * The agents' hooks are installed by the normal install path, through the
 * launcher; this module only puts the sealed hook where the launcher looks
 * first (`shim_paths`) and marks the host as set up to capture.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { HOST_MARKER_FILE, loadSealedConfig } from "@omnodex/sealed-hook";

/** Agents the sealed hook supports, with the shim file name each launcher runs. */
export const EPHEMERAL_SHIMS = {
  "claude-code": "claude-hook-shim.js",
  codex: "codex-hook-shim.js",
  copilot: "copilot-hook-shim.js",
  cursor: "cursor-hook-shim.js",
  antigravity: "antigravity-hook-shim.js",
} as const;

export type EphemeralTarget = keyof typeof EPHEMERAL_SHIMS;

export function isEphemeralTarget(value: string): value is EphemeralTarget {
  return Object.prototype.hasOwnProperty.call(EPHEMERAL_SHIMS, value);
}

/** What an ephemeral host captures when no agent is named. */
export const DEFAULT_EPHEMERAL_TARGETS: readonly EphemeralTarget[] = ["claude-code", "codex"];

export interface EphemeralInstallOptions {
  /** The Omnodex home on this host. */
  home: string;
  env: Record<string, string | undefined>;
  targets: readonly EphemeralTarget[];
  /** The sealed hook file shipped with this CLI. */
  sealedHook: string;
  /** Installs one agent's hooks through the normal path. */
  installTarget: (target: EphemeralTarget) => Promise<void>;
  log: (message: string) => void;
}

export type EphemeralResult = { ok: true } | { ok: false; reason: string };

async function readJsonObject(file: string): Promise<Record<string, unknown>> {
  try {
    const parsed: unknown = JSON.parse(await fs.readFile(file, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Sets up the host. Changes nothing when the settings or the sealed hook are missing. */
export async function installEphemeral(options: EphemeralInstallOptions): Promise<EphemeralResult> {
  const { home, env, targets } = options;
  const config = await loadSealedConfig(env, { home });
  if (!config) {
    return {
      ok: false,
      reason:
        "capture settings are missing or invalid: set OMNODEX_INGEST_PUBLIC_KEY and OMNODEX_INGEST_SOURCE_ID " +
        "(and OMNODEX_INGEST_API_BASE if you do not use api.omnodex.com), or place them in the home's ingest.json",
    };
  }
  try {
    await fs.access(options.sealedHook);
  } catch {
    return { ok: false, reason: `the sealed hook is not next to this CLI (${options.sealedHook}); install the published omnodex package` };
  }

  const shimDir = path.join(home, "sealed");
  await fs.mkdir(shimDir, { recursive: true });
  const shimPaths: Record<string, string> = {};
  for (const target of targets) {
    const dest = path.join(shimDir, EPHEMERAL_SHIMS[target]);
    await fs.copyFile(options.sealedHook, dest);
    await fs.chmod(dest, 0o755);
    shimPaths[target] = dest;
  }

  // The launcher reads shim_paths before it searches for an npm install.
  const configPath = path.join(home, "omnodex-config.json");
  const current = await readJsonObject(configPath);
  const existing =
    current.shim_paths && typeof current.shim_paths === "object" ? (current.shim_paths as Record<string, string>) : {};
  current.shim_paths = { ...existing, ...shimPaths };
  await fs.writeFile(configPath, JSON.stringify(current, null, 2) + "\n", "utf8");

  // Settings the hooks read on every call. Public values only: no token.
  const settings = {
    version: 1,
    source_id: config.sourceId,
    public_key: Buffer.from(config.publicKey).toString("base64"),
    key_id: config.keyId,
    api_base: config.apiBase,
    ...(config.redactParameters ? { redact_parameters: true } : {}),
  };
  await fs.writeFile(path.join(home, "ingest.json"), JSON.stringify(settings, null, 2) + "\n", "utf8");
  await fs.writeFile(path.join(home, HOST_MARKER_FILE), "1\n", "utf8");

  for (const target of targets) {
    options.log(`[install] ${target}: sealed hook at ${shimPaths[target]}`);
    await options.installTarget(target);
  }
  options.log(
    config.ingestToken
      ? "[install] an ingest token is in the environment; it is used from there and not written to disk"
      : "[install] no ingest token on this host: ingest must be reached through a proxy that attaches it",
  );
  return { ok: true };
}
