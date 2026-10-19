// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The guardrails module: what turns a call's verdicts into the decision an
 * agent host acts on.
 *
 * Guardrails are a paid feature. This repository holds the verdicts (which
 * shadow mode also uses) and the interface below; the code that decides is
 * delivered to entitled installs as a signed, sealed module, the same way
 * advanced rules are (see bundle.ts):
 *
 *   manifest    kind "guardrails-module", version, interface version,
 *               channel, validity, and the SHA-256 of the sealed payload
 *   signature   Ed25519 over the canonical manifest, checked against the
 *               publishing keys compiled into this client
 *   payload     an ES module, sealed with AES-256-GCM under a content key
 *               the license check hands only to entitled accounts
 *
 * The module is opened in memory and imported from there; its source is
 * never written to disk unsealed. Without a module that opens (no
 * subscription, none fetched yet, expired, an interface this client does not
 * speak), guardrails stop nothing and calls are recorded as in shadow mode.
 * Nothing here throws at a caller.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { GUARDRAILS_INTERFACE, type BlockingVerdict } from "@omnodex/shared";
import { TRUSTED_PUBLISHING_KEYS } from "../bundle.js";
import { openSigned, type OpenFailure } from "../sealed.js";
import type { Verdict } from "./resolve-verdict.js";

export { GUARDRAILS_INTERFACE };

export const GUARDRAILS_DIR = "guardrails";
export const CURRENT_MODULE_FILE = "current.module.json";

/** Base64 content key, for a module sealed locally. Development only. */
export const GUARDRAILS_KEY_ENV = "OMNODEX_GUARDRAILS_KEY";
/** Base64 SPKI public key, for a module signed with a local key. Development only. */
export const GUARDRAILS_PUBLIC_KEY_ENV = "OMNODEX_GUARDRAILS_PUBLIC_KEY";

/** The agent hosts a decision can be written for. */
export type EnforcementHost = "claude-code" | "codex" | "antigravity" | "mcp-proxy";

export interface GuardrailsInput {
  host: EnforcementHost;
  /** One per finding on the call, resolved from the user's settings. */
  verdicts: readonly Verdict[];
  /** Set when the rules could not judge the call. */
  failure?: "timeout" | "error";
  /** What to do with a call that could not be judged. */
  onError: "allow" | "block";
}

export interface GuardrailsDecision {
  /** What happens to the call. */
  action: BlockingVerdict;
  /** Rule ids of the findings that stopped or held it. */
  held: string[];
  /**
   * The host's answer: a hook's stdout payload, or for the MCP proxy
   * `{ reason }`. Null when the call runs untouched.
   */
  output: Record<string, unknown> | null;
}

/** What a guardrails module exports. */
export interface GuardrailsModule {
  GUARDRAILS_INTERFACE: number;
  decide(input: GuardrailsInput): GuardrailsDecision;
}

export interface ModuleManifest {
  kind: "guardrails-module";
  module_version: string;
  interface: number;
  channel: string;
  created_at: string;
  not_after: string;
  payload_sha256: string;
}

export interface SealedModule {
  manifest: ModuleManifest;
  signature: string;
  payload: string;
}

export type ModuleSkipReason =
  | "none_cached"
  | "unreadable"
  | "interface_mismatch"
  | "malformed_module"
  | OpenFailure;

export type GuardrailsLoad =
  | { module: GuardrailsModule; manifest: ModuleManifest; skipped?: undefined }
  | { module?: undefined; manifest?: ModuleManifest; skipped: ModuleSkipReason };

/** The bytes the signature covers. Starts with its kind, so no other artifact's signature fits. */
export function canonicalModuleManifest(m: ModuleManifest): Buffer {
  const ordered = {
    kind: "guardrails-module",
    module_version: m.module_version,
    interface: m.interface,
    channel: m.channel,
    created_at: m.created_at,
    not_after: m.not_after,
    payload_sha256: m.payload_sha256,
  };
  return Buffer.from(JSON.stringify(ordered), "utf8");
}

export function modulePath(home: string): string {
  return path.join(home, GUARDRAILS_DIR, CURRENT_MODULE_FILE);
}

/**
 * The key the license check gave this home for exactly this module version,
 * from license-cache.json.
 */
export function licensedModuleKey(home: string, manifest: ModuleManifest): Buffer | null {
  try {
    const cache = JSON.parse(fs.readFileSync(path.join(home, "license-cache.json"), "utf8")) as {
      response?: { guardrails_module?: { module_version?: unknown; content_key?: unknown } };
    };
    const grant = cache.response?.guardrails_module;
    if (!grant || grant.module_version !== manifest.module_version || typeof grant.content_key !== "string") return null;
    return Buffer.from(grant.content_key, "base64");
  } catch {
    return null;
  }
}

/** Opened modules by payload hash, so a long-lived process imports each version once. */
const opened = new Map<string, GuardrailsModule>();

export interface LoadModuleOptions {
  /** Read this file instead of the home's cached module. */
  file?: string;
  /** Raw content key. Defaults to OMNODEX_GUARDRAILS_KEY, then the license grant. */
  key?: Buffer | null;
  env?: NodeJS.ProcessEnv;
  at?: Date;
}

/** The guardrails module this installation may run, or why it has none. */
export async function loadGuardrailsModule(
  home: string = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex"),
  opts: LoadModuleOptions = {},
): Promise<GuardrailsLoad> {
  const env = opts.env ?? process.env;
  let sealed: SealedModule;
  try {
    sealed = JSON.parse(fs.readFileSync(opts.file ?? modulePath(home), "utf8")) as SealedModule;
  } catch (err) {
    return { skipped: (err as NodeJS.ErrnoException).code === "ENOENT" ? "none_cached" : "unreadable" };
  }
  const m = sealed?.manifest;
  if (!m || m.kind !== "guardrails-module" || typeof sealed.signature !== "string" || typeof sealed.payload !== "string") {
    return { skipped: "unreadable" };
  }

  const cached = opened.get(m.payload_sha256);
  const devKey = env[GUARDRAILS_KEY_ENV] ? Buffer.from(env[GUARDRAILS_KEY_ENV]!, "base64") : null;
  const result = openSigned({
    signed: canonicalModuleManifest(m),
    signature: sealed.signature,
    notAfter: m.not_after,
    payload: sealed.payload,
    payloadSha256: m.payload_sha256,
    key: opts.key ?? devKey ?? licensedModuleKey(home, m),
    trustedKeys: env[GUARDRAILS_PUBLIC_KEY_ENV]
      ? [env[GUARDRAILS_PUBLIC_KEY_ENV]!, ...TRUSTED_PUBLISHING_KEYS]
      : TRUSTED_PUBLISHING_KEYS,
    at: opts.at,
  });
  if (!result.ok) return { manifest: m, skipped: result.reason };
  if (m.interface !== GUARDRAILS_INTERFACE) return { manifest: m, skipped: "interface_mismatch" };
  if (cached) return { module: cached, manifest: m };

  try {
    const source = result.plaintext.toString("base64");
    const mod = (await import(`data:text/javascript;base64,${source}`)) as Partial<GuardrailsModule>;
    if (mod.GUARDRAILS_INTERFACE !== GUARDRAILS_INTERFACE || typeof mod.decide !== "function") {
      return { manifest: m, skipped: "malformed_module" };
    }
    const module = mod as GuardrailsModule;
    opened.set(m.payload_sha256, module);
    return { module, manifest: m };
  } catch {
    return { manifest: m, skipped: "malformed_module" };
  }
}

/** One line for `omnodex status` and `omnodex enforce status`. */
export function describeGuardrails(load: GuardrailsLoad): string {
  if (!load.skipped) return `guardrails module ${load.manifest.module_version} (valid until ${load.manifest.not_after})`;
  const why: Record<ModuleSkipReason, string> = {
    none_cached: "no guardrails module installed (Pro)",
    unreadable: "the installed guardrails module could not be read",
    interface_mismatch: "the installed guardrails module is for another version of Omnodex; update Omnodex",
    malformed_module: "the installed guardrails module did not load",
    untrusted_signature: "the installed guardrails module is not signed by a key this client trusts",
    expired: "the installed guardrails module has expired",
    payload_mismatch: "the installed guardrails module failed its integrity check",
    no_key: "guardrails module installed, but no key to open it (Pro subscription needed)",
    undecryptable: "the installed guardrails module did not open with the key held",
  };
  return why[load.skipped];
}
