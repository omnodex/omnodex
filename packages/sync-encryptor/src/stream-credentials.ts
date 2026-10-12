// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- stream credentials
 *
 * - Secret verifier. The cloud keeps a one-way verifier of each stream's
 *   secret (deriveStreamVerifier) and refuses a different one. A sync
 *   registers it the first time it runs with a token and secret pair, and
 *   stops if the cloud says this machine's secret is not the stream's:
 *   uploading would leave every linked dashboard unable to read the data.
 * - Token collection. After the owner rotates a stream's token, the cloud
 *   answers the old token with 401 token_rotated. A machine that holds the
 *   stream secret collects the new token once and keeps syncing; the old
 *   token alone is not enough.
 *
 * The last check is kept in stream-verifier.json, keyed by a hash of the
 * token and secret, so the Argon2id derivation runs once per pair, not per
 * sync.
 */

import { promises as fs } from "node:fs";
import { createHash } from "node:crypto";
import * as path from "node:path";
import { deriveStreamVerifier } from "./crypto.js";
import { computeMachineId } from "./machine-id.js";

export const STREAM_VERIFIER_FILE = "stream-verifier.json";

export const TOKEN_ROTATED_ERROR = "token_rotated";
export const SECRET_MISMATCH_ERROR = "secret_mismatch";

/** The owner rotated this machine's token; it can try to collect the new one. */
export class TokenRotatedError extends Error {
  constructor() {
    super("the stream's owner rotated this machine's token");
    this.name = "TokenRotatedError";
  }
}

/** This machine's stream secret is not the one the stream uses. */
export class SecretMismatchError extends Error {
  constructor() {
    super(
      "this machine's stream secret is not the one the stream uses, so uploads stopped. " +
        "Reveal the stream secret in the dashboard Settings and run: omnodex connect --secret <stream secret>",
    );
    this.name = "SecretMismatchError";
  }
}

/** A collection the cloud refused, with what to do instead. */
export class TokenCollectionError extends Error {
  constructor(readonly code: string, detail: string) {
    super(
      `the stream's owner rotated this machine's token and it could not collect the new one (${detail}). ` +
        "Copy the new token from the dashboard Settings and run: omnodex connect --token <new token>",
    );
    this.name = "TokenCollectionError";
  }
}

function errorCode(body: string): string | null {
  try {
    const code = (JSON.parse(body) as { error?: unknown }).error;
    return typeof code === "string" ? code : null;
  } catch {
    return null;
  }
}

/** True for the 401 the cloud sends an old token while it can still be swapped. */
export function isTokenRotated(status: number, body: string): boolean {
  return status === 401 && errorCode(body) === TOKEN_ROTATED_ERROR;
}

export interface VerifierState {
  /** sha256 of token and secret: the pair this result is for. */
  key: string;
  status: "registered" | "matched" | "mismatch" | "unsupported";
  checked_at: string;
}

function pairKey(apiToken: string, secret: string): string {
  return createHash("sha256").update(apiToken).update("\0").update(secret).digest("hex");
}

export async function readVerifierState(home: string): Promise<VerifierState | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(home, STREAM_VERIFIER_FILE), "utf8")) as VerifierState;
    return parsed && typeof parsed.key === "string" ? parsed : null;
  } catch {
    return null;
  }
}

async function writeVerifierState(home: string, state: VerifierState): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  await fs.writeFile(path.join(home, STREAM_VERIFIER_FILE), JSON.stringify(state, null, 2) + "\n");
}

/** True when the last check for this token and secret found the secret wrong. */
export async function knownSecretMismatch(home: string, apiToken: string, secret: string): Promise<boolean> {
  const state = await readVerifierState(home);
  return state?.key === pairKey(apiToken, secret) && state.status === "mismatch";
}

export interface CredentialOptions {
  home: string;
  apiUrl: string;
  apiToken: string;
  /** The stream secret. */
  passphrase: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Register this stream's secret verifier, or check it against the one the
 * cloud has. Runs once per token and secret pair. Throws SecretMismatchError
 * when the secret is wrong (now or at the last check); a network failure
 * returns "skipped" and the next sync tries again.
 */
export async function ensureSecretVerifier(
  opts: CredentialOptions,
): Promise<VerifierState["status"] | "skipped"> {
  const key = pairKey(opts.apiToken, opts.passphrase);
  const prior = await readVerifierState(opts.home);
  if (prior?.key === key) {
    if (prior.status === "mismatch") throw new SecretMismatchError();
    return prior.status;
  }

  const verifier = await deriveStreamVerifier(opts.passphrase);
  let res: Response;
  try {
    res = await (opts.fetchFn ?? fetch)(opts.apiUrl.replace(/\/$/, "") + "/api/v1/stream/verifier", {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + opts.apiToken },
      body: JSON.stringify({ secret_verifier: verifier }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
  } catch {
    return "skipped";
  }
  const text = await res.text().catch(() => "");
  let status: VerifierState["status"];
  if (res.ok) {
    status = (JSON.parse(text || "{}") as { status?: string }).status === "registered" ? "registered" : "matched";
  } else if (res.status === 409 && errorCode(text) === SECRET_MISMATCH_ERROR) {
    status = "mismatch";
  } else if (res.status === 404) {
    // An older cloud without the route.
    status = "unsupported";
  } else {
    // A rejected token or a server error: the sync itself reports those.
    return "skipped";
  }
  await writeVerifierState(opts.home, { key, status, checked_at: new Date().toISOString() });
  if (status === "mismatch") throw new SecretMismatchError();
  return status;
}

/**
 * Collect the new token after the owner rotated this stream's token, by
 * proving this machine holds the stream secret, and save it to
 * stream-config.json. Returns the new token.
 */
export async function collectRotatedToken(opts: CredentialOptions): Promise<string> {
  const verifier = await deriveStreamVerifier(opts.passphrase);
  let res: Response;
  try {
    res = await (opts.fetchFn ?? fetch)(opts.apiUrl.replace(/\/$/, "") + "/api/v1/stream/collect-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ old_token: opts.apiToken, machine_id: computeMachineId(), secret_verifier: verifier }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
  } catch (err) {
    throw new TokenCollectionError("network", (err as Error).message);
  }
  const text = await res.text().catch(() => "");
  if (!res.ok) {
    const code = errorCode(text) ?? `http_${res.status}`;
    const detail: Record<string, string> = {
      secret_mismatch: "this machine's stream secret is not the stream's",
      already_collected: "this machine already collected it once",
      not_collectable: "the window to collect it has closed",
      verifier_unregistered: "no machine has proved the stream secret yet",
    };
    throw new TokenCollectionError(code, detail[code] ?? `HTTP ${res.status}`);
  }
  const { api_token: newToken } = JSON.parse(text) as { api_token: string };
  await saveApiToken(opts.home, newToken);
  return newToken;
}

/** Replace api_token in stream-config.json, keeping every other setting. */
async function saveApiToken(home: string, apiToken: string): Promise<void> {
  const file = path.join(home, "stream-config.json");
  let config: Record<string, unknown> = {};
  try {
    config = JSON.parse(await fs.readFile(file, "utf8")) as Record<string, unknown>;
  } catch {
    // Unreadable or missing: write the token on its own.
  }
  config.api_token = apiToken;
  config.last_used_at = new Date().toISOString();
  await fs.writeFile(file, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
}

/**
 * What the cloud says about a token: "valid"; "rotated" (the owner rotated
 * it and the new one can still be collected); "rejected" (revoked, or
 * unknown); "unknown" when the cloud cannot be reached or errs.
 */
export async function probeStreamToken(
  opts: { apiUrl: string; apiToken: string; fetchFn?: typeof fetch; timeoutMs?: number },
): Promise<"valid" | "rotated" | "rejected" | "unknown"> {
  try {
    const res = await (opts.fetchFn ?? fetch)(opts.apiUrl.replace(/\/$/, "") + "/api/v1/license/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + opts.apiToken },
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
    if (res.ok) return "valid";
    if (res.status !== 401) return "unknown";
    return isTokenRotated(res.status, await res.text().catch(() => "")) ? "rotated" : "rejected";
  } catch {
    return "unknown";
  }
}

/**
 * Whether the stream behind this token already has a registered secret
 * verifier. "unknown" when the cloud cannot say (unreachable, older cloud,
 * rejected token).
 */
export async function streamHasSecret(
  opts: { apiUrl: string; apiToken: string; fetchFn?: typeof fetch; timeoutMs?: number },
): Promise<boolean | "unknown"> {
  try {
    const res = await (opts.fetchFn ?? fetch)(opts.apiUrl.replace(/\/$/, "") + "/api/v1/stream/verifier", {
      method: "GET",
      headers: { Authorization: "Bearer " + opts.apiToken },
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
    if (!res.ok) return "unknown";
    const body = (await res.json()) as { registered?: unknown };
    return typeof body.registered === "boolean" ? body.registered : "unknown";
  } catch {
    return "unknown";
  }
}
