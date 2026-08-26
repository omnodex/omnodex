// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Stream connection link generation.
 *
 * Creates a claim token on the cloud API and builds a connection URL
 * that the user can open in a browser to link the stream to their
 * dashboard account. The passphrase is encrypted under a one-time
 * transfer key (AES-256-GCM) so the server never sees the plaintext.
 * The transfer key travels in the URL fragment (never sent to the server).
 */

import * as path from "node:path";
import * as os from "node:os";
import { webcrypto } from "node:crypto";
import { computeMachineId, readMachineLabel } from "@omnodex/sync-encryptor";

const subtle = webcrypto.subtle;

// ---------------------------------------------------------------------------
// Transfer encryption
// ---------------------------------------------------------------------------

/**
 * Encrypt the sync passphrase under a random one-time transfer key.
 *
 * The transfer key is a raw 256-bit AES-GCM key generated fresh for each
 * claim. It is encoded as hex and appended to the connection URL as a
 * fragment (#tk=<hex>), which browsers never send to the server.
 *
 * The dashboard extracts the transfer key from the fragment, decrypts the
 * passphrase client-side, then re-encrypts it under the user's
 * master_wrap_key for storage.
 */
export async function encryptForTransfer(passphrase: string): Promise<{
  /** Encrypted passphrase, base64-encoded. */
  passphrase_enc: string;
  /** AES-GCM IV, base64-encoded. */
  passphrase_iv: string;
  /** Transfer key, hex-encoded (goes in URL fragment, never to server). */
  transfer_key: string;
}> {
  // Generate a random 256-bit transfer key
  const keyBytes = new Uint8Array(32);
  webcrypto.getRandomValues(keyBytes);

  // Import as AES-GCM key
  const key = await subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  // Generate a random IV
  const iv = new Uint8Array(12);
  webcrypto.getRandomValues(iv);

  // Encrypt the passphrase
  const encoded = new TextEncoder().encode(passphrase);
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded,
  );

  // Encode outputs
  const transferKeyHex = Array.from(keyBytes, (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  return {
    passphrase_enc: bufferToBase64(new Uint8Array(ciphertext)),
    passphrase_iv: bufferToBase64(iv),
    transfer_key: transferKeyHex,
  };
}

function bufferToBase64(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64");
}

// ---------------------------------------------------------------------------
// Claim token creation
// ---------------------------------------------------------------------------

export interface CreateClaimOptions {
  /** API base URL (e.g., https://api.omnodex.com). */
  apiUrl: string;
  /** Bearer API token for authentication. */
  apiToken: string;
  /** Sync passphrase (plaintext, encrypted locally before sending). */
  passphrase: string;
  /** Human-readable machine label (e.g., "Brian's MacBook"). */
  machineLabel?: string;
  /** Platform identifier (e.g., "claude-code-hook", "codex-hook"). */
  platform?: string;
  /** Project directory name. */
  projectLabel?: string;
  /** Optional custom stream label for the dashboard. */
  streamLabel?: string;
}

export interface ClaimResult {
  /** The claim token (omx_claim_...). */
  claimToken: string;
  /** When the claim expires. */
  expiresAt: string;
  /** The full connection URL including the transfer key fragment. */
  connectUrl: string;
}

/**
 * Create a claim token on the cloud API and return the connection URL.
 *
 * 1. Encrypts the passphrase under a fresh transfer key
 * 2. POSTs the claim to /api/v1/connect/claim (encrypted passphrase only)
 * 3. Appends #tk=<transfer_key> to the returned connect URL
 *
 * The server stores only the ciphertext. The transfer key stays client-side,
 * carried in the URL fragment.
 */
export async function createClaim(
  opts: CreateClaimOptions,
): Promise<ClaimResult> {
  const { apiUrl, apiToken, passphrase } = opts;

  // Encrypt the passphrase for transfer
  const { passphrase_enc, passphrase_iv, transfer_key } =
    await encryptForTransfer(passphrase);

  // Gather machine metadata
  const machineId = computeMachineId();
  const omnodexHome =
    process.env.OMNODEX_HOME ??
    path.join(os.homedir(), ".omnodex");
  const machineLabel = opts.machineLabel ?? (await readMachineLabel(omnodexHome));

  const body = {
    machine_label: machineLabel,
    platform: opts.platform || null,
    project_label: opts.projectLabel || null,
    machine_id: machineId,
    passphrase_enc,
    passphrase_iv,
  };

  const res = await fetch(`${apiUrl}/api/v1/connect/claim`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const message =
      (err as any)?.message || `Claim creation failed (${res.status})`;
    throw new Error(message);
  }

  const result = (await res.json()) as {
    claim_token: string;
    expires_at: string;
    connect_url: string;
  };

  // Append the transfer key as a URL fragment
  const connectUrl = `${result.connect_url}#tk=${transfer_key}`;

  return {
    claimToken: result.claim_token,
    expiresAt: result.expires_at,
    connectUrl,
  };
}

// ---------------------------------------------------------------------------
// Convenience: detect platform from install target
// ---------------------------------------------------------------------------

const TARGET_PLATFORM_MAP: Record<string, string> = {
  "claude-code": "claude-code-hook",
  codex: "codex-hook",
  antigravity: "antigravity-hook",
  cowork: "cowork-plugin",
};

/**
 * Map an install target name to a platform identifier for the claim.
 */
export function platformFromTarget(target: string): string {
  return TARGET_PLATFORM_MAP[target] || target;
}
