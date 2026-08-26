// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- connect-tool
 *
 * Built-in MCP tool that generates a dashboard connection link from within
 * the proxy process. This runs on the user's machine with direct access to
 * ~/.omnodex/stream-config.json, so the Cowork plugin skill can trigger
 * connection without requiring the CLI binary on PATH.
 *
 * The tool:
 *   1. Reads credentials from stream-config.json / env vars
 *   2. Auto-generates a passphrase if none exists
 *   3. Encrypts the passphrase under a one-time transfer key (AES-256-GCM)
 *   4. Creates a claim token via the cloud API
 *   5. Returns the connection URL with the transfer key in the fragment
 */

import { webcrypto, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { computeMachineId, readMachineLabel } from "@omnodex/sync-encryptor";

const subtle = webcrypto.subtle;

// ---------------------------------------------------------------------------
// Stream config (minimal subset of CLI's stream-config.ts)
// ---------------------------------------------------------------------------

interface StreamConfig {
  api_token: string;
  passphrase: string;
  api_url?: string;
}

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function generatePassphrase(): string {
  const bytes = randomBytes(32);
  let result = "";
  for (const b of bytes) {
    result += BASE62[b % BASE62.length];
  }
  return result;
}

function resolveOmnodexHome(): string {
  return process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
}

async function readStreamConfig(home: string): Promise<StreamConfig | null> {
  try {
    const raw = await fs.readFile(path.join(home, "stream-config.json"), "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed.api_token || !parsed.passphrase) return null;
    return parsed as StreamConfig;
  } catch {
    return null;
  }
}

async function writeStreamConfig(home: string, config: StreamConfig): Promise<void> {
  const filePath = path.join(home, "stream-config.json");
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Transfer encryption (same as CLI's connect.ts)
// ---------------------------------------------------------------------------

function bufferToBase64(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64");
}

async function encryptForTransfer(passphrase: string): Promise<{
  passphrase_enc: string;
  passphrase_iv: string;
  transfer_key: string;
}> {
  const keyBytes = new Uint8Array(32);
  webcrypto.getRandomValues(keyBytes);

  const key = await subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = new Uint8Array(12);
  webcrypto.getRandomValues(iv);

  const encoded = new TextEncoder().encode(passphrase);
  const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  const transferKeyHex = Array.from(keyBytes, (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  return {
    passphrase_enc: bufferToBase64(new Uint8Array(ciphertext)),
    passphrase_iv: bufferToBase64(iv),
    transfer_key: transferKeyHex,
  };
}

// ---------------------------------------------------------------------------
// Claim creation
// ---------------------------------------------------------------------------

interface ConnectResult {
  status: "ok" | "device_code" | "no_credentials" | "error";
  connect_url?: string;
  expires_at?: string;
  user_code?: string;
  message: string;
}

export async function handleConnect(params: {
  platform?: string;
  project_label?: string;
}): Promise<ConnectResult> {
  const home = resolveOmnodexHome();

  // Resolve credentials: env > stream-config.json
  let apiToken = process.env.OMNODEX_API_TOKEN ?? "";
  let passphrase = process.env.OMNODEX_SYNC_PASSPHRASE ?? "";
  let apiUrl = process.env.OMNODEX_API_URL ?? "";

  const config = await readStreamConfig(home);
  if (!apiToken && config?.api_token) apiToken = config.api_token;
  if (!passphrase && config?.passphrase) passphrase = config.passphrase;
  if (!apiUrl) apiUrl = config?.api_url ?? "https://api.omnodex.com";

  if (!apiToken) {
    // No token: initiate device code flow
    return initiateDeviceCodeFlow(home, passphrase, apiUrl);
  }

  // Auto-generate passphrase if missing
  if (!passphrase) {
    passphrase = generatePassphrase();
    await writeStreamConfig(home, {
      api_token: apiToken,
      passphrase,
      api_url: apiUrl,
    });
  }

  try {
    const { passphrase_enc, passphrase_iv, transfer_key } =
      await encryptForTransfer(passphrase);

    const machineId = computeMachineId();
    const machineLabel = await readMachineLabel(home);

    const body = {
      machine_label: machineLabel,
      platform: params.platform ?? "cowork-plugin",
      project_label: params.project_label ?? null,
      machine_id: machineId,
      passphrase_enc,
      passphrase_iv,
    };

    const res = await fetch(apiUrl + "/api/v1/connect/claim", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + apiToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = (err as Record<string, unknown>)?.message ?? "Claim creation failed (" + res.status + ")";
      return { status: "error", message: String(msg) };
    }

    const result = (await res.json()) as {
      claim_token: string;
      expires_at: string;
      connect_url: string;
    };

    const connectUrl = result.connect_url + "#tk=" + transfer_key;

    return {
      status: "ok",
      connect_url: connectUrl,
      expires_at: result.expires_at,
      message: "Connection link generated. The user should open this URL in their browser.",
    };
  } catch (err) {
    return {
      status: "error",
      message: "Failed to create connection link: " + (err as Error).message,
    };
  }
}

// ---------------------------------------------------------------------------
// Device code flow (fallback when no API token exists)
// ---------------------------------------------------------------------------

/** In-flight device code polling state, keyed by device_code. */
export const activePolls = new Map<string, { cancel: () => void }>();

async function initiateDeviceCodeFlow(
  home: string,
  existingPassphrase: string,
  apiUrl: string,
): Promise<ConnectResult> {
  // Auto-generate passphrase if missing
  let passphrase = existingPassphrase;
  if (!passphrase) {
    passphrase = generatePassphrase();
    await writeStreamConfig(home, {
      api_token: "",
      passphrase,
      api_url: apiUrl,
    });
  }

  try {
    const { passphrase_enc, passphrase_iv, transfer_key } =
      await encryptForTransfer(passphrase);

    const machineId = computeMachineId();
    const machineLabel = await readMachineLabel(home);

    const body = {
      machine_label: machineLabel,
      machine_id: machineId,
      passphrase_enc,
      passphrase_iv,
    };

    const res = await fetch(apiUrl + "/api/v1/device/code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = (err as Record<string, unknown>)?.message ?? "Device code request failed (" + res.status + ")";
      return { status: "error", message: String(msg) };
    }

    const result = (await res.json()) as {
      device_code: string;
      user_code: string;
      verification_url: string;
      expires_in: number;
      interval: number;
    };

    const connectUrl = result.verification_url + "#tk=" + transfer_key;

    // Start background polling for authorization
    startBackgroundPoll(
      home,
      apiUrl,
      result.device_code,
      passphrase,
      result.interval,
      result.expires_in,
    );

    return {
      status: "device_code",
      connect_url: connectUrl,
      user_code: result.user_code,
      expires_at: new Date(Date.now() + result.expires_in * 1000).toISOString(),
      message:
        "Device code flow started. The user should open the URL and enter the code " +
        "to authorize this machine. The proxy will automatically pick up the token " +
        "once authorized.",
    };
  } catch (err) {
    return {
      status: "error",
      message: "Failed to start device code flow: " + (err as Error).message,
    };
  }
}

function startBackgroundPoll(
  home: string,
  apiUrl: string,
  deviceCode: string,
  passphrase: string,
  interval: number,
  expiresIn: number,
): void {
  // Cancel any existing poll for this device code
  activePolls.get(deviceCode)?.cancel();

  let cancelled = false;
  const cancel = () => { cancelled = true; };
  activePolls.set(deviceCode, { cancel });

  const deadline = Date.now() + expiresIn * 1000;
  let pollInterval = interval;

  (async () => {
    while (!cancelled && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, pollInterval * 1000));
      if (cancelled) break;

      try {
        const res = await fetch(apiUrl + "/api/v1/device/token", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            device_code: deviceCode,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          }),
        });

        if (res.status === 200) {
          const data = (await res.json()) as {
            api_token: string;
            customer_id: string;
            api_url?: string;
          };

          // Store the token in stream-config.json
          await writeStreamConfig(home, {
            api_token: data.api_token,
            passphrase,
            api_url: data.api_url ?? apiUrl,
          });

          activePolls.delete(deviceCode);
          return; // Success!
        }

        const body = await res.json().catch(() => ({ error: "unknown" }));
        const error = (body as Record<string, unknown>)?.error;

        if (error === "slow_down") {
          pollInterval = ((body as Record<string, unknown>)?.interval as number) ?? pollInterval + 5;
        } else if (error !== "authorization_pending") {
          // expired_token, access_denied, or unexpected error -- stop polling
          break;
        }
      } catch {
        // Network error -- keep trying until deadline
      }
    }

    activePolls.delete(deviceCode);
  })();
}

// ---------------------------------------------------------------------------
// Connection status check
// ---------------------------------------------------------------------------

export interface ConnectionStatus {
  has_api_token: boolean;
  has_passphrase: boolean;
  api_url: string;
  token_source: "env" | "config" | "none";
}

export async function checkConnectionStatus(): Promise<ConnectionStatus> {
  const home = resolveOmnodexHome();
  const config = await readStreamConfig(home);

  const envToken = process.env.OMNODEX_API_TOKEN ?? "";
  const envPassphrase = process.env.OMNODEX_SYNC_PASSPHRASE ?? "";

  const hasToken = !!(envToken || config?.api_token);
  const hasPassphrase = !!(envPassphrase || config?.passphrase);
  const tokenSource: "env" | "config" | "none" = envToken
    ? "env"
    : config?.api_token
      ? "config"
      : "none";

  return {
    has_api_token: hasToken,
    has_passphrase: hasPassphrase,
    api_url: process.env.OMNODEX_API_URL ?? config?.api_url ?? "https://api.omnodex.com",
    token_source: tokenSource,
  };
}
