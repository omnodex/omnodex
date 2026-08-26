// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RFC 8628 device code authorization flow.
 *
 * When no API token exists, the CLI requests a device code from the cloud
 * API, displays a user code and verification URL, then polls until the
 * user authorizes the device on the dashboard. The passphrase is encrypted
 * under a one-time transfer key (AES-256-GCM) so the server never sees
 * the plaintext. The transfer key travels in the URL fragment.
 */

import { computeMachineId, readMachineLabel } from "@omnodex/sync-encryptor";
import { encryptForTransfer } from "./connect.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DeviceCodeRequest {
  /** API base URL (e.g., https://api.omnodex.com). */
  apiUrl: string;
  /** Sync passphrase (plaintext, encrypted locally before sending). */
  passphrase: string;
  /** Human-readable machine label (e.g., "Brian's MacBook"). */
  machineLabel?: string;
}

export interface DeviceCodeResponse {
  /** Opaque device code for polling (never shown to the user). */
  deviceCode: string;
  /** Short human-readable code the user enters on the dashboard. */
  userCode: string;
  /** Base verification URL (CLI appends #tk=<transfer_key>). */
  verificationUrl: string;
  /** Seconds until the device code expires. */
  expiresIn: number;
  /** Minimum polling interval in seconds. */
  interval: number;
  /** Full URL with transfer key fragment for the user to open. */
  connectUrl: string;
}

export interface DeviceTokenResult {
  /** The API token to store in stream-config.json. */
  apiToken: string;
  /** The customer ID on the cloud platform. */
  customerId: string;
  /** The API URL to use. */
  apiUrl: string;
}

// ---------------------------------------------------------------------------
// Device code request
// ---------------------------------------------------------------------------

/**
 * Request a device code from the cloud API.
 *
 * Generates a passphrase, encrypts it under a one-time transfer key,
 * and sends it with machine metadata. The transfer key is appended to
 * the verification URL as a fragment (#tk=<hex>).
 */
export async function requestDeviceCode(
  opts: DeviceCodeRequest,
): Promise<DeviceCodeResponse> {
  const { apiUrl, passphrase } = opts;

  // Encrypt the passphrase for transfer
  const { passphrase_enc, passphrase_iv, transfer_key } =
    await encryptForTransfer(passphrase);

  // Gather machine metadata
  const machineId = computeMachineId();
  const omnodexHome =
    process.env.OMNODEX_HOME ??
    require("node:path").join(require("node:os").homedir(), ".omnodex");
  const machineLabel =
    opts.machineLabel ?? (await readMachineLabel(omnodexHome));

  const body = {
    machine_label: machineLabel,
    machine_id: machineId,
    passphrase_enc,
    passphrase_iv,
  };

  const res = await fetch(`${apiUrl}/api/v1/device/code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const message =
      (err as any)?.message || `Device code request failed (${res.status})`;
    throw new Error(message);
  }

  const result = (await res.json()) as {
    device_code: string;
    user_code: string;
    verification_url: string;
    expires_in: number;
    interval: number;
  };

  // Append the transfer key as a URL fragment
  const connectUrl = `${result.verification_url}#tk=${transfer_key}`;

  return {
    deviceCode: result.device_code,
    userCode: result.user_code,
    verificationUrl: result.verification_url,
    expiresIn: result.expires_in,
    interval: result.interval,
    connectUrl,
  };
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/**
 * Poll the device/token endpoint until the user authorizes (or the code
 * expires). Follows RFC 8628 Section 3.5 error shapes.
 *
 * Returns the API token and customer ID on success.
 * Throws on expiry, denial, or unexpected errors.
 */
export async function pollForAuthorization(
  apiUrl: string,
  deviceCode: string,
  opts: {
    /** Initial polling interval in seconds. */
    interval: number;
    /** Total expiry time in seconds. */
    expiresIn: number;
    /** Optional callback invoked each poll cycle (for progress indication). */
    onPoll?: () => void;
  },
): Promise<DeviceTokenResult> {
  let interval = opts.interval;
  const deadline = Date.now() + opts.expiresIn * 1000;

  while (Date.now() < deadline) {
    // Wait for the polling interval
    await sleep(interval * 1000);

    opts.onPoll?.();

    const res = await fetch(`${apiUrl}/api/v1/device/token`, {
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
      return {
        apiToken: data.api_token,
        customerId: data.customer_id,
        apiUrl: data.api_url ?? apiUrl,
      };
    }

    // RFC 8628 error shapes (all returned as 400)
    const body = await res.json().catch(() => ({ error: "unknown" }));
    const error = (body as any)?.error;

    switch (error) {
      case "authorization_pending":
        // Keep polling at the current interval
        continue;
      case "slow_down":
        // Back off: increase interval (server may suggest a new one)
        interval = (body as any)?.interval ?? interval + 5;
        continue;
      case "expired_token":
        throw new Error("Device code expired. Please run `omnodex connect` again.");
      case "access_denied":
        throw new Error("Authorization was denied.");
      default:
        throw new Error(
          `Unexpected error during device authorization: ${error ?? res.status}`,
        );
    }
  }

  throw new Error("Device code expired. Please run `omnodex connect` again.");
}

// ---------------------------------------------------------------------------
// Full flow
// ---------------------------------------------------------------------------

export interface DeviceAuthFlowOptions {
  /** API base URL (defaults to https://api.omnodex.com). */
  apiUrl?: string;
  /** Sync passphrase (plaintext). */
  passphrase: string;
  /** Human-readable machine label. */
  machineLabel?: string;
}

/**
 * Run the full device code authorization flow:
 *
 * 1. Request a device code (with encrypted passphrase)
 * 2. Display the URL and user code to the terminal
 * 3. Poll until the user authorizes on the dashboard
 * 4. Return the API token and customer ID
 */
export async function runDeviceAuthFlow(
  opts: DeviceAuthFlowOptions,
): Promise<DeviceTokenResult> {
  const apiUrl = opts.apiUrl ?? "https://api.omnodex.com";

  // Step 1: Request device code
  const deviceCode = await requestDeviceCode({
    apiUrl,
    passphrase: opts.passphrase,
    machineLabel: opts.machineLabel,
  });

  // Step 2: Display instructions
  console.log("");
  console.log("  1. Open this URL in your browser:");
  console.log(`     ${deviceCode.connectUrl}`);
  console.log("");
  console.log("  2. Enter this code when prompted:");
  console.log(`     ${deviceCode.userCode}`);
  console.log("");
  const expiryMin = Math.round(deviceCode.expiresIn / 60);
  process.stdout.write(
    `  Waiting for authorization... (expires in ${expiryMin} minutes)\r`,
  );

  // Step 3: Poll for authorization
  let dots = 0;
  const result = await pollForAuthorization(apiUrl, deviceCode.deviceCode, {
    interval: deviceCode.interval,
    expiresIn: deviceCode.expiresIn,
    onPoll: () => {
      dots = (dots + 1) % 4;
      const spinner = ".".repeat(dots).padEnd(3);
      process.stdout.write(
        `\r  Waiting for authorization${spinner}`,
      );
    },
  });

  // Step 4: Success
  process.stdout.write("\r" + " ".repeat(60) + "\r");
  console.log("  Connected! API token stored in ~/.omnodex/stream-config.json");
  console.log("  Your stream is now live. Events will appear in your dashboard.");
  console.log("");

  return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
