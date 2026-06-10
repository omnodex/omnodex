// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- transport
 *
 * Pluggable transport for pushing encrypted sync blobs to the cloud.
 * The default HttpSyncTransport calls the Omnodex cloud API; tests and
 * offline mode can substitute a mock or file-backed implementation.
 */

export interface SyncPushRequest {
  /** Opaque customer identifier. */
  customer_id: string;
  /** AES-256-GCM ciphertext. */
  encrypted_payload: Uint8Array;
  /** GCM initialisation vector. */
  iv: Uint8Array;
  /** Argon2id KDF salt (not the key). */
  kdf_salt: Uint8Array;
  /** Original plaintext byte count (before encryption). */
  payload_bytes: number;
  /** Session IDs covered by this sync. */
  sessions_included: string[];
}

export interface SyncPushResponse {
  /** Server-generated receipt for audit trail. */
  blob_id: string;
  /** R2 object key (opaque to the client). */
  r2_key: string;
}

/** Transport interface for sync blob uploads. */
export interface SyncTransport {
  push(req: SyncPushRequest): Promise<SyncPushResponse>;
}

export interface HttpSyncTransportOptions {
  /** Base URL for the cloud API (e.g. "https://api.omnodex.com"). */
  baseUrl: string;
  /** API token for authentication. */
  apiToken: string;
  /** Request timeout in ms. Default: 30000. */
  timeoutMs?: number;
}

/**
 * HTTP transport that calls PUT /api/v1/sync/push on the Omnodex cloud API.
 */
export class HttpSyncTransport implements SyncTransport {
  private readonly baseUrl: string;
  private readonly apiToken: string;
  private readonly timeoutMs: number;

  constructor(options: HttpSyncTransportOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiToken = options.apiToken;
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  async push(req: SyncPushRequest): Promise<SyncPushResponse> {
    const url = this.baseUrl + "/api/v1/sync/push";
    const body = JSON.stringify({
      customer_id: req.customer_id,
      encrypted_payload: base64Encode(req.encrypted_payload),
      iv: base64Encode(req.iv),
      kdf_salt: base64Encode(req.kdf_salt),
      payload_bytes: req.payload_bytes,
      sessions_included: req.sessions_included,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(url, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + this.apiToken,
        },
        body,
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(
          "sync push failed: HTTP " + res.status + " " + text.slice(0, 200),
        );
      }

      const data = (await res.json()) as SyncPushResponse;
      return data;
    } finally {
      clearTimeout(timer);
    }
  }
}

function base64Encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
