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
 *
 * Wire format: the blob is uploaded as a single `application/octet-stream`
 * body -- a v1 self-describing envelope (magic | version | salt | iv |
 * ciphertext, see envelope.ts). The salt and IV travel inside the blob so
 * the cloud stores opaque bytes and the browser dashboard can decrypt from
 * the pulled blob alone. Session IDs ride in the X-Omnodex-Sessions header.
 */

import { encodeEnvelope } from "./envelope.js";

/** The largest sync blob the cloud accepts, in bytes; a bigger push gets HTTP 413. */
export const SYNC_BLOB_MAX_BYTES = 50 * 1024 * 1024;

/** Thrown by a push the cloud refused for size (HTTP 413). */
export class SyncBlobTooLargeError extends Error {
  readonly bytes: number;
  readonly maxBytes: number;

  constructor(bytes: number, maxBytes = SYNC_BLOB_MAX_BYTES) {
    super(
      `sync push refused: the blob is ${(bytes / 1048576).toFixed(1)} MB, over the ` +
        `${Math.round(maxBytes / 1048576)} MB limit`,
    );
    this.name = "SyncBlobTooLargeError";
    this.bytes = bytes;
    this.maxBytes = maxBytes;
  }
}

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
  /** Stable machine identifier (SHA-256 prefix of hostname). */
  machine_id: string;
  /** Optional human-readable machine label. */
  machine_label?: string;
  /** Envelope version for the upload: 2 when encrypted_payload is gzipped JSON. Default 1. */
  envelope_version?: number;
}

export interface SyncPushResponse {
  /** Server-generated receipt for audit trail. */
  blob_id: string;
  /** R2 object key (opaque to the client). */
  r2_key: string;
  /** Bytes uploaded (the whole envelope), which is what the cloud's size limit applies to. */
  bytes?: number;
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

    // Pack salt + IV + ciphertext into a self-describing v1 envelope.
    // customer_id is derived server-side from the bearer token; payload_bytes
    // is recomputed server-side from the stored body.
    const envelope = encodeEnvelope(req.kdf_salt, req.iv, req.encrypted_payload, req.envelope_version);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(url, {
        method: "PUT",
        headers: {
          "Content-Type": "application/octet-stream",
          "Authorization": "Bearer " + this.apiToken,
          "X-Omnodex-Sessions": JSON.stringify(req.sessions_included),
          "X-Omnodex-Machine-Id": req.machine_id,
          ...(req.machine_label ? { "X-Omnodex-Machine-Label": req.machine_label } : {}),
        },
        // BodyInit typings don't accept a Uint8Array view; encodeEnvelope
        // returns a fresh full-size buffer, so its ArrayBuffer is exactly
        // the envelope bytes.
        body: envelope.buffer as ArrayBuffer,
        signal: controller.signal,
      });

      if (res.status === 413) {
        throw new SyncBlobTooLargeError(envelope.byteLength);
      }
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(
          "sync push failed: HTTP " + res.status + " " + text.slice(0, 200),
        );
      }

      const data = (await res.json()) as SyncPushResponse;
      return { ...data, bytes: envelope.byteLength };
    } finally {
      clearTimeout(timer);
    }
  }
}
