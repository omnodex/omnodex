// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- streaming transport
 *
 * Encrypts individual trace events with a pre-derived streaming key
 * (AES-256-GCM, per-event random IV) and pushes them to the cloud API
 * in micro-batches. The cloud stores only opaque ciphertext -- zero
 * knowledge is maintained end-to-end.
 *
 * Usage:
 *   const key = await deriveStreamingKey(passphrase, customerId);
 *   const keyId = await computeKeyId(key);
 *   const transport = new StreamingTransport({ apiBase, apiToken, keyId, streamingKey: key });
 *   // in the tail loop:
 *   await transport.push(event);
 *   // on shutdown:
 *   await transport.flush();
 *   transport.stop();
 *
 * Design:
 *   - Buffers events and flushes every 100ms or when 50 events accumulate.
 *   - Fire-and-forget: a failed push logs a warning but never throws or
 *     blocks the local pipeline.
 *   - Each event is individually encrypted with a fresh 12-byte IV.
 *   - The IV is prepended to the ciphertext in the wire payload.
 */

import type { TraceEvent } from "@omnodex/shared";
import type { AesGcmKey } from "./crypto.js";
import { encrypt } from "./crypto.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StreamingTransportOptions {
  /** Cloud API base URL (e.g. "https://api.omnodex.com"). */
  apiBase: string;
  /** Customer API token for Bearer auth. */
  apiToken: string;
  /** Key identifier: first 8 hex chars of SHA256(streaming_key). */
  keyId: string;
  /** Pre-derived AES-256-GCM streaming key. */
  streamingKey: AesGcmKey;
  /** Flush interval in ms. Default: 100. */
  flushIntervalMs?: number;
  /** Max events per batch before forcing a flush. Default: 50. */
  maxBatchSize?: number;
  /** Request timeout in ms. Default: 10000. */
  timeoutMs?: number;
}

interface EncryptedEventWire {
  event_id: string;
  iv: string;    // base64
  ct: string;    // base64
  key_id: string;
  ts: number;    // unix ms
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

// ---------------------------------------------------------------------------
// StreamingTransport
// ---------------------------------------------------------------------------

export class StreamingTransport {
  private readonly apiBase: string;
  private readonly apiToken: string;
  private readonly keyId: string;
  private readonly streamingKey: AesGcmKey;
  private readonly flushIntervalMs: number;
  private readonly maxBatchSize: number;
  private readonly timeoutMs: number;

  private buffer: EncryptedEventWire[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private flushing = false;
  private stopped = false;

  constructor(opts: StreamingTransportOptions) {
    this.apiBase = opts.apiBase.replace(/\/$/, "");
    this.apiToken = opts.apiToken;
    this.keyId = opts.keyId;
    this.streamingKey = opts.streamingKey;
    this.flushIntervalMs = opts.flushIntervalMs ?? 100;
    this.maxBatchSize = opts.maxBatchSize ?? 50;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  /**
   * Encrypt and queue a trace event for cloud push.
   * Returns immediately -- never blocks the local pipeline.
   */
  async push(event: TraceEvent): Promise<void> {
    if (this.stopped) return;

    try {
      const plaintext = new TextEncoder().encode(JSON.stringify(event));
      const { ciphertext, iv } = await encrypt(this.streamingKey, plaintext);

      const wire: EncryptedEventWire = {
        event_id: event.event_id,
        iv: uint8ToBase64(iv),
        ct: uint8ToBase64(ciphertext),
        key_id: this.keyId,
        ts: Date.now(),
      };

      this.buffer.push(wire);

      // Flush immediately if buffer is full
      if (this.buffer.length >= this.maxBatchSize) {
        this.scheduleFlush(0);
      } else if (!this.flushTimer) {
        this.scheduleFlush(this.flushIntervalMs);
      }
    } catch (err) {
      console.warn("[stream] encrypt error (event dropped):", err);
    }
  }

  /**
   * Flush any buffered events immediately. Call before shutdown.
   */
  async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    await this.doFlush();
  }

  /**
   * Stop the transport. Flushes remaining events, then no further
   * pushes are accepted.
   */
  async stop(): Promise<void> {
    this.stopped = true;
    await this.flush();
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private scheduleFlush(delayMs: number): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.doFlush().catch((err) => {
        console.warn("[stream] flush error:", err);
      });
    }, delayMs);
  }

  private async doFlush(): Promise<void> {
    if (this.buffer.length === 0 || this.flushing) return;
    this.flushing = true;

    // Grab current buffer and reset
    const batch = this.buffer;
    this.buffer = [];

    try {
      const url = this.apiBase + "/api/v1/sync/events";
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + this.apiToken,
          },
          body: JSON.stringify({
            key_id: this.keyId,
            events: batch,
          }),
          signal: controller.signal,
        });

        if (!res.ok) {
          const text = await res.text().catch(() => "");
          console.warn(
            "[stream] push failed: HTTP " + res.status + " " + text.slice(0, 200),
          );
        }
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      // Fire-and-forget: log and continue. Events are lost on failure,
      // which is acceptable -- the blob sync is the durable record.
      console.warn("[stream] push error (batch of " + batch.length + " dropped):", err);
    } finally {
      this.flushing = false;
    }
  }
}
