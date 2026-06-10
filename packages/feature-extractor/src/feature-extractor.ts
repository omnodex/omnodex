// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/feature-extractor -- orchestrator
 *
 * Coordinates the full feature extraction pipeline:
 *   1. Read session data from the SQLite read model
 *   2. Produce anonymized FeatureBatch (counts, timing, risk, HMAC hashes)
 *   3. Submit to the cloud via the transport
 *   4. Emit a feature.extracted audit event to the local event log
 *
 * The raw tool names, MCP server names, file paths, credentials, and
 * conversation content never leave the machine. Only statistical
 * aggregates and HMAC-hashed identifiers cross the wire.
 */

import { extractSessionFeatures } from "./extractor.js";
import { generateLocalSalt } from "./hasher.js";
import type { FeatureTransport } from "./transport.js";
import type { ReadModelStore } from "@omnodex/projection";
import type { EventLog } from "@omnodex/event-log";
import type {
  FeatureBatch,
  FeatureExtractedEvent,
  InterceptorKind,
} from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";
import { webcrypto } from "node:crypto";

/** SHA-256 hex digest of a string. */
async function sha256Hex(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const hash = await webcrypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface FeatureExtractorOptions {
  /** Opaque customer ID from license validation. */
  customerId: string;
  /**
   * HMAC salt from license validation response (hex-encoded, 32 bytes).
   * When absent, a locally-generated salt is used as fallback.
   */
  hmacSaltHex?: string;
  /** Transport for submitting batches to the cloud. */
  transport: FeatureTransport;
  /** The read model store to extract from. */
  store: ReadModelStore;
  /** Event log for emitting feature.extracted audit events. */
  eventLog: EventLog;
  /** Interceptor kind to stamp on audit events. Default: "analyzer". */
  interceptorKind?: InterceptorKind;
}

export interface ExtractionResult {
  /** The submitted batch. */
  batch: FeatureBatch;
  /** Server receipt ID. */
  receiptId: string;
  /** Anomaly score if the server returned one synchronously. */
  anomalyScore: number | null;
}

export class FeatureExtractor {
  private readonly customerId: string;
  private readonly hmacSaltHex: string;
  private readonly transport: FeatureTransport;
  private readonly store: ReadModelStore;
  private readonly eventLog: EventLog;
  private readonly interceptorKind: InterceptorKind;

  constructor(options: FeatureExtractorOptions) {
    this.customerId = options.customerId;
    this.hmacSaltHex = options.hmacSaltHex ?? generateLocalSalt();
    this.transport = options.transport;
    this.store = options.store;
    this.eventLog = options.eventLog;
    this.interceptorKind = options.interceptorKind ?? "analyzer";
  }

  /**
   * Extract and submit features for a single session.
   * Returns null if the session does not exist in the read model.
   */
  async extractSession(sessionId: string): Promise<ExtractionResult | null> {
    // 1. Extract anonymized features
    const batch = await extractSessionFeatures(this.store, {
      sessionId,
      customerId: this.customerId,
      hmacSaltHex: this.hmacSaltHex,
    });

    if (!batch) return null;

    // 2. Submit to cloud
    const response = await this.transport.submit(batch);

    // 3. Emit audit event
    await this.emitAuditEvent(batch, response.receipt_id);

    return {
      batch,
      receiptId: response.receipt_id,
      anomalyScore: response.anomaly_score,
    };
  }

  /**
   * Extract and submit features for all sessions in the read model.
   * Useful for batch catch-up or timer-based extraction.
   */
  async extractAll(): Promise<ExtractionResult[]> {
    const sessions = await this.store.listSessions();
    const results: ExtractionResult[] = [];

    for (const session of sessions) {
      const result = await this.extractSession(session.session_id);
      if (result) results.push(result);
    }

    return results;
  }

  /**
   * Extract and submit features for specific session IDs.
   * Skips sessions that don't exist. Useful for session-end flush.
   */
  async extractSessions(sessionIds: string[]): Promise<ExtractionResult[]> {
    const results: ExtractionResult[] = [];

    for (const id of sessionIds) {
      const result = await this.extractSession(id);
      if (result) results.push(result);
    }

    return results;
  }

  /** Return the HMAC salt in use (for persistence/diagnostics). */
  getHmacSaltHex(): string {
    return this.hmacSaltHex;
  }

  private async emitAuditEvent(
    batch: FeatureBatch,
    receiptId: string,
  ): Promise<void> {
    const featureHash = await sha256Hex(JSON.stringify(batch));
    const now = new Date().toISOString();

    const event: FeatureExtractedEvent = {
      schema_version: SCHEMA_VERSION,
      event_id: webcrypto.randomUUID(),
      session_id: batch.session_hash, // hashed, not raw
      occurred_at: now,
      recorded_at: now,
      interceptor: this.interceptorKind,
      event_type: "feature.extracted",
      batch_id: batch.batch_id,
      feature_hash: featureHash,
      cloud_receipt_id: receiptId,
    };

    await this.eventLog.append(event);
  }
}
