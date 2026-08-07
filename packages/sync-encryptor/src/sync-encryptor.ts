// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- orchestrator
 *
 * Coordinates the full sync pipeline:
 *   1. Serialize projection data from the SQLite read model
 *   2. Encrypt with AES-256-GCM (key derived from passphrase via Argon2id)
 *   3. Push ciphertext to the cloud via the transport
 *   4. Emit a sync.pushed audit event to the local event log
 *
 * The passphrase and derived key never leave the client. The cloud stores
 * only ciphertext, IV, and KDF salt. This is the same zero-knowledge
 * pattern used by Proton Mail and Bitwarden.
 */

import { randomSalt, deriveKey, encrypt, sha256Hex } from "./crypto.js";
import { serializeReadModel, encodePayload } from "./serializer.js";
import type { SyncTransport } from "./transport.js";
import type { ReadModelStore } from "@omnodex/projection";
import type { EventLog } from "@omnodex/event-log";
import type { SyncPushedEvent, InterceptorKind } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";
import { randomUUID } from "node:crypto";

export interface SyncEncryptorOptions {
  /** The customer's chosen passphrase for encryption. */
  passphrase: string;
  /** Opaque customer ID from license validation. */
  customerId: string;
  /** Transport for pushing encrypted blobs to the cloud. */
  transport: SyncTransport;
  /** The read model store to serialize from. */
  store: ReadModelStore;
  /** Event log for emitting sync.pushed audit events. */
  eventLog: EventLog;
  /** Interceptor kind to stamp on audit events. Default: "analyzer". */
  interceptorKind?: InterceptorKind;
  /**
   * Persisted KDF salt. When provided, the same salt is reused across
   * syncs so the hosted dashboard can derive the same key with the
   * same passphrase. When omitted, a fresh salt is generated on first
   * sync and returned for the caller to persist.
   */
  kdfSalt?: Uint8Array;
  /** Stable machine identifier (SHA-256 prefix of hostname). */
  machineId: string;
  /** Optional human-readable machine label. */
  machineLabel?: string;
}

export interface SyncResult {
  /** Server-generated blob ID (receipt). */
  blobId: string;
  /** SHA-256 hex digest of the ciphertext. */
  ciphertextHash: string;
  /** Session IDs included in this sync. */
  sessionsIncluded: string[];
  /** Byte count of the plaintext before encryption. */
  payloadBytes: number;
  /** The KDF salt used. Persist this for subsequent syncs. */
  kdfSalt: Uint8Array;
  /** Machine identifier included in this sync. */
  machineId: string;
}

export class SyncEncryptor {
  private readonly passphrase: string;
  private readonly customerId: string;
  private readonly transport: SyncTransport;
  private readonly store: ReadModelStore;
  private readonly eventLog: EventLog;
  private readonly interceptorKind: InterceptorKind;
  private readonly machineId: string;
  private readonly machineLabel: string | undefined;
  private kdfSalt: Uint8Array;

  constructor(options: SyncEncryptorOptions) {
    this.passphrase = options.passphrase;
    this.customerId = options.customerId;
    this.transport = options.transport;
    this.store = options.store;
    this.eventLog = options.eventLog;
    this.interceptorKind = options.interceptorKind ?? "analyzer";
    this.machineId = options.machineId;
    this.machineLabel = options.machineLabel;
    this.kdfSalt = options.kdfSalt ?? randomSalt();
  }

  /**
   * Run a full sync cycle: serialize, encrypt, push, audit.
   *
   * When sessionIds is provided, only those sessions are synced
   * (incremental sync). When omitted, all sessions are synced (full sync).
   */
  async sync(sessionIds?: string[]): Promise<SyncResult> {
    // 1. Serialize projection data
    const payload = await serializeReadModel(this.store, sessionIds);
    const plaintext = encodePayload(payload);

    // 2. Derive key and encrypt
    const key = await deriveKey(this.passphrase, this.kdfSalt);
    const { ciphertext, iv } = await encrypt(key, plaintext);

    // 3. Compute ciphertext hash for audit
    const ciphertextHash = await sha256Hex(ciphertext);

    // 4. Push to cloud
    const response = await this.transport.push({
      customer_id: this.customerId,
      encrypted_payload: ciphertext,
      iv,
      kdf_salt: this.kdfSalt,
      payload_bytes: plaintext.length,
      sessions_included: payload.session_ids,
      machine_id: this.machineId,
      machine_label: this.machineLabel,
    });

    // 5. Emit audit event
    const now = new Date().toISOString();
    const auditEvent: SyncPushedEvent = {
      schema_version: SCHEMA_VERSION,
      event_id: randomUUID(),
      session_id: payload.session_ids[0] ?? "global",
      occurred_at: now,
      recorded_at: now,
      interceptor: this.interceptorKind,
      event_type: "sync.pushed",
      payload_bytes: plaintext.length,
      ciphertext_hash: ciphertextHash,
      sessions_included: payload.session_ids,
      cloud_receipt_id: response.blob_id,
      machine_id: this.machineId,
      machine_label: this.machineLabel,
    };
    await this.eventLog.append(auditEvent);

    return {
      blobId: response.blob_id,
      ciphertextHash,
      sessionsIncluded: payload.session_ids,
      payloadBytes: plaintext.length,
      kdfSalt: this.kdfSalt,
      machineId: this.machineId,
    };
  }

  /** Return the KDF salt for persistence. */
  getKdfSalt(): Uint8Array {
    return this.kdfSalt;
  }
}
