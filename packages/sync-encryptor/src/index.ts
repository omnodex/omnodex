// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
export { SyncEncryptor } from "./sync-encryptor.js";
export type { SyncEncryptorOptions, SyncResult } from "./sync-encryptor.js";

export { deriveKey, encrypt, decrypt, sha256Hex, randomSalt, randomIv, KDF_PARAMS, deriveStreamingKey, computeKeyId } from "./crypto.js";

export { serializeReadModel, encodePayload, SYNC_PAYLOAD_VERSION } from "./serializer.js";
export type { SyncPayload } from "./serializer.js";

export {
  encodeEnvelope,
  decodeEnvelope,
  ENVELOPE_MAGIC,
  ENVELOPE_VERSION,
  SALT_LEN,
  IV_LEN,
  HEADER_LEN,
} from "./envelope.js";
export type { DecodedEnvelope } from "./envelope.js";

export { HttpSyncTransport } from "./transport.js";
export type {
  SyncTransport,
  SyncPushRequest,
  SyncPushResponse,
  HttpSyncTransportOptions,
} from "./transport.js";

export { StreamingTransport } from "./streaming-transport.js";

export { computeMachineId, readMachineLabel } from "./machine-id.js";
export type { StreamingTransportOptions } from "./streaming-transport.js";

export { pushEventsToCloud } from "./shim-push.js";

export {
  startBackgroundSync,
  runAutoSync,
  readAutoSyncState,
  readAutoSyncIntervalMs,
  includesSessionEnd,
  AUTO_SYNC_CHILD_ENV,
  DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS,
  DEFAULT_AUTO_SYNC_INTERVAL_SECONDS,
} from "./auto-sync.js";
export type { AutoSyncState, AutoSyncDecision, AutoSyncOutcome, StartBackgroundSyncOptions } from "./auto-sync.js";
