// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
export { SyncEncryptor } from "./sync-encryptor.js";
export type { SyncEncryptorOptions, SyncResult } from "./sync-encryptor.js";

export { deriveKey, encrypt, decrypt, sha256Hex, randomSalt, randomIv, KDF_PARAMS, deriveStreamingKey, computeKeyId } from "./crypto.js";

export {
  HPKE_EVENT_SCHEME,
  HPKE_EVENT_INFO,
  createStreamSuite,
  hpkeEventAad,
  computePublicKeyId,
  generateStreamKeyPair,
  sealEvent,
  openEvent,
} from "./hpke-event.js";
export type { HpkeEventWire, StreamKeyPair, StreamPrivateKey } from "./hpke-event.js";

export {
  WRAPPED_STREAM_KEY_VERSION,
  deriveStreamWrapKey,
  wrapStreamPrivateKey,
  unwrapStreamPrivateKey,
} from "./stream-keypair.js";
export type { WrappedStreamKey, StreamWrapKey } from "./stream-keypair.js";

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
  LiveGate,
  LIVE_BACKOFF_MIN_MS,
  LIVE_BACKOFF_MAX_MS,
  livePushAllowed,
  recordLivePush,
} from "./live-gate.js";
export type { LivePushOutcome, LiveGateState } from "./live-gate.js";
export { readOrFetchLicense } from "./license-cache.js";
export type { CachedLicense, LicenseCredentials } from "./license-cache.js";

export {
  startBackgroundSync,
  runAutoSync,
  backgroundPassDue,
  readAutoSyncState,
  readAutoSyncIntervalMs,
  includesSessionEnd,
  AUTO_SYNC_CHILD_ENV,
  DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS,
  DEFAULT_AUTO_SYNC_INTERVAL_SECONDS,
} from "./auto-sync.js";
export type { AutoSyncState, AutoSyncDecision, AutoSyncOutcome, StartBackgroundSyncOptions, RunAutoSyncOptions } from "./auto-sync.js";
