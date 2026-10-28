// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
export { SyncEncryptor } from "./sync-encryptor.js";
export type { SyncEncryptorOptions, SyncResult } from "./sync-encryptor.js";

export { deriveKey, encrypt, decrypt, sha256Hex, randomSalt, randomIv, KDF_PARAMS, deriveStreamingKey, computeKeyId, deriveStreamVerifier } from "./crypto.js";

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

export { serializeReadModel, encodePayload, SYNC_PAYLOAD_VERSION, PAYLOAD_FIELDS } from "./serializer.js";
export type { SyncPayload } from "./serializer.js";

export {
  encodeEnvelope,
  decodeEnvelope,
  ENVELOPE_MAGIC,
  ENVELOPE_VERSION,
  ENVELOPE_VERSION_GZIP,
  SALT_LEN,
  IV_LEN,
  HEADER_LEN,
} from "./envelope.js";
export type { DecodedEnvelope } from "./envelope.js";

export {
  HttpSyncTransport,
  ReceivingPausedError,
  SyncBlobTooLargeError,
  SyncTooSoonError,
  SYNC_BLOB_MAX_BYTES,
  SYNC_INTERVAL_HEADER,
} from "./transport.js";
export { syncSegments, SEGMENT_SEAL_BYTES, SEGMENT_WINDOW_DAYS, SEGMENT_MANIFEST_FILE } from "./segment-sync.js";
export type { SegmentSyncOptions, SegmentSyncResult, SegmentManifest } from "./segment-sync.js";
export { HttpSegmentTransport, SegmentsUnsupportedError, MissingSegmentsError } from "./segment-transport.js";
export type { SegmentTransport, SegmentMeta, HttpSegmentTransportOptions } from "./segment-transport.js";
export type {
  SyncTransport,
  SyncPushRequest,
  SyncPushResponse,
  HttpSyncTransportOptions,
} from "./transport.js";

export { StreamingTransport } from "./streaming-transport.js";

export {
  computeMachineId,
  readMachineLabel,
  legacyMachineId,
  pendingMachineIdRemap,
  acknowledgeMachineIdRemap,
  remapMachineId,
  type RemapOptions,
} from "./machine-id.js";
export {
  deriveLabelKey,
  sealLabel,
  openLabel,
  sealedMachineLabel,
  sealedText,
  SEALED_LABEL_RE,
  type LabelField,
  type LabelKey,
} from "./machine-label.js";
export {
  TokenRotatedError,
  SecretMismatchError,
  TokenCollectionError,
  isTokenRotated,
  ensureSecretVerifier,
  collectRotatedToken,
  readVerifierState,
  knownSecretMismatch,
  probeStreamToken,
  streamHasSecret,
  STREAM_VERIFIER_FILE,
} from "./stream-credentials.js";
export type { VerifierState, CredentialOptions } from "./stream-credentials.js";
export type { StreamingTransportOptions } from "./streaming-transport.js";

export { pushEventsToCloud, deferLivePush, takeDeferredPush, DEFERRED_PUSH_FILE } from "./shim-push.js";
export {
  LiveGate,
  LIVE_BACKOFF_MIN_MS,
  LIVE_BACKOFF_MAX_MS,
  livePushAllowed,
  recordLivePush,
  readLiveGate,
  clearLiveGate,
  isReceivingPaused,
  RECEIVING_PAUSED_ERROR,
} from "./live-gate.js";
export type { LivePushOutcome, LiveGateState } from "./live-gate.js";
export { readOrFetchLicense } from "./license-cache.js";
export type { CachedLicense, LicenseCredentials } from "./license-cache.js";

export {
  acquireSyncLock,
  SYNC_LOCK_WAIT_MS,
  startBackgroundSync,
  runAutoSync,
  backgroundPassDue,
  readAutoSyncState,
  recordSyncOutcome,
  syncDeferred,
  readAutoSyncIntervalMs,
  includesSessionEnd,
  AUTO_SYNC_CHILD_ENV,
  DEFAULT_AUTO_SYNC_MIN_INTERVAL_SECONDS,
  DEFAULT_AUTO_SYNC_INTERVAL_SECONDS,
} from "./auto-sync.js";
export type { AcquireSyncLockOptions, AutoSyncState, AutoSyncDecision, AutoSyncOutcome, StartBackgroundSyncOptions, RunAutoSyncOptions, DetectResult } from "./auto-sync.js";
export { checkMonitoringConfig, codexHooksOff, readMonitoringSlots, MONITORING_CHECK_INTERVAL_MS, UNEXPLAINED_CHANGE_RULE_ID } from "./monitoring-check.js";
export { buildHeartbeat, sendMonitoringHeartbeat, readHeartbeatState, HEARTBEAT_INTERVAL_MS, HEARTBEAT_MIN_GAP_MS, SESSION_OPEN_WINDOW_MS } from "./monitoring-heartbeat.js";
export type { ComponentState, Heartbeat, HeartbeatOutcome, HeartbeatPlatform, HeartbeatState, SendHeartbeatOptions } from "./monitoring-heartbeat.js";
export type { InstallationCheck, InstallationState, MonitoringCheckOptions, MonitoringCheckResult } from "./monitoring-check.js";

// Advanced (Pro) rule usage: counted in the background pass, submitted in batches
export { readAdvancedUsage, ADVANCED_USAGE_FILE, MAX_AGE_DAYS as ADVANCED_USAGE_MAX_AGE_DAYS } from "./advanced-usage.js";
export type { AdvancedUsageState } from "./advanced-usage.js";
export { readRuleSignals, collectRuleSignals, submitRuleSignals, RULE_SIGNALS_FILE, RULE_SIGNALS_LOG } from "./rule-signals.js";
export type { RuleSignalsState, RuleSignalCount } from "./rule-signals.js";

// Advanced rule bundle refresh (background pass, Pro and Enterprise)
export { refreshRuleBundle, RULE_BUNDLE_FILE, RULES_REFRESH_ENV } from "./rules-refresh.js";
export {
  refreshGuardrailsModule,
  guardrailsEntitled,
  GUARDRAILS_MODULE_FILE,
  GUARDRAILS_REFRESH_ENV,
  GUARDRAILS_REFRESH_STATE_FILE,
} from "./guardrails-refresh.js";
export type { GuardrailsRefreshOutcome, GuardrailsRefreshOptions } from "./guardrails-refresh.js";
export type { RulesRefreshOutcome, RulesRefreshOptions } from "./rules-refresh.js";
