// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/shared
 *
 * Core types shared across all Omnodex packages. Defines the trace event
 * schema (the source of truth wire format written into the append-only event
 * log) and the Interceptor interface, which every interception source
 * (Claude Code hooks, Cowork desktop seam, MCP proxy, mock generator) must
 * implement.
 *
 * Keep this file free of runtime dependencies so every other package can
 * import from it without pulling in transitive weight.
 */

export const SCHEMA_VERSION = 1 as const;

/** Severity levels used for risk events. */
export type RiskSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Logical category of the interception source that emitted an event. */
export type InterceptorKind =
  | "claude-code-hook"
  | "codex-hook"
  | "antigravity-hook"
  | "cowork-desktop"
  | "mcp-proxy"
  | "mock"
  | "analyzer";

/**
 * The agent runtime platform. Distinct from InterceptorKind: interceptor
 * identifies the mechanism (hook, proxy), platform identifies the runtime
 * (cowork, codex, claude-code). Enables filtering by agent runtime
 * independently of interception method.
 */
export type PlatformKind =
  | "claude-code"
  | "codex"
  | "cowork"
  | "web"
  | "antigravity"
  | "copilot";

/** Fields present on every trace event, regardless of type. */
export interface BaseEvent {
  /** Schema version of the event wire format. Bump when fields change. */
  schema_version: typeof SCHEMA_VERSION;
  /** Globally unique event id. UUID v4 is fine. */
  event_id: string;
  /** Session the event belongs to. */
  session_id: string;
  /** When the underlying thing actually happened, ISO 8601. */
  occurred_at: string;
  /** When Omnodex saw it, ISO 8601. May differ from occurred_at under async. */
  recorded_at: string;
  /** Which interceptor produced this event. */
  interceptor: InterceptorKind;
  /**
   * The agent runtime platform. Optional for backwards compatibility
   * with existing event logs. When absent, consumers may infer platform
   * from the interceptor field.
   */
  platform?: PlatformKind;
}

export interface SessionStartedEvent extends BaseEvent {
  event_type: "session.started";
  user: string;
  project_path: string;
  mcp_servers: string[];
}

export interface SessionEndedEvent extends BaseEvent {
  event_type: "session.ended";
  duration_ms: number;
  /** How the session terminated. */
  status: "completed" | "errored" | "interrupted";
}

export interface ToolInvokedEvent extends BaseEvent {
  event_type: "tool.invoked";
  tool_call_id: string;
  tool_name: string;
  /**
   * Name of the MCP server that owns the tool, or "builtin" for tools
   * implemented by the agent runtime itself (Read, Write, Bash, etc.).
   */
  mcp_server: string;
  /** Parameters as a JSON-serializable object. May be redacted upstream. */
  parameters: Record<string, unknown>;
  /**
   * Working directory of the agent session at the time of this tool call.
   * Populated from the hook payload (all major agents include cwd).
   * Used by cwd_boundary rules to detect file access outside the project.
   * Optional for backwards compatibility with existing event logs.
   */
  cwd?: string;
}

export interface ToolCompletedEvent extends BaseEvent {
  event_type: "tool.completed";
  tool_call_id: string;
  duration_ms: number;
  status: "success" | "error";
  /** Byte size of the serialized response. Full body is not stored. */
  response_bytes: number;
  error_message?: string;
}

export interface FileReadEvent extends BaseEvent {
  event_type: "file.read";
  path: string;
  bytes: number;
}

export interface FileWrittenEvent extends BaseEvent {
  event_type: "file.written";
  path: string;
  bytes: number;
}

export interface RiskDetectedEvent extends BaseEvent {
  event_type: "risk.detected";
  severity: RiskSeverity;
  category: string;
  description: string;
  /**
   * Identifier of the triggering event. In practice this is the
   * `tool_call_id` of the tool call that caused the detection, which
   * lets the dashboard cross-link directly to the event timeline.
   * Future analyzers may reference a raw `event_id` instead.
   */
  related_event_id: string;
  /** Rule id that fired. */
  rule_id: string;
}


// ---------------------------------------------------------------------------
// Cloud API types (used by license-client, sync-encryptor, feature-extractor)
// ---------------------------------------------------------------------------

/** Sent by the local CLI to validate a subscription and retrieve tier info. */
export interface LicenseValidateRequest {
  api_token: string;
  client_version: string;
  interceptor_kind: InterceptorKind;
}

/** Returned by the cloud license endpoint. Cache locally for ttl_seconds. */
export interface LicenseValidateResponse {
  customer_id: string;
  tier: "free" | "hosted" | "pro" | "enterprise";
  /** Enabled feature flags for this subscription. */
  features: string[];
  /** AES-256-GCM key for decrypting advanced rule definitions (Pro+). */
  rule_decryption_key?: string;
  /** Presigned R2 URL for sync blob access (Hosted+). */
  sync_endpoint?: string;
  /** How long the caller may cache this response, in seconds. */
  ttl_seconds: number;
  /**
   * Customer-specific HMAC salt for hashing tool names and MCP server
   * names in feature batches. Server-issued for controlled rotation.
   * Hex-encoded, 32 bytes.
   */
  hmac_salt?: string;
}

/**
 * Anonymized, aggregated feature batch submitted by Pro+ customers.
 * Never contains raw event content -- only counts, hashes, and scores.
 */
export interface FeatureBatch {
  batch_id: string;
  customer_id: string;
  /** HMAC-SHA256 of the raw session_id. */
  session_hash: string;
  timestamp: string;
  metrics: {
    event_count: number;
    tool_call_count: number;
    unique_tool_count: number;
    unique_mcp_server_count: number;
    duration_ms: number;
    /** Risk score computed locally before submission. */
    risk_score: number;
  };
  timing: {
    mean_tool_duration_ms: number;
    median_tool_duration_ms: number;
    p95_tool_duration_ms: number;
  };
  risk_summary: {
    by_severity: Record<RiskSeverity, number>;
    by_category: Record<string, number>;
    rule_ids_fired: string[];
  };
  hashed_identifiers: {
    /** HMAC-SHA256 of each tool name. */
    tool_names: string[];
    /** HMAC-SHA256 of each MCP server name. */
    mcp_servers: string[];
  };
}

/**
 * Zero-knowledge encrypted sync payload. The cloud never holds the
 * decryption key -- the passphrase-derived key stays client-side.
 */
export interface SyncPackage {
  blob_id: string;
  customer_id: string;
  /** AES-256-GCM ciphertext of the serialized session data. */
  encrypted_payload: ArrayBuffer;
  /** Initialisation vector, fresh per sync operation. */
  iv: Uint8Array;
  /** Argon2id KDF salt stored alongside the blob. */
  kdf_salt: Uint8Array;
  payload_bytes: number;
  sessions_included: string[];
}

// ---------------------------------------------------------------------------
// Cloud event types (emitted by local packages after a cloud operation)
// ---------------------------------------------------------------------------

export interface SyncPushedEvent extends BaseEvent {
  event_type: "sync.pushed";
  payload_bytes: number;
  /** SHA-256 hex digest of the ciphertext, for tamper detection. */
  ciphertext_hash: string;
  sessions_included: string[];
  cloud_receipt_id: string;
}

export interface FeatureExtractedEvent extends BaseEvent {
  event_type: "feature.extracted";
  batch_id: string;
  /** SHA-256 hex digest of the batch JSON. */
  feature_hash: string;
  cloud_receipt_id: string;
}

export interface RuleUpdatedEvent extends BaseEvent {
  event_type: "rule.updated";
  rules_updated: string[];
  source: "cloud" | "local";
}

/** Discriminated union of every event type accepted by the event log. */
export type TraceEvent =
  | SessionStartedEvent
  | SessionEndedEvent
  | ToolInvokedEvent
  | ToolCompletedEvent
  | FileReadEvent
  | FileWrittenEvent
  | RiskDetectedEvent
  | SyncPushedEvent
  | FeatureExtractedEvent
  | RuleUpdatedEvent;

export type EventType = TraceEvent["event_type"];

/**
 * The Interceptor interface. Every interception source is a factory that
 * returns an object conforming to this interface. The event log and
 * downstream packages only ever see this shape, so a Claude Code
 * hook-backed interceptor and a desktop interceptor are
 * interchangeable from the pipeline's point of view.
 *
 * Interceptors are async-only by design. They fire-and-forget events onto
 * the event log; they never block the agent's execution path.
 */
export interface Interceptor {
  /** Human readable name for logs and diagnostics. */
  readonly name: string;
  /** Which kind of source this is. */
  readonly kind: InterceptorKind;
  /**
   * Start producing events. The interceptor will invoke `emit` for every
   * event it observes. Returns a stop function for graceful shutdown.
   */
  start(emit: EmitFn): Promise<StopFn>;
}

/** Function passed to an interceptor to record an event. */
export type EmitFn = (event: TraceEvent) => void | Promise<void>;

/** Returned by `start()`; invoking it cleanly stops the interceptor. */
export type StopFn = () => Promise<void>;

/**
 * Narrow guard useful when consumers only care about a subset of events.
 */
export function isEventOfType<T extends EventType>(
  event: TraceEvent,
  type: T,
): event is Extract<TraceEvent, { event_type: T }> {
  return event.event_type === type;
}
