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

import type { FindingEnforcement } from "./enforcement.js";

export const SCHEMA_VERSION = 1 as const;

/**
 * Split a model-visible MCP tool name into its server and tool components.
 *
 * MCP clients compose names as `mcp__<server>__<tool>`. Both components may
 * contain single underscores, so the first double underscore after the
 * prefix is the only safe boundary. The tool component keeps later double
 * underscores because proxies use the same delimiter for upstream names.
 */
export function splitMcpToolName(
  toolName: string,
): { mcpServer: string; upstreamToolName: string } | null {
  if (!toolName.startsWith("mcp__")) return null;
  const rest = toolName.slice("mcp__".length);
  const separator = rest.indexOf("__");
  if (separator <= 0) return null;
  const upstreamToolName = rest.slice(separator + 2);
  if (!upstreamToolName) return null;
  return {
    mcpServer: rest.slice(0, separator),
    upstreamToolName,
  };
}

/**
 * Joins a proxy's upstream prefix and the upstream tool name in the name the
 * agent sees. Clients restrict tool names to letters, digits, "_" and "-"
 * (the Claude API enforces ^[a-zA-Z0-9_-]{1,64}$), so the separator must stay
 * inside that set. A "/" separator gets rewritten by some clients, which
 * breaks per-tool approval because the approved name no longer matches the
 * called name.
 */
export const TOOL_NAME_SEPARATOR = "__";

/** Hex digits of the hash appended to a shortened tool name. */
const SHORT_NAME_HASH_LENGTH = 6;

/** FNV-1a, so the same name shortens the same way on every runtime. */
function shortHash(value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0").slice(0, SHORT_NAME_HASH_LENGTH);
}

/**
 * The agent-visible name for an upstream tool within a length limit. A name
 * that fits is the plain prefixed name. A longer one keeps the prefix and
 * separator, so it still resolves to its upstream, and as much of the tool
 * name as fits, then "_" and a hash of the full name so two long names that
 * start alike stay distinct. Only when the prefix itself leaves no room is
 * the whole name cut.
 */
export function fitToolName(prefix: string, toolName: string, limit?: number): string {
  const full = `${prefix}${TOOL_NAME_SEPARATOR}${toolName}`;
  if (limit === undefined || full.length <= limit) return full;
  const suffix = `_${shortHash(full)}`;
  const room = limit - prefix.length - TOOL_NAME_SEPARATOR.length - suffix.length;
  if (room >= 4) {
    return `${prefix}${TOOL_NAME_SEPARATOR}${toolName.slice(0, room).replace(/[_-]+$/, "")}${suffix}`;
  }
  return `${full.slice(0, limit - suffix.length).replace(/[_-]+$/, "")}${suffix}`;
}

/**
 * Whether `shortName` is what fitToolName made of the prefixed name
 * `fullName` under some limit: it ends in "_" and the full name's hash, and
 * what comes before that starts the full name. Needs no limit, so it holds
 * whatever limit the proxy ran with.
 */
export function isShortenedToolName(shortName: string, fullName: string): boolean {
  const suffix = `_${shortHash(fullName)}`;
  if (shortName === fullName || !shortName.endsWith(suffix)) return false;
  const stem = shortName.slice(0, -suffix.length);
  return stem.length > 0 && fullName.startsWith(stem);
}

/** Severity levels used for risk events. */
export type RiskSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * What one finding of each severity contributes to a session's risk score.
 *
 * This is the single source of truth. Four different scales had grown up
 * independently (the projector on 5/15/30/60, the hosted dashboard's live
 * reducer on 0.1/1.0, the demo generator on 1/15, and threshold checks that
 * matched none of them), so the same session scored differently depending on
 * whether its data arrived by synced blob or by live stream.
 *
 * The scale is deliberately small. A score is a sum over a whole session, and
 * a session with hundreds of findings should still read as a number a person
 * can hold in their head rather than several thousand.
 *
 * The hosted dashboard lives in another repo and mirrors these values by
 * hand, the same way it mirrors the read-model row shapes. Change both.
 */
export const RISK_SEVERITY_WEIGHT: Readonly<Record<RiskSeverity, number>> = {
  LOW: 0.1,
  MEDIUM: 0.4,
  HIGH: 0.7,
  CRITICAL: 1.0,
};

/**
 * Lower bound of each risk band, for turning an accumulated score back into a
 * label. Set so that a session with exactly one finding lands in that
 * finding's own band, and accumulates upward from there.
 */
export const RISK_BAND_THRESHOLD: Readonly<Record<RiskSeverity, number>> = {
  CRITICAL: RISK_SEVERITY_WEIGHT.CRITICAL,
  HIGH: RISK_SEVERITY_WEIGHT.HIGH,
  MEDIUM: RISK_SEVERITY_WEIGHT.MEDIUM,
  LOW: 0,
};

/** Score contributed by one finding. Unknown severities contribute nothing. */
export function riskScoreFor(severity: string): number {
  return RISK_SEVERITY_WEIGHT[severity as RiskSeverity] ?? 0;
}

/**
 * Round an accumulated risk score to the precision the weights are expressed
 * in. Summing tenths in binary floating point produces values like
 * 1.2000000000000002, which have no business reaching a dashboard.
 */
export function roundRiskScore(score: number): number {
  return Math.round(score * 100) / 100;
}

/**
 * The band an accumulated score falls in, or null when nothing fired.
 * Used for labels, colours and filters so they cannot drift from the weights.
 */
export function riskBandFor(score: number): RiskSeverity | null {
  if (score <= 0) return null;
  if (score >= RISK_BAND_THRESHOLD.CRITICAL) return "CRITICAL";
  if (score >= RISK_BAND_THRESHOLD.HIGH) return "HIGH";
  if (score >= RISK_BAND_THRESHOLD.MEDIUM) return "MEDIUM";
  return "LOW";
}

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
  /**
   * The subagent the event happened in, as the runtime identifies it.
   * Absent for the main agent and for runtimes without subagents. Lets a
   * tool call be attributed to the subagent that made it, and joins it to
   * that subagent's subagent.started and subagent.stopped events.
   */
  agent_id?: string;
  /**
   * Recorded while uploads were paused on this machine. The event stays in
   * the local log and local dashboard, and never leaves the machine: live
   * push and sync skip it. Absent means the event may be uploaded.
   */
  local_only?: boolean;
}

export interface SessionStartedEvent extends BaseEvent {
  event_type: "session.started";
  user: string;
  project_path: string;
  mcp_servers: string[];
  /**
   * How each MCP server is reached, when the interceptor knows (the MCP
   * proxy does). `host` is the URL host of a remote server; paths, query
   * strings and credentials are never recorded.
   */
  mcp_server_transports?: McpServerTransport[];
  /**
   * The MCP client the proxy served, as the client named itself in the MCP
   * initialize handshake (clientInfo). Only the proxy records it.
   */
  mcp_client?: { name: string; version?: string };
  /**
   * The project's git `origin` remote, normalized to `host/owner/repo`
   * (scheme, credentials, port and `.git` dropped; ssh and https forms of
   * one repo read the same). It names the project the same way on every
   * machine, whatever its folder is called. Absent when the working
   * directory is not in a repository, has no `origin`, or `origin` is a
   * local path.
   */
  project_remote?: string;
  /**
   * The model the agent platform reported for the session's first turn, as
   * the platform names it. Only what the platform reports: never probed or
   * verified. Absent when the platform does not say (session.model_changed
   * may supply it later).
   */
  model?: string;
}

export interface McpServerTransport {
  name: string;
  transport: "stdio" | "http";
  host?: string;
}

/**
 * What an MCP server looked like when the proxy received its tool list: at
 * connect, or after the server announced a change (tools/list_changed). The
 * proxy writes one per server per session, and another whenever the list
 * changes, so comparing a server's observations shows when it changed.
 *
 * Fingerprints are hashes of local data. Tool descriptions and schemas are
 * not in the event; the proxy keeps the full lists on the machine, found by
 * tool_list_fingerprint, for a before-and-after view.
 */
export interface ServerObservedEvent extends BaseEvent {
  event_type: "server.observed";
  /** The server's configured name, as tool.invoked names it. */
  mcp_server: string;
  transport: "stdio" | "http";
  /** connect: listed when the server connected. list_changed: listed again after the server announced a change. */
  trigger: "connect" | "list_changed";
  /**
   * Hash of the server's configuration entry: command, arguments and
   * working directory, or URL; and the names, never the values, of its
   * environment variables and headers.
   */
  config_fingerprint: string;
  /** The server's own name and version from the MCP initialize handshake. */
  reported?: { name: string; version?: string };
  /**
   * The version of the package actually installed, when the proxy can read
   * it (an npx server's package in the npx cache). Unlike the reported
   * version, the server cannot choose it.
   */
  installed_version?: string;
  /** Hash of every tool's fingerprint, sorted: one comparison for the whole list. */
  tool_list_fingerprint: string;
  /** Each tool's name, and a hash of its name, description and input schema. */
  tools: { name: string; fingerprint: string }[];
}

export interface SessionEndedEvent extends BaseEvent {
  event_type: "session.ended";
  duration_ms: number;
  /** How the session terminated. */
  status: "completed" | "errored" | "interrupted";
}

/**
 * The session's title changed: the user renamed it, or the agent runtime
 * named it. Interceptors emit it only when the title differs from the last
 * one they recorded, so the latest event for a session is its title.
 */
export interface SessionRenamedEvent extends BaseEvent {
  event_type: "session.renamed";
  title: string;
}

/**
 * The model the platform reports for the session changed, or was first
 * reported after the session started. Interceptors emit it only when the
 * model differs from the last one they recorded for the session, so the
 * latest event (or session.started) names the current model.
 */
export interface SessionModelChangedEvent extends BaseEvent {
  event_type: "session.model_changed";
  model: string;
  /** The model recorded before; absent when this is the first one seen. */
  previous?: string;
  /** Where the platform reported it: its hook input, or its transcript. */
  source: "hook" | "transcript";
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

/**
 * The version of the rule format this release's analyzer reads. Version 2
 * added the ordered `steps` form of sequence conditions and the staging
 * condition. A host that fetches rules says which version it reads, so
 * rules in a newer format can be held back from it.
 */
export const RULE_FORMAT_VERSION = 2;

/**
 * What a call contributed to a finding that spans several calls: where the
 * data came from, an intermediate step such as archiving or encoding it,
 * the call that sent it, or context that explains the others.
 */
export type EvidenceRole = "source" | "staging" | "sink" | "context";

export interface EvidenceStep {
  /** tool_call_id of the call, as in related_event_ids. */
  tool_call_id: string;
  role: EvidenceRole;
  /**
   * One line on what the call did, built from what it reads, writes and
   * reaches ("Read ~/.aws/credentials"). Never the command text, which can
   * hold the credential itself.
   */
  summary: string;
  /** What matched on this call, such as the label of a sensitive path. */
  labels?: string[];
  /** The interceptor that recorded the call. */
  interceptor?: InterceptorKind;
}

export interface EvidenceDestination {
  /** Lowercased host name or IP literal. */
  host: string;
  scheme?: string;
  port?: number;
  ip_class?: "loopback" | "private" | "link-local" | "metadata" | "public";
  /** The call names an IP address rather than a host name. */
  raw_ip?: boolean;
}

export interface EvidenceCredential {
  /** The kind of credential, as the rule labels it ("AWS credentials"). */
  class: string;
  /** Seen as a file the agent read, or as a pattern in a call's parameters. */
  source: "file-read" | "param-pattern";
  /** How the sink used it: as authentication, in a body, a URL, and so on. */
  role?: "auth-header" | "body" | "url" | "env" | "argument" | "content";
}

/**
 * How an MCP server changed, on a drift finding: the structured form of
 * what its description says, so a dashboard or digest can group and link
 * it without parsing text. Tool names only; descriptions stay local.
 */
export interface EvidenceDrift {
  server: string;
  transport: "stdio" | "http";
  /** Which drift rule's kind of change: an update, tools added or removed, or a tool definition changed. */
  change: "updated" | "tools" | "definition";
  /** The change was announced while the server was in use. */
  mid_session: boolean;
  reported_version?: { from: string; to: string };
  installed_version?: { from: string; to: string };
  config_changed: boolean;
  tools_added: string[];
  tools_removed: string[];
  tools_changed: string[];
  /**
   * Tool list fingerprints, before and after, when the list changed. The
   * proxy keeps each full list on the machine under its fingerprint, so
   * the local dashboard can show what changed.
   */
  tool_list?: { from: string; to: string };
}

/** One line of a drift finding's change summary. */
export interface DriftSummaryRow {
  label: string;
  value: string;
}

const DRIFT_CHANGE_LABEL: Record<EvidenceDrift["change"], string> = {
  updated: "Server updated",
  tools: "Tools added or removed",
  definition: "Tool definitions changed",
};

/**
 * A drift finding's change summary as label and value rows, from the
 * finding alone. Both dashboards show it, so they say the same thing.
 */
export function driftSummaryRows(drift: EvidenceDrift): DriftSummaryRow[] {
  const rows: DriftSummaryRow[] = [
    { label: "Server", value: `${drift.server} (${drift.transport})` },
    { label: "Change", value: DRIFT_CHANGE_LABEL[drift.change] + (drift.mid_session ? ", announced while in use" : "") },
  ];
  if (drift.reported_version) rows.push({ label: "Reported version", value: `${drift.reported_version.from} to ${drift.reported_version.to}` });
  if (drift.installed_version) rows.push({ label: "Installed version", value: `${drift.installed_version.from} to ${drift.installed_version.to}` });
  if (drift.config_changed) rows.push({ label: "Configuration", value: "Its configuration entry changed" });
  if (drift.tools_added.length) rows.push({ label: "New tools", value: drift.tools_added.join(", ") });
  if (drift.tools_removed.length) rows.push({ label: "Dropped tools", value: drift.tools_removed.join(", ") });
  if (drift.tools_changed.length) rows.push({ label: "Changed tools", value: drift.tools_changed.join(", ") });
  return rows;
}

/**
 * The calls behind a finding and how they connect. Carried on findings from
 * rules that match a sequence of calls. It names credentials by kind only:
 * a credential's value is never part of it.
 */
export interface FindingEvidence {
  /**
   * The calls in order, ending with the one the finding is anchored on.
   * Empty on a drift finding, which has no call behind it.
   */
  steps: EvidenceStep[];
  /** On a drift finding: how the MCP server changed. */
  drift?: EvidenceDrift;
  /** Where the sink call went, when it reached an external host. */
  destination?: EvidenceDestination;
  credential?: EvidenceCredential;
  /** The destination had not been reached from this machine before. */
  first_seen_destination?: boolean;
  /** A routine reason the same calls can happen, from the rule. */
  benign_note?: string;
  /**
   * When the finding was made: as the last call was recorded ("capture"),
   * or by a later pass over the log ("background").
   */
  found_at?: "capture" | "background";
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
  /**
   * Tier of the rule that fired. Absent on findings recorded before it was
   * added; readers treat absence as "community".
   */
  rule_tier?: "community" | "advanced";
  /**
   * For rules that match a sequence of events: every tool_call_id in the
   * pattern, earliest first, ending with `related_event_id`. Absent for
   * single-event findings.
   */
  related_event_ids?: string[];
  /**
   * For rules that match a sequence of events: the role each call played,
   * with destination and credential kind. Its steps name the same calls as
   * related_event_ids. Absent for single-event findings and on findings
   * recorded before it was added.
   */
  evidence?: FindingEvidence;
  /** What enforcement made of this finding when it was captured. Absent in monitor mode and on older findings. */
  enforcement?: FindingEnforcement;
}

/**
 * Enforcement could not judge a call in time (rules failed to load, threw,
 * or ran past their time cap), so the call went ahead (the default) or was
 * stopped (enforcement.on_error "block"). Written only in guardrails mode.
 * Carries no captured content.
 */
export interface RiskEnforcementErrorEvent extends BaseEvent {
  event_type: "risk.enforcement_error";
  /** tool_call_id of the call that could not be judged. */
  related_event_id: string;
  reason: "timeout" | "error";
  outcome: "allowed" | "blocked";
}


/**
 * The user submitted a prompt: one per turn. The text is kept in full, as
 * tool parameters are, because the event log is meant to answer what the
 * agent was asked to do as well as what it did.
 */
export interface PromptSubmittedEvent extends BaseEvent {
  event_type: "prompt.submitted";
  prompt: string;
  /**
   * The runtime's own id for the turn, when it sends one (Claude Code's
   * prompt_id, Codex's turn_id). Groups the turn's tool calls.
   */
  prompt_id?: string;
}

/** The agent started a subagent. */
export interface SubagentStartedEvent extends BaseEvent {
  event_type: "subagent.started";
  /**
   * The runtime's id for the subagent; events inside it carry it too. On
   * subagent.started and subagent.stopped it names the subagent itself, not
   * where the event happened (runtimes do not nest subagents today).
   */
  agent_id: string;
  /** What kind of subagent, as the runtime names it (Explore, Plan, ...). */
  agent_type?: string;
}

/** A subagent finished and handed its result back. */
export interface SubagentStoppedEvent extends BaseEvent {
  event_type: "subagent.stopped";
  agent_id: string;
  agent_type?: string;
  /** Since the matching subagent.started, when the interceptor saw it. */
  duration_ms?: number;
  /** How the subagent ended, when the runtime says. */
  status?: "completed" | "errored" | "interrupted";
  /**
   * Byte size of the subagent's final message. The text itself is not
   * stored, as with tool responses.
   */
  response_bytes?: number;
}

/**
 * The runtime asked the user to allow an action. Not every tool call asks:
 * whether one does depends on the session's permission settings.
 */
export interface PermissionRequestedEvent extends BaseEvent {
  event_type: "permission.requested";
  tool_name: string;
  /** As on tool.invoked: the owning MCP server, or "builtin". */
  mcp_server: string;
  /** The tool's parameters, as on tool.invoked. */
  parameters: Record<string, unknown>;
  /** The tool call this is for, when the runtime sends its id. */
  tool_call_id?: string;
  /** The kind of permission asked for, when the runtime names it. */
  permission_type?: string;
}

/** The runtime refused an action: the user, a rule or a classifier said no. */
export interface PermissionDeniedEvent extends BaseEvent {
  event_type: "permission.denied";
  tool_name: string;
  mcp_server: string;
  parameters: Record<string, unknown>;
  tool_call_id?: string;
  /** Why, as the runtime puts it. */
  reason?: string;
}

// ---------------------------------------------------------------------------
// Cloud API types (used by license-client and sync-encryptor)
// ---------------------------------------------------------------------------

/** Sent by the local CLI to validate a subscription and retrieve tier info. */
export interface LicenseValidateRequest {
  api_token: string;
  client_version: string;
  interceptor_kind: InterceptorKind;
}

/** Returned by the cloud license endpoint. Cache locally for ttl_seconds. */
/** The key to one advanced rule bundle version, as the licence check returns it. */
export interface RuleBundleGrant {
  channel: string;
  bundle_version: string;
  /** Base64 AES-256 key that opens that bundle version. */
  content_key: string;
  /** When clients stop accepting that bundle. */
  not_after: string;
}

/** The key to one guardrails module version, as the license check returns it. */
export interface GuardrailsModuleGrant {
  /** The module interface version it implements. */
  interface: number;
  module_version: string;
  /** Base64 AES-256 key that opens that module version. */
  content_key: string;
  /** When clients stop accepting that module. */
  not_after: string;
}

export interface LicenseValidateResponse {
  customer_id: string;
  tier: "free" | "hosted" | "pro" | "enterprise";
  /** Enabled feature flags for this subscription. */
  features: string[];
  /**
   * The key to the current advanced rule bundle for this plan (Pro and
   * Enterprise with an active subscription, once a bundle is published).
   * The bundle itself is fetched separately, from /api/v1/rules/update.
   */
  rule_bundle?: RuleBundleGrant;
  /**
   * The key to the current guardrails module (Pro and Enterprise with an
   * active subscription, once a module is published). The module itself is
   * fetched separately, from /api/v1/guardrails/update.
   */
  guardrails_module?: GuardrailsModuleGrant;
  /** Presigned R2 URL for sync blob access (Hosted+). */
  sync_endpoint?: string;
  /** How long the caller may cache this response, in seconds. */
  ttl_seconds: number;
}

/**
 * End-to-end encrypted sync payload. The cloud never holds the
 * decryption key -- the passphrase-derived key stays client-side.
 */
export interface SyncPackage {
  blob_id: string;
  customer_id: string;
  /** AES-256-GCM ciphertext of the serialized session data. */
  encrypted_payload: ArrayBuffer;
  /** Initialization vector, fresh per sync operation. */
  iv: Uint8Array;
  /** Argon2id KDF salt stored alongside the blob. */
  kdf_salt: Uint8Array;
  payload_bytes: number;
  sessions_included: string[];
  /** Stable identifier for the source machine (SHA-256 of hostname). */
  machine_id: string;
  /** Optional human-readable label (e.g. "Work Laptop"). */
  machine_label?: string;
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
  /** Source machine identifier. */
  machine_id: string;
  /** Optional human-readable machine label. */
  machine_label?: string;
}

export interface RuleUpdatedEvent extends BaseEvent {
  event_type: "rule.updated";
  rules_updated: string[];
  source: "cloud" | "local";
}

// ---------------------------------------------------------------------------
// Capture pause markers (written when a person pauses or resumes capture)
// ---------------------------------------------------------------------------

/**
 * What a pause stops. `record`: nothing is captured. `sync`: events are
 * captured locally but never uploaded. `enforce`: rules stop blocking.
 */
export type CapturePauseKind = "record" | "sync" | "enforce";

/** Session id that carries pause markers, which belong to no agent session. */
export const CAPTURE_CONTROL_SESSION_ID = "omnodex-capture-control";

/**
 * A pause started. Markers carry no captured content, so they are written
 * and uploaded under every pause, and a pause shows as a gap rather than as
 * missing data.
 */
export interface CapturePausedEvent extends BaseEvent {
  event_type: "capture.paused";
  /** Same id on the matching capture.resumed. */
  pause_id: string;
  kind: CapturePauseKind;
  /** When the pause ends by itself, ISO 8601; null when only a resume ends it. */
  until: string | null;
  /** Host name of the machine that paused. */
  machine_label?: string;
}

/** A pause ended: resumed by a person, or its time ran out. */
export interface CaptureResumedEvent extends BaseEvent {
  event_type: "capture.resumed";
  pause_id: string;
  kind: CapturePauseKind;
  /** When the pause started, ISO 8601. */
  paused_at: string;
  reason: "command" | "expired" | "replaced";
  machine_label?: string;
}

/**
 * Capture pauses, each folded from its capture.paused and capture.resumed
 * markers into one row: the local dashboard's timeline and the synced
 * payload both show them, so a pause stays visible after the fact.
 */
export interface CapturePauseRow {
  pause_id: string;
  kind: CapturePauseKind;
  paused_at: string;
  /** When it ended; null while it is still in force. */
  resumed_at: string | null;
  /** When it was set to end by itself, if it had a duration. */
  until: string | null;
  /** How it ended: resumed by a person, ran out, or replaced by a new pause. */
  reason: "command" | "expired" | "replaced" | null;
  machine_label: string | null;
}

/**
 * One row per pause, oldest first. A pause can have two end markers when
 * two processes noticed its expiry; the earliest wins. An end marker
 * without its start (the start fell outside the log) still gives a row.
 */
export function capturePauseRows(events: Iterable<TraceEvent>): CapturePauseRow[] {
  const rows = new Map<string, CapturePauseRow>();
  for (const e of events) {
    if (e.event_type === "capture.paused") {
      const row = rows.get(e.pause_id);
      rows.set(e.pause_id, {
        pause_id: e.pause_id,
        kind: e.kind,
        paused_at: e.occurred_at,
        resumed_at: row?.resumed_at ?? null,
        until: e.until,
        reason: row?.reason ?? null,
        machine_label: e.machine_label ?? row?.machine_label ?? null,
      });
    } else if (e.event_type === "capture.resumed") {
      const row = rows.get(e.pause_id) ?? {
        pause_id: e.pause_id,
        kind: e.kind,
        paused_at: e.paused_at,
        resumed_at: null,
        until: null,
        reason: null,
        machine_label: e.machine_label ?? null,
      };
      if (row.resumed_at === null || e.occurred_at < row.resumed_at) {
        row.resumed_at = e.occurred_at;
        row.reason = e.reason;
      }
      rows.set(e.pause_id, row);
    }
  }
  return [...rows.values()].sort((a, b) => a.paused_at.localeCompare(b.paused_at));
}

// ---------------------------------------------------------------------------
// Monitoring change markers (written when Omnodex itself is installed,
// removed or reconfigured)
// ---------------------------------------------------------------------------

/**
 * What changed about monitoring on this machine. `exclude` and `include`
 * leave a project out of, or bring it back into, every-project recording;
 * `everywhere_on` and `everywhere_off` switch every-project recording.
 */
export type MonitoringAction =
  | "install"
  | "uninstall"
  | "update"
  | "exclude"
  | "include"
  | "everywhere_on"
  | "everywhere_off"
  | "connect"
  | "disconnect"
  | "enforce_mode"
  | "clear";

/**
 * Who made the change: a person at an interactive terminal, or a process
 * without one (a script, a fleet tool, or an agent's shell).
 */
export type MonitoringActor = "terminal" | "unattended";

/**
 * Omnodex was installed, removed or reconfigured. Written by the CLI for
 * every change it makes, under the capture-control session, so a removal
 * or a silence with no marker can be told apart from one that was made on
 * purpose. Carries no captured content and, like pause markers, is kept
 * and uploaded under every pause.
 */
export interface MonitoringChangedEvent extends BaseEvent {
  event_type: "monitoring.changed";
  action: MonitoringAction;
  /** Agent platform the change applies to, when it applies to one. */
  target?: string;
  /** Which part was installed or removed. */
  component?: "hooks" | "plugin" | "mcp";
  /** One project, or every project for this user. */
  scope?: "project" | "user";
  /** The project, for project-scope changes and exclusions. */
  project_path?: string;
  /** Value before and after: a version, an enforcement mode. */
  from?: string | null;
  to?: string | null;
  /** Omnodex version that made the change. */
  cli_version: string;
  actor: MonitoringActor;
  /** Host name of the machine. */
  machine_label?: string;
}

/** What the config check found wrong with one installation. */
export type MonitoringProblem =
  | "hooks_missing"
  | "hooks_disabled"
  | "plugin_missing"
  | "plugin_disabled"
  | "mcp_missing";

/**
 * An installation Omnodex recorded no longer matches the agent's real
 * config (our hook entry gone, hooks switched off, the plugin or MCP entry
 * removed), and no monitoring.changed marker explains it. Written by the
 * background config check under the capture-control session, kept and
 * uploaded under every pause. Names only Omnodex's own config locations.
 */
export interface MonitoringUnexplainedChangeEvent extends BaseEvent {
  event_type: "monitoring.unexplained_change";
  problem: MonitoringProblem;
  target: string;
  component: "hooks" | "plugin" | "mcp";
  scope: "project" | "user";
  project_path?: string;
  /** The agent config file or plugin directory that was checked. */
  file: string;
  /** Host name of the machine. */
  machine_label?: string;
}

/** A monitoring change as the dashboards and the synced payload carry it. */
export interface MonitoringChangeRow {
  event_id: string;
  at: string;
  action: MonitoringAction;
  target: string | null;
  component: "hooks" | "plugin" | "mcp" | null;
  scope: "project" | "user" | null;
  project_path: string | null;
  from: string | null;
  to: string | null;
  cli_version: string;
  actor: MonitoringActor;
  machine_label: string | null;
}

/** One row per monitoring.changed marker, oldest first. */
export function monitoringChangeRows(events: Iterable<TraceEvent>): MonitoringChangeRow[] {
  const rows: MonitoringChangeRow[] = [];
  for (const e of events) {
    if (e.event_type !== "monitoring.changed") continue;
    rows.push({
      event_id: e.event_id,
      at: e.occurred_at,
      action: e.action,
      target: e.target ?? null,
      component: e.component ?? null,
      scope: e.scope ?? null,
      project_path: e.project_path ?? null,
      from: e.from ?? null,
      to: e.to ?? null,
      cli_version: e.cli_version,
      actor: e.actor,
      machine_label: e.machine_label ?? null,
    });
  }
  return rows.sort((a, b) => a.at.localeCompare(b.at));
}

/** Discriminated union of every event type accepted by the event log. */
export type TraceEvent =
  | SessionStartedEvent
  | SessionEndedEvent
  | SessionRenamedEvent
  | SessionModelChangedEvent
  | ToolInvokedEvent
  | ToolCompletedEvent
  | FileReadEvent
  | FileWrittenEvent
  | RiskDetectedEvent
  | RiskEnforcementErrorEvent
  | PromptSubmittedEvent
  | SubagentStartedEvent
  | SubagentStoppedEvent
  | PermissionRequestedEvent
  | PermissionDeniedEvent
  | SyncPushedEvent
  | RuleUpdatedEvent
  | CapturePausedEvent
  | CaptureResumedEvent
  | MonitoringChangedEvent
  | MonitoringUnexplainedChangeEvent
  | ServerObservedEvent;

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

// Enforcement configuration shapes (modes, verdicts, overrides).
export * from "./enforcement.js";
