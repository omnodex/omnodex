// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/analyzer -- declarative rule definition types.
 *
 * Rules are pure data. No logic lives in a RuleDefinition; the RuleEngine
 * interprets conditions. This design makes rules serializable, diffable, and
 * eventually encryptable for the Pro-tier distribution pipeline.
 *
 */

import type { BlockingVerdict, EventType, RiskSeverity, SafeAlternative } from "@omnodex/shared";

// ---------------------------------------------------------------------------
// Rule definition
// ---------------------------------------------------------------------------

/**
 * A declarative risk rule. The engine evaluates all conditions against a
 * trace event and, when every condition matches, emits a RiskFinding.
 *
 * Tier notes:
 *   "community" -- bundled open-source, always active.
 *   "advanced"  -- requires a Pro or Enterprise subscription. Delivered
 *                  encrypted from the Omnodex license server and decrypted
 *                  locally. See RuleRegistry.loadAdvancedRules().
 */
export interface RuleDefinition {
  /** Stable unique identifier. Never reused across rule versions. */
  rule_id: string;
  /** Semantic version of this rule definition. */
  version: string;
  /** Subscription tier required to activate this rule. */
  tier: "community" | "advanced";
  /**
   * Event types this rule applies to. The engine skips events whose
   * event_type is not in this list, so rules only pay evaluation cost
   * for relevant event shapes.
   */
  event_types: EventType[];
  /**
   * Conditions that must ALL match for the rule to fire (AND semantics).
   *
   * Conditions may yield multiple match contexts -- for example, a
   * path_match condition yields one context per matched path. When a
   * condition yields N > 1 contexts and another yields M, the engine
   * takes the cross-product and emits N * M findings. In practice,
   * current rules have at most one multi-context condition, so the
   * cross-product is always 1-to-1.
   */
  conditions: Condition[];
  /** Severity of the emitted risk finding. */
  severity: RiskSeverity;
  /** Short classification tag (e.g. "sensitive_path_read"). */
  category: string;
  /**
   * Human-readable description with {{variable}} substitution.
   *
   * Available variables:
   *   {{tool_name}}        -- name of the tool that triggered detection
   *   {{mcp_server}}       -- MCP server the tool belongs to ("builtin" for
   *                           built-in tools like Read/Write/Bash)
   *   {{matched_path}}     -- file path that matched (path_match condition)
   *   {{matched_label}}    -- human label for the matched pattern
   *                           (path_match, tool_name_match conditions)
   *   {{credential_types}} -- comma-separated credential type labels
   *                           (credential_match condition)
   *   {{rate_count}}       -- number of events in the window when threshold
   *                           was crossed (rate_threshold condition)
   *   {{rate_window}}      -- window size in seconds (rate_threshold condition)
   *   {{matched_domain}}   -- hostname that matched (domain_match condition)
   *   {{matched_destination}} -- external host an outbound call reaches
   *                           (outbound_call condition); "an external endpoint"
   *                           when the call names none that can be read
   */
  description_template: string;
  /**
   * What the rule would do to a matching call when enforcement acts.
   *
   * - "deny"       -- block the action outright. Recommended for CRITICAL rules.
   * - "confirm"    -- hold the call for the human to confirm. For HIGH rules.
   * - "alert_only" -- log and alert but never block. Default for lower-severity rules.
   *
   * A rule that omits it is "alert_only". The hint is a candidate, not a
   * promise: shadow mode records it, but in guardrails it takes effect only
   * once the rule carries a `safe_alternative`. User and project overrides
   * apply either way (see resolveVerdict).
   */
  blocking_hint?: BlockingVerdict;
  /**
   * What the agent should do instead when this rule blocks a call. Sent to
   * the agent in the block reason. A rule needs one before its hint can
   * block a call by default.
   */
  safe_alternative?: SafeAlternative;
  /**
   * Severity when the match was in content written to a file (a "staged"
   * credential_match scope) rather than in a command that ran. Defaults to
   * one step below `severity`. Rules whose risk is the write itself, such as
   * a registry override in .npmrc, set it equal to `severity`.
   */
  staged_severity?: RiskSeverity;
  /**
   * A routine reason the matched calls can happen ("deploy scripts upload
   * configuration"). Carried in the evidence of findings on a sequence, so
   * the reader sees why the finding might be fine beside why it fired.
   */
  benign_note?: string;
}

// ---------------------------------------------------------------------------
// Condition types
// ---------------------------------------------------------------------------

export type Condition =
  | PathMatchCondition
  | CredentialMatchCondition
  | OutboundCallCondition
  | IpDestinationCondition
  | ToolNameMatchCondition
  | SessionFirstSeenCondition
  | RateThresholdCondition
  | DomainMatchCondition
  | CwdBoundaryCondition
  | SequenceCondition
  | StagingCondition
  | DestinationFirstSeenCondition
  | FileEditCondition;

/**
 * Matches when at least one file path extracted from the event matches at
 * least one of the supplied patterns. Yields one MatchContext per matched
 * path (so N matched paths -> N risk findings from this rule).
 *
 * Path extraction covers:
 *   - Standard parameter keys: file_path, path, filePath, filename
 *   - Bash command strings: cat, less, head, tail, cp, scp
 */
export interface PathMatchCondition {
  type: "path_match";
  /** At least one of these must match. */
  patterns: PathPattern[];
  /**
   * Which paths to test. "any" (the default) is every path the call names,
   * read or write. "write" is only what it writes to (see
   * extractWriteTargets), which is what a rule about planting something in a
   * file needs: reading that file is not planting anything. "read" is every
   * path except those, for a rule about data leaving: writing a file is not
   * reading what is in it.
   */
  access?: "any" | "write" | "read";
}

export interface PathPattern {
  /**
   * Regex pattern string (case-sensitive). Passed to new RegExp(regex).
   * Use standard JS regex escaping: literal backslash -> "\\", dot -> "\.".
   */
  regex: string;
  /** Human-readable label used in {{matched_label}} substitution. */
  label: string;
  /**
   * The credential type the file holds ("aws-key"), for a sequence step
   * that binds "credential": a later step sending it to that type's own
   * service is authentication, not movement.
   */
  credential_type?: string;
}

/**
 * Matches when at least one credential-like pattern is found in the
 * JSON-serialized event parameters. Yields a single MatchContext with
 * all matched credential types joined.
 */
export interface CredentialMatchCondition {
  type: "credential_match";
  patterns: CredentialPattern[];
  /**
   * Which text to scan. "all" (the default) is every parameter, which suits
   * secrets and payloads: a token is a leak wherever it appears. A list
   * narrows command patterns to what matters: "exec" is the command a shell
   * tool runs, "staged" is content written into a script or config file
   * (reported one severity lower unless the rule sets staged_severity), and
   * "target" is the file paths the call reads or writes. "sql" scans only
   * SQL statement parameters as raw strings, before JSON escaping.
   */
  scope?: CredentialScope;
  /**
   * "skip" drops a credential the call sends as authentication (a header or
   * the URL) when every host the call reaches belongs to the credential's
   * own service: that is the service being used, not the credential leaving.
   * Applies with scope "all". Omitted: every credential counts.
   */
  provider_auth?: "skip";
  /**
   * Only these type labels are reported. Patterns of other types still
   * claim the values they match first, so a rule can lead with another
   * rule's patterns and report only what those leave. Applies with scope
   * "all". Omitted: every type is reported.
   */
  report?: readonly string[];
}

export type CredentialScope = "all" | ReadonlyArray<"exec" | "staged" | "target" | "sql">;

export interface CredentialPattern {
  /**
   * Regex pattern string. Applied with flags "gi" (global, case-insensitive)
   * to JSON.stringify(event.parameters).
   */
  regex: string;
  /** Credential type label used in {{credential_types}} substitution. */
  type: string;
  /**
   * Skip this pattern in staged files whose forward-slash path matches any
   * of these regexes. Exec and other scopes are unaffected. Useful when a
   * dedicated file-edit rule already reports the direct settings change.
   */
  exclude_staged_paths?: readonly string[];
  /**
   * Index of the capture group whose value identifies the credential.
   * If omitted, the full match is used. The value itself is never stored;
   * only the type label is recorded in risk findings.
   */
  group?: number;
  /**
   * Check that the matched value is a secret, not text about one. "secret"
   * skips placeholders and variable references ("${TOKEN}", "<your key>",
   * "notarealtoken"), vendor documentation example keys, and values without
   * both letters and digits (prose such as "Bearer tokens"). "placeholder"
   * skips only placeholders and variable references, for secrets such as
   * passwords that can be letters alone. "prefixed" is for vendor formats
   * whose prefix and fixed length already mark a key, some of which are
   * letters alone: it skips placeholders by their words, runs and
   * references, and documentation keys, but not identifier-like values.
   * "generated" is for values with no vendor format: on top of "secret" it
   * needs enough variety of characters to look machine-made, and skips
   * hashes, UUIDs, integrity strings and file paths.
   * Omitted: every match counts.
   */
  check?: "secret" | "placeholder" | "prefixed" | "generated";
}

/**
 * Matches when the event looks like an outbound HTTP call. Acts as a guard:
 * yields one empty MatchContext if the event is outbound, nothing otherwise.
 *
 * Detection heuristics:
 *   - Tool name contains "fetch", "http", or "request"
 *   - Bash command contains curl, wget, http, or httpie
 *   - Parameters contain an external URL (non-localhost)
 */
export interface OutboundCallCondition {
  type: "outbound_call";
}

/**
 * Matches when the event targets a raw IPv4 address (rather than a hostname)
 * and classifies the IP by whether it falls within a known cloud provider
 * CIDR range. Supports two-tier network rules with different severities:
 *
 *   "in_known_cidr"      -- IP is within a known cloud provider range.
 *                           Lower severity: probably legit traffic but odd
 *                           to use a bare IP instead of a hostname.
 *   "not_in_known_cidr"  -- IP is outside all known ranges.
 *                           Higher severity: potential C2 or exfiltration.
 *
 * Yields one MatchContext per qualifying IP found in the event parameters.
 */
export interface IpDestinationCondition {
  type: "ip_destination";
  match: "in_known_cidr" | "not_in_known_cidr";
  /** CIDR notation strings (e.g. "52.0.0.0/8") for known cloud provider ranges. */
  known_cidrs: string[];
}

/**
 * Matches when the event's tool_name and/or mcp_server fields match one of
 * the supplied patterns. Useful for detecting tool name shadowing (an MCP
 * server registering a tool with the same name as a built-in) and other
 * structural tool identity attacks.
 *
 * Yields a single MatchContext with {{matched_label}} set to the label of
 * the first matching pattern. If both tool_name_regex and mcp_server_regex
 * are specified for a pattern, both must match.
 */
export interface ToolNameMatchCondition {
  type: "tool_name_match";
  patterns: ToolNamePattern[];
}

export interface ToolNamePattern {
  /**
   * Regex applied to the full tool_name field. Optional -- omit to match
   * any tool name (combine with mcp_server_regex to scope by server).
   */
  tool_name_regex?: string;
  /**
   * Regex applied to the mcp_server field. Optional -- omit to match any
   * MCP server.
   */
  mcp_server_regex?: string;
  /** Human-readable label used in {{matched_label}} substitution. */
  label: string;
}

/**
 * Stateful condition that fires the FIRST time a tracked field value is
 * seen within a session. Used to detect new MCP servers appearing mid-session
 * that were not present at session start.
 *
 * The RuleEngine maintains per-session seen sets internally, keyed by
 * session_id + track. State accumulates for the lifetime of the engine
 * instance. The engine is shared across multiple sessions in the streaming
 * loop, so session isolation is maintained by the session_id key.
 *
 * Yields a single empty MatchContext on first occurrence; yields nothing
 * on subsequent occurrences of the same value in the same session.
 *
 * Note: because seen sets grow for the engine's lifetime, long-running
 * processes should use one RuleEngine per session rather than a shared
 * instance if memory is a concern. The streaming loop's per-session tail
 * already provides this isolation in practice.
 */
export interface SessionFirstSeenCondition {
  type: "session_first_seen";
  /**
   * Which event field to track. "mcp_server" is the primary use case:
   * fire LOW when an MCP server invokes a tool for the first time in the
   * session.
   */
  track: "mcp_server" | "tool_name";
  /**
   * Values to skip entirely (never fire, never record as seen).
   * Use to exclude "builtin" from MCP server tracking since built-in
   * Claude Code tools always use mcp_server="builtin".
   */
  exclude?: string[];
  /**
   * "session" (the default): first time in this session. "machine": first
   * time on this machine, from a persistent store the host supplies (see
   * machine-state.ts); a server reached over a different transport or host
   * than recorded also counts. Without a store, "machine" behaves as
   * "session".
   */
  scope?: "session" | "machine";
}


/**
 * Stateful condition that fires when tool call frequency within a sliding
 * time window exceeds a threshold. Designed for OWASP LLM10 (Unbounded
 * Consumption) detection: runaway loops, recursive storms, resource abuse.
 *
 * The RuleEngine maintains per-session, per-rule state internally (timestamps
 * array + fired flag). State accumulates for the engine's lifetime.
 *
 * Fires once when the threshold is crossed. Suppresses subsequent findings
 * until the rate drops below threshold again (avoids N duplicate findings
 * for N events above threshold).
 *
 * Yields a single MatchContext with rate_count and rate_window populated
 * on first threshold crossing; empty array otherwise.
 */
export interface RateThresholdCondition {
  type: "rate_threshold";
  /** Sliding window size in seconds. */
  window_seconds: number;
  /** Number of events within the window that triggers a finding. */
  threshold: number;
}

/**
 * Matches when a URL found in the event parameters targets a domain in (or
 * not in) a supplied list. Supports exact hostname matching and wildcard
 * subdomain matching: listing "chase.com" matches "chase.com" and any
 * subdomain ("online.chase.com", "secure.chase.com", etc.).
 *
 * Domain extraction covers the same sources as outbound_call: URL parameters
 * and bash command strings (curl, wget, etc.).
 *
 * Yields one MatchContext per matched URL hostname with {{matched_domain}}
 * populated. An empty array means no match (the condition fails).
 */
export interface DomainMatchCondition {
  type: "domain_match";
  /** Whether to fire when a domain IS in the list (in_list) or is NOT in the list (not_in_list). */
  match: "in_list" | "not_in_list";
  /**
   * Domains to test against. Each entry is an apex domain (e.g. "chase.com").
   * Both exact matches and wildcard subdomains are matched:
   *   "chase.com" matches "chase.com" and "online.chase.com".
   */
  domains: string[];
}

/**
 * Matches when a file path extracted from the event is outside the
 * session's working directory (cwd). Requires the event to have cwd
 * populated; events without cwd never match this condition.
 *
 * This is a guard condition with no configuration: if cwd is present
 * and any extracted path falls outside it, the condition fires.
 *
 * Yields one MatchContext per outside-cwd path with matched_path and
 * matched_label populated.
 */
export interface CwdBoundaryCondition {
  type: "cwd_boundary";
  /**
   * "any" (the default) judges every path the call names; "write" only the
   * files it writes to (see extractWriteTargets).
   */
  access?: "any" | "write";
}

/**
 * Facts about the machine an event is judged on, supplied by the host so
 * conditions stay pure functions of the event.
 */
export interface EvaluationContext {
  /** Directories that count as the session's workspace. Defaults to [cwd]. */
  workspaceRoots?: readonly string[];
  /** The user's home directory, for expanding ~ in paths. */
  home?: string;
  /** Persistent state for machine-scope rules. */
  machineState?: import("./machine-state.js").MachineState;
  /** How the event's MCP server is reached, when its session recorded it. */
  mcpServerTransport?: import("@omnodex/shared").McpServerTransport;
}

/**
 * Stateful condition for patterns that exist only across events: it
 * matches when an earlier tool.invoked event in the same session satisfied
 * every condition in `prior`. The rule's other conditions apply to the
 * current event, so the rule reads as "this event, after that one" (for
 * example, an outbound call after a credential file was read).
 *
 * The engine keeps a bounded window of each session's recent events for
 * this. `prior` conditions must be stateless. The finding cites the earlier
 * event as well as the current one (RiskDetectedEvent.related_event_ids).
 *
 * Yields a single MatchContext naming the most recent qualifying earlier
 * event, or nothing.
 */
export interface SequenceCondition {
  type: "sequence";
  /**
   * Conditions an earlier event must all satisfy. Stateless types only.
   * The two-step form: the earlier event is the source, the current one
   * the sink. Ignored when `steps` is given.
   */
  prior?: Condition[];
  /**
   * The ordered form: each step matched by a later event than the one
   * before, the last step by the current event. Steps can bind values a
   * later step must carry, so "read, then encode that file, then send the
   * encoded file" is one rule.
   */
  steps?: SequenceStep[];
  /** Look back at most this many earlier events (capped by the engine's window). */
  within_events?: number;
  /** Look back at most this many seconds before the current event. */
  within_seconds?: number;
}

/**
 * Values a step can bind for later steps:
 *   "path"       -- the file the step matched or read
 *   "output"     -- the file a staging step wrote (archive, encoded copy)
 *   "credential" -- credentials the step's credential_match found: their
 *                   values, kept in memory to match against later calls
 *                   and never recorded, and their types
 */
export type SequenceBinding = "path" | "output" | "credential";

export interface SequenceStep {
  /** The role the matching call plays in the finding's evidence. */
  as: import("@omnodex/shared").EvidenceRole;
  /** Conditions the call must all satisfy. Stateless types only. */
  match: Condition[];
  /** The step may be absent; when present it is recorded in the evidence. */
  optional?: boolean;
  /** Values this step makes available to later steps. */
  bind?: SequenceBinding[];
  /**
   * The call must name at least one value bound under these keys by an
   * earlier step, in its command or parameters.
   */
  carries?: SequenceBinding[];
  /**
   * With `carries`: the carried value must be used in one of these ways
   * (a request body, a URL, an argument...). Authentication headers are
   * how a credential is meant to be used, so a movement rule leaves them out.
   */
  carried_as?: import("./action.js").CredentialRole[];
  /**
   * Skip the call when it goes to the service a bound credential belongs
   * to (a GitHub token sent to api.github.com): that is the credential
   * being used, not moved.
   */
  exclude_credential_provider?: boolean;
}

/**
 * Matches when the call reaches an external host no call from this machine
 * had reached before (see machine-state.ts). Needs the host's machine
 * state, so only hosts that keep one run it; without one it never matches.
 * Yields one context naming the new host as {{matched_destination}}.
 */
export interface DestinationFirstSeenCondition {
  type: "destination_first_seen";
}

/**
 * Matches when the call archives, encodes, encrypts or copies data to the
 * clipboard (see the normalized action's staging steps). Yields one context
 * naming the staged output when the command names one.
 */
/**
 * Matches on what a file-writing call does to the text of a file, per file
 * (see conditions/file-edit.ts). "removed": a pattern is in the replaced
 * text and not in the new text. "added": in the new text and not the
 * replaced text. "absent": the call writes the whole file without it.
 * Yields one context per matching file, with {{matched_path}} and the
 * pattern's {{matched_label}}.
 */
export interface FileEditCondition {
  type: "file_edit";
  /** Files this applies to; tested against the path with forward slashes. */
  paths: PathPattern[];
  change: "removed" | "added" | "absent";
  /** At least one must match; the first that does names the finding. */
  patterns: { regex: string; label: string }[];
  /** Only files whose new text matches this. Omitted: every file. */
  when?: string;
}

export interface StagingCondition {
  type: "staging";
  /** Only these operations. Omitted: any. */
  ops?: import("./action.js").StagingOp[];
}

// ---------------------------------------------------------------------------
// Engine-internal types
// ---------------------------------------------------------------------------

/**
 * Context captured when a condition matches. Used to populate description
 * template variables. Fields are optional because not every condition
 * populates every field.
 */
export interface MatchContext {
  /** Always populated from the triggering event. */
  tool_name: string;
  /** Always populated from the triggering event. */
  mcp_server: string;
  /** Populated by path_match conditions. */
  matched_path?: string;
  /** Populated by path_match and tool_name_match conditions. */
  matched_label?: string;
  /** Populated by credential_match conditions. */
  credential_types?: string[];
  /**
   * Populated by credential_match conditions: what matched, values
   * included, for sequence bindings. Never rendered or recorded.
   */
  credential_sightings?: { type: string; value: string }[];
  /** Populated by path_match when the matched pattern names a credential type. */
  path_credential_type?: string;
  /** Populated by staging conditions: the file the staging step wrote. */
  staging_output?: string;
  /** Populated by destination_first_seen: the destination is new to this machine. */
  first_seen_destination?: boolean;
  /** Populated by ip_destination conditions. */
  matched_ip?: string;
  /** Populated by ip_destination conditions ("cloud provider" or "unknown host"). */
  ip_classification?: string;
  /** Populated by rate_threshold conditions: number of events in window. */
  rate_count?: number;
  /** Populated by rate_threshold conditions: window size in seconds. */
  rate_window?: number;
  /** Populated by domain_match conditions: the matched hostname. */
  matched_domain?: string;
  /** Populated by outbound_call conditions: the external host the call reaches, when known. */
  matched_destination?: string;
  /** Populated by staged credential_match: the file the content was written to. */
  staged_path?: string;
  /** Populated by sequence conditions: the earlier events that matched, oldest first. */
  sequence_steps?: SequenceStepMatch[];
  /** Populated by the steps form: the role the current event plays. */
  sequence_role?: import("@omnodex/shared").EvidenceRole;
  /** Populated by the steps form: the credential the chain carried, for evidence. */
  sequence_credential?: import("@omnodex/shared").EvidenceCredential;
}

/** An earlier event a sequence condition matched, and what matched on it. */
export interface SequenceStepMatch {
  event: import("@omnodex/shared").ToolInvokedEvent;
  role: import("@omnodex/shared").EvidenceRole;
  context: Partial<MatchContext>;
}

/** A single detection result produced by the rule engine. */
export interface RiskFinding {
  severity: RiskSeverity;
  category: string;
  /** Rendered description string (template variables already substituted). */
  description: string;
  rule_id: string;
  /** Tier of the rule that fired. */
  tier: "community" | "advanced";
  /** Earlier events a sequence rule matched, in addition to the current one. */
  related_event_ids?: string[];
  /** For a sequence rule, every matched call with its role, ending with the current one; for a single call to a first-seen destination, that call. */
  evidence?: import("@omnodex/shared").FindingEvidence;
}

/** Return value of detectRisks(). */
export interface DetectionResult {
  sessionId: string;
  /** New risk.detected events ready to be appended to the event log. */
  newEvents: import("@omnodex/shared").RiskDetectedEvent[];
  /** Existing detections that were skipped due to deduplication. */
  skipped: number;
  /** tool.invoked events judged in this call (all of the session's, each run). */
  evaluated: number;
  /** Whether advanced rules were among the rules that judged them. */
  advancedActive: boolean;
}
