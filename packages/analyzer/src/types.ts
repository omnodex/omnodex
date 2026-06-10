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

import type { EventType, RiskSeverity } from "@omnodex/shared";

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
   */
  description_template: string;
  /**
   * Intended blocking behavior when the Audit Firewall is active.
   *
   * - "deny"       -- block the action outright. Recommended for CRITICAL rules.
   * - "confirm"    -- pause execution and ask the human for confirmation. For HIGH rules.
   * - "alert_only" -- log and alert but never block. Default for lower-severity rules.
   *
   * Existing rules that omit this field are treated as "alert_only" until the Audit Firewall ships.
   * No runtime behavior change in the current analyzer.
   */
  blocking_hint?: "deny" | "confirm" | "alert_only";
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
  | CwdBoundaryCondition;

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
}

export interface PathPattern {
  /**
   * Regex pattern string (case-sensitive). Passed to new RegExp(regex).
   * Use standard JS regex escaping: literal backslash -> "\\", dot -> "\.".
   */
  regex: string;
  /** Human-readable label used in {{matched_label}} substitution. */
  label: string;
}

/**
 * Matches when at least one credential-like pattern is found in the
 * JSON-serialized event parameters. Yields a single MatchContext with
 * all matched credential types joined.
 */
export interface CredentialMatchCondition {
  type: "credential_match";
  patterns: CredentialPattern[];
}

export interface CredentialPattern {
  /**
   * Regex pattern string. Applied with flags "gi" (global, case-insensitive)
   * to JSON.stringify(event.parameters).
   */
  regex: string;
  /** Credential type label used in {{credential_types}} substitution. */
  type: string;
  /**
   * Index of the capture group whose value identifies the credential.
   * If omitted, the full match is used. The value itself is never stored;
   * only the type label is recorded in risk findings.
   */
  group?: number;
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
}

/** A single detection result produced by the rule engine. */
export interface RiskFinding {
  severity: RiskSeverity;
  category: string;
  /** Rendered description string (template variables already substituted). */
  description: string;
  rule_id: string;
}

/** Return value of detectRisks(). */
export interface DetectionResult {
  sessionId: string;
  /** New risk.detected events ready to be appended to the event log. */
  newEvents: import("@omnodex/shared").RiskDetectedEvent[];
  /** Existing detections that were skipped due to deduplication. */
  skipped: number;
}
