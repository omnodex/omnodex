// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
/**
 * Risk detector -- the seed of the Omnodex analyzer.
 *
 * Scans tool.invoked events in the event log for known risk patterns and
 * emits risk.detected events back into the log. This is the batch version;
 * the future streaming detector will run the same rules against events as
 * they arrive.
 *
 * Design:
 *
 *   1. Read all events for a session.
 *   2. Collect existing risk.detected event_ids so we can skip duplicates.
 *   3. For each tool.invoked event, run all rules.
 *   4. Deduplicate: skip if a risk event with the same rule_id +
 *      related_event_id already exists in the log.
 *   5. Return the new risk events (caller appends to the log).
 *
 * Rules are hardcoded for now. A future analyzer package will introduce a
 * rule definition format so rules become data, not code.
 */

import type {
  RiskDetectedEvent,
  RiskSeverity,
  ToolInvokedEvent,
  TraceEvent,
} from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

// ---------------------------------------------------------------------------
// Rule interface
// ---------------------------------------------------------------------------

export interface RiskRule {
  rule_id: string;
  /** Runs against a single tool.invoked event. Returns zero or more detections. */
  check(event: ToolInvokedEvent): RiskFinding[];
}

export interface RiskFinding {
  severity: RiskSeverity;
  category: string;
  description: string;
}

// ---------------------------------------------------------------------------
// Sensitive path patterns
// ---------------------------------------------------------------------------

const SENSITIVE_PATH_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^\/etc\/passwd$/,            label: "/etc/passwd" },
  { pattern: /^\/etc\/shadow$/,            label: "/etc/shadow" },
  { pattern: /^\/etc\/sudoers/,            label: "/etc/sudoers" },
  { pattern: /^\/etc\/ssh\//,              label: "/etc/ssh/ config" },
  { pattern: /^\/root\//,                  label: "/root/ directory" },
  { pattern: /[/\]\.ssh[/\]/,            label: ".ssh directory" },
  { pattern: /[/\]\.env$/,                label: ".env file" },
  { pattern: /[/\]\.env\.[^/\]+$/,       label: ".env file" },
  { pattern: /[/\]\.aws[/\]credentials/, label: "AWS credentials" },
  { pattern: /[/\]\.gcloud[/\]/,         label: "GCloud config" },
  { pattern: /[/\]\.kube[/\]config/,     label: "Kubernetes config" },
  { pattern: /\.pem$/,                     label: "PEM private key" },
  { pattern: /id_rsa/,                     label: "SSH private key" },
  { pattern: /id_ed25519/,                 label: "SSH private key" },
];

/**
 * Extract file paths from a tool invocation. Handles both builtin tools
 * (Read, Write, Glob, Grep) and MCP filesystem tools (read_file, etc.).
 */
function extractPaths(event: ToolInvokedEvent): string[] {
  const params = event.parameters;
  const paths: string[] = [];

  // Builtin and MCP filesystem tools use various key names for paths.
  for (const key of ["file_path", "path", "filePath", "filename"]) {
    const val = params[key];
    if (typeof val === "string" && val.length > 0) paths.push(val);
  }

  // Bash commands: extract paths from the command string heuristically.
  if (typeof params.command === "string") {
    const cmd = params.command;
    // Match common file-reading commands followed by a path.
    const cmdPatterns = [
      /cat\s+([^\s|;&]+)/g,
      /less\s+([^\s|;&]+)/g,
      /head\s+(?:-\S+\s+)*([^\s|;&]+)/g,
      /tail\s+(?:-\S+\s+)*([^\s|;&]+)/g,
      /cp\s+(?:-\S+\s+)*([^\s|;&]+)/g,
      /scp\s+(?:-\S+\s+)*([^\s|;&]+)/g,
    ];
    for (const re of cmdPatterns) {
      let m;
      while ((m = re.exec(cmd)) !== null) {
        if (m[1]) paths.push(m[1]);
      }
    }
  }

  return paths;
}

// ---------------------------------------------------------------------------
// Credential patterns (mirrors the dashboard's client-side detection)
// ---------------------------------------------------------------------------

interface CredentialMatch {
  type: string;
  value: string;
}

const CREDENTIAL_PATTERNS: Array<{
  pattern: RegExp;
  type: string;
  group?: number;
}> = [
  { pattern: /Bearer\s+([A-Za-z0-9_\-.]+)/g,                                  type: "bearer",   group: 1 },
  { pattern: /sk_live_[A-Za-z0-9_-]+/g,                                        type: "api-key"            },
  { pattern: /sk_test_[A-Za-z0-9_-]+/g,                                        type: "api-key"            },
  { pattern: /api[_-]?key["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})/gi,          type: "api-key",  group: 1 },
  { pattern: /token["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})/gi,                type: "token",    group: 1 },
  { pattern: /password["']?\s*[:=]\s*["']?([^\s"',}]{4,})/gi,                  type: "password", group: 1 },
  { pattern: /ghp_[A-Za-z0-9]{36,}/g,                                          type: "github-pat"         },
  { pattern: /xoxb-[A-Za-z0-9-]+/g,                                            type: "slack-bot"          },
  { pattern: /AKIA[A-Z0-9]{16}/g,                                              type: "aws-key"            },
];

function findCredentials(text: string): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  for (const { pattern, type, group } of CREDENTIAL_PATTERNS) {
    // Reset the regex (they are global).
    const re = new RegExp(pattern.source, pattern.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = group !== undefined ? m[group] : m[0];
      if (value) matches.push({ type, value });
    }
  }
  return matches;
}

/**
 * Heuristic: does this tool call look like it is sending data to an
 * external endpoint? Checks tool name and parameters for URL patterns.
 */
function isOutboundCall(event: ToolInvokedEvent): boolean {
  const name = event.tool_name.toLowerCase();

  // MCP fetch tools.
  if (name.includes("fetch") || name.includes("http") || name.includes("request")) {
    return true;
  }

  // Bash commands with curl/wget/httpie.
  if (name === "bash" && typeof event.parameters.command === "string") {
    const cmd = event.parameters.command;
    if (/(curl|wget|http|httpie)/.test(cmd)) return true;
  }

  // Parameters that contain URLs.
  const paramStr = JSON.stringify(event.parameters);
  if (/https?:\/\/[^\s"']+/.test(paramStr)) {
    // Only flag external URLs, not localhost/127.0.0.1.
    const urlMatch = paramStr.match(/https?:\/\/([^\s"'/]+)/);
    if (urlMatch) {
      const host = urlMatch[1].toLowerCase();
      if (!host.startsWith("localhost") && !host.startsWith("127.0.0.1") && !host.startsWith("[::1]")) {
        return true;
      }
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------

const RULE_SENSITIVE_PATH_READ: RiskRule = {
  rule_id: "RULE_SENSITIVE_PATH_READ",
  check(event: ToolInvokedEvent): RiskFinding[] {
    const paths = extractPaths(event);
    const findings: RiskFinding[] = [];

    for (const p of paths) {
      for (const { pattern, label } of SENSITIVE_PATH_PATTERNS) {
        if (pattern.test(p)) {
          findings.push({
            severity: "HIGH",
            category: "sensitive_path_read",
            description: `Session accessed ${label} (${p}), a sensitive system path.`,
          });
          break; // One finding per path is enough.
        }
      }
    }
    return findings;
  },
};

const RULE_CREDENTIAL_IN_PARAMS: RiskRule = {
  rule_id: "RULE_CREDENTIAL_IN_PARAMS",
  check(event: ToolInvokedEvent): RiskFinding[] {
    const paramStr = JSON.stringify(event.parameters);
    const creds = findCredentials(paramStr);
    if (creds.length === 0) return [];

    // Summarize what was found without repeating the actual secret.
    const types = [...new Set(creds.map((c) => c.type))];
    return [
      {
        severity: "MEDIUM",
        category: "credential_exposure",
        description: `Credential(s) found in tool parameters for ${event.tool_name}: ${types.join(", ")}.`,
      },
    ];
  },
};

const RULE_CREDENTIAL_EXFILTRATION: RiskRule = {
  rule_id: "RULE_CREDENTIAL_EXFIL",
  check(event: ToolInvokedEvent): RiskFinding[] {
    if (!isOutboundCall(event)) return [];

    const paramStr = JSON.stringify(event.parameters);
    const creds = findCredentials(paramStr);
    if (creds.length === 0) return [];

    const types = [...new Set(creds.map((c) => c.type))];
    return [
      {
        severity: "CRITICAL",
        category: "credential_exfiltration",
        description: `Credential(s) transmitted to external endpoint via ${event.tool_name}: ${types.join(", ")}.`,
      },
    ];
  },
};

/** All active rules. */
export const RULES: RiskRule[] = [
  RULE_SENSITIVE_PATH_READ,
  RULE_CREDENTIAL_IN_PARAMS,
  RULE_CREDENTIAL_EXFILTRATION,
];

// ---------------------------------------------------------------------------
// Detector: runs rules against a session's events
// ---------------------------------------------------------------------------

export interface DetectionResult {
  sessionId: string;
  newEvents: RiskDetectedEvent[];
  /** Number of existing risk events that were skipped (already detected). */
  skipped: number;
}

/**
 * Run all rules against events for a single session.
 *
 * @param events     All events for the session (in log order).
 * @param newEventId A function that produces unique event IDs.
 * @returns          New risk.detected events to append (deduplicated).
 */
export function detectRisks(
  events: TraceEvent[],
  newEventId: () => string,
): DetectionResult {
  const sessionId = events[0]?.session_id ?? "unknown";

  // Build a set of existing (rule_id, related_event_id) pairs for dedup.
  const existing = new Set<string>();
  for (const e of events) {
    if (e.event_type === "risk.detected") {
      existing.add(`${e.rule_id}::${e.related_event_id}`);
    }
  }

  const newEvents: RiskDetectedEvent[] = [];
  let skipped = 0;

  for (const event of events) {
    if (event.event_type !== "tool.invoked") continue;

    for (const rule of RULES) {
      const findings = rule.check(event);
      for (const finding of findings) {
        const dedupKey = `${rule.rule_id}::${event.tool_call_id}`;
        if (existing.has(dedupKey)) {
          skipped++;
          continue;
        }
        existing.add(dedupKey); // Prevent intra-run duplicates too.

        const now = new Date().toISOString();
        newEvents.push({
          schema_version: SCHEMA_VERSION,
          event_id: newEventId(),
          session_id: event.session_id,
          occurred_at: now,
          recorded_at: now,
          interceptor: "analyzer",
          event_type: "risk.detected",
          severity: finding.severity,
          category: finding.category,
          description: finding.description,
          related_event_id: event.tool_call_id,
          rule_id: rule.rule_id,
        });
      }
    }
  }

  return { sessionId, n
