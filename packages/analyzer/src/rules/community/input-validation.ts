// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Input validation attack detection rules.
 *
 * RULE_INPUT_VALIDATION_SQL_INJECTION (HIGH)
 *   Fires when tool call parameters destined for a database-type MCP server
 *   contain recognizable SQL injection patterns. Two conditions must both
 *   match (AND semantics): the MCP server name must match a known database
 *   server pattern, AND the parameters must contain at least one of the
 *   SQL injection signatures below.
 *
 *   Covers the attack class documented by Akamai Security Research (2026):
 *   SQL injection (CVE-2025-66335), missing auth, and unauthenticated data
 *   exposure across Apache Doris, Pinot, and Alibaba RDS MCP servers.
 *   The MCP proxy intercepts tool calls at the transport layer, giving us
 *   visibility into query parameters before they reach the database engine.
 *
 * Source:
 *   Akamai Threat Research, "SQL Injection via MCP Tool Parameters" (2026).
 *   CVE-2025-66335 (Apache Doris MCP server, CVSS 9.8).
 *
 * Pro tier extension: obfuscation and encoding bypass variants (hex-encoded
 * SQL, double-URL-encoded payloads, comment-based keyword splitting) require
 * ML-assisted normalization and are planned for the advanced rule set.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

/**
 * Regex fragment matching MCP server names that are likely to be database
 * backends. Applied to the mcp_server field (case-insensitive).
 *
 * Intentionally broad: false negatives (a DB server with an unusual name)
 * are worse than false positives here because SQL injection in a DB context
 * is always high severity.
 */
const DB_SERVER_PATTERN =
  "(?:db|sql|database|postgres|pg|mysql|sqlite|mariadb|doris|pinot|rds|" +
  "bigquery|snowflake|mongo|athena|redshift|clickhouse|duckdb|supabase|neon)";

export const RULE_INPUT_VALIDATION_SQL_INJECTION: RuleDefinition = {
  rule_id: "RULE_INPUT_VALIDATION_SQL_INJECTION",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      // Scope detection to known database-type MCP servers to limit false
      // positives from SQL-like syntax in unrelated tools (e.g. a logging
      // server that happens to accept query strings).
      type: "tool_name_match",
      patterns: [
        {
          mcp_server_regex: DB_SERVER_PATTERN,
          label: "database MCP server",
        },
      ],
    },
    {
      // At least one of these SQL injection signatures must appear in the
      // JSON-serialized event parameters. The credential_match condition
      // applies flags "gi" (global, case-insensitive).
      type: "credential_match",
      patterns: [
        {
          // UNION-based injection: extracts data from other tables.
          regex: "\\bUNION\\s+(?:ALL\\s+)?SELECT\\b",
          type: "sql-union-inject",
        },
        {
          // Comment-based injection: terminates legitimate query.
          // Matches single-quote + semicolon + comment start: '; --  '; #  '; /*
          regex: "';\\s*(?:--|#|/\\*)",
          type: "sql-comment-inject",
        },
        {
          // Classic boolean tautology: OR 1=1, OR 1=1--, OR 1 = 1.
          // Uses \\b word boundaries to avoid matching inside identifiers.
          regex: "\\bOR\\s+1\\s*=\\s*1\\b",
          type: "sql-boolean-inject",
        },
        {
          // Stacked queries: terminates the current statement and injects
          // a destructive command. Matches: ; DROP TABLE  ; DELETE FROM etc.
          regex: ";\\s*\\b(?:DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\\b",
          type: "sql-stacked-query",
        },
        {
          // Time-based blind injection: SLEEP(), BENCHMARK(), PG_SLEEP().
          regex: "\\b(?:SLEEP|BENCHMARK|WAITFOR\\s+DELAY|PG_SLEEP)\\s*\\(",
          type: "sql-time-based-inject",
        },
        {
          // Out-of-band exfiltration via database-native HTTP/file functions.
          regex: "\\b(?:LOAD_FILE|UTL_HTTP|UTL_INADDR|UTL_FILE)\\s*\\(",
          type: "sql-oob-exfil",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "input_validation",
  description_template:
    "SQL injection pattern detected in {{mcp_server}} ({{tool_name}}): {{credential_types}}. " +
    "Tool parameters contain one or more SQL injection signatures.",
};
