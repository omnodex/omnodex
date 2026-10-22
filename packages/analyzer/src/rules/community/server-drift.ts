// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_MCP_SERVER_UPDATED, RULE_MCP_SERVER_TOOLS_CHANGED,
 * RULE_MCP_TOOL_DEFINITION_CHANGED
 *
 * An MCP server a user approved once keeps running whatever its publisher
 * ships next, and an agent acts on the descriptions in its tool list. These
 * rules compare each server.observed event from the MCP proxy with the last
 * observation of the same server on this machine and report what changed.
 * The newer observation becomes the baseline, so each change is reported
 * once. A server's first observation is its baseline; first use is reported
 * by RULE_SUPPLY_CHAIN_NEW_MCP_SERVER.
 *
 * RULE_MCP_SERVER_UPDATED (LOW)
 *   The version the server reports, the installed package version, or its
 *   configuration entry changed. Usually a routine update; the finding lists
 *   any tool changes that came with it.
 *
 * RULE_MCP_SERVER_TOOLS_CHANGED (LOW)
 *   Tools were added or removed while the version and configuration stayed
 *   the same.
 *
 * RULE_MCP_TOOL_DEFINITION_CHANGED (MEDIUM)
 *   A tool's description or input schema changed while the version and
 *   configuration stayed the same: what the agent is told about a tool
 *   changed without a release that would explain it.
 *
 * Limits: only servers reached through the MCP proxy are observed; a change
 * to a server's code that leaves its tools, version and configuration alone
 * is not visible here; the reported version is whatever the server says.
 *
 * Tier:     community
 * Severity: LOW / LOW / MEDIUM
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_MCP_SERVER_UPDATED: RuleDefinition = {
  rule_id: "RULE_MCP_SERVER_UPDATED",
  version: "1.0.0",
  tier: "community",
  event_types: ["server.observed"],
  conditions: [{ type: "server_drift", change: "updated" }],
  severity: "LOW",
  category: "supply_chain",
  description_template:
    "MCP server {{mcp_server}} changed since this machine last saw it: {{matched_label}}.",
};

export const RULE_MCP_SERVER_TOOLS_CHANGED: RuleDefinition = {
  rule_id: "RULE_MCP_SERVER_TOOLS_CHANGED",
  version: "1.0.0",
  tier: "community",
  event_types: ["server.observed"],
  conditions: [{ type: "server_drift", change: "tools" }],
  severity: "LOW",
  category: "supply_chain",
  description_template:
    "MCP server {{mcp_server}} changed its tools without a version or configuration change: {{matched_label}}.",
};

export const RULE_MCP_TOOL_DEFINITION_CHANGED: RuleDefinition = {
  rule_id: "RULE_MCP_TOOL_DEFINITION_CHANGED",
  version: "1.0.0",
  tier: "community",
  event_types: ["server.observed"],
  conditions: [{ type: "server_drift", change: "definition" }],
  severity: "MEDIUM",
  category: "supply_chain",
  description_template:
    "MCP server {{mcp_server}} changed what these tools tell the agent, without a version or configuration change: {{matched_label}}. Review the new descriptions before relying on them.",
};
