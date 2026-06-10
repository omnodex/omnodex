// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Self-protection detection rules.
 *
 * Rules detecting attempts by an agent to disable, modify, or remove
 * the Omnodex interceptor. A compromised agent or prompt injection
 * attack may attempt to neutralize monitoring before executing its
 * payload. These rules become critical when enforcement mode ships.
 *
 * RULE_SELF_PROTECTION_CONFIG_WRITE (HIGH)
 *   Fires when a Write/Edit targets Omnodex configuration files or
 *   the hook entries that register the interceptor.
 *
 * RULE_SELF_PROTECTION_BASH (HIGH)
 *   Fires when a bash command attempts to uninstall Omnodex, stop
 *   the interceptor, or manipulate the hook configuration via CLI.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_SELF_PROTECTION_CONFIG_WRITE: RuleDefinition = {
  rule_id: "RULE_SELF_PROTECTION_CONFIG_WRITE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          // Omnodex config directory
          regex: "(?:^|[/\\\\])\\.omnodex[/\\\\]",
          label: "Omnodex config directory",
        },
        {
          // Omnodex event log files (tampering with the audit trail)
          regex: "(?:^|[/\\\\])omnodex[_-]events\\.jsonl$",
          label: "Omnodex event log",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "self_protection",
  description_template:
    "Write to {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "Modifying Omnodex configuration or event logs could disable monitoring or tamper with the audit trail.",
  blocking_hint: "deny",
};

export const RULE_SELF_PROTECTION_BASH: RuleDefinition = {
  rule_id: "RULE_SELF_PROTECTION_BASH",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          // omnodex uninstall command
          regex: "\\bomnodex\\s+uninstall\\b",
          type: "omnodex-uninstall",
        },
        {
          // Removing omnodex hook entries from Claude Code settings via sed/jq
          regex: "(?:sed|jq)\\b[^\\n]*omnodex[^\\n]*(?:settings|hooks)",
          type: "omnodex-hook-removal",
        },
        {
          // Deleting omnodex files or directories
          regex: "\\brm\\b[^\\n]*(?:\\.omnodex|omnodex[_-]events)",
          type: "omnodex-file-deletion",
        },
        {
          // Killing omnodex processes
          regex: "\\b(?:kill|pkill|killall)\\b[^\\n]*omnodex",
          type: "omnodex-process-kill",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "self_protection",
  description_template:
    "Attempt to disable Omnodex detected via {{tool_name}}: {{credential_types}}. " +
    "An agent attempting to remove its own monitoring is a strong indicator of compromise.",
  blocking_hint: "deny",
};
