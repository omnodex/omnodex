// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Sandbox disable detection rules.
 *
 * Rules detecting attempts to weaken or disable the security sandbox
 * configuration of AI coding agents. Each major agent platform has its
 * own sandbox mechanism; a compromised session may attempt to disable
 * the sandbox to gain unrestricted execution.
 *
 * RULE_SANDBOX_DISABLE_SETTINGS_WRITE (HIGH)
 *   Fires when a Write/Edit tool call targets an agent settings file
 *   AND the content contains sandbox-disabling patterns. Covers:
 *   - Claude Code: settings.json with sandbox-related keys
 *   - Codex: config with sandbox/permissions bypass flags
 *   - Gemini CLI: config with sandbox_mode or execution settings
 *
 * RULE_SANDBOX_DISABLE_BASH (HIGH)
 *   Fires when a bash command attempts to disable sandboxing via
 *   command-line flags, environment variables, or file manipulation.
 *   Covers patterns like: --dangerously-skip-permissions,
 *   GEMINI_SANDBOX=none, sed/cp/mv targeting settings files.
 *
 * Sources:
 *   Prempti default ruleset (6 sandbox-disable rules, Apache 2.0)
 *   Adversa AI TrustFall research
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_SANDBOX_DISABLE_SETTINGS_WRITE: RuleDefinition = {
  rule_id: "RULE_SANDBOX_DISABLE_SETTINGS_WRITE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          // Claude Code settings files
          regex: "(?:^|[/\\\\])\\.claude[/\\\\]settings(?:\\.local)?\\.json$",
          label: "Claude Code settings file",
        },
        {
          // Codex config files
          regex: "(?:^|[/\\\\])\\.codex[/\\\\](?:config|settings)\\.(?:json|yaml|yml)$",
          label: "Codex config file",
        },
        {
          // Gemini CLI config
          regex: "(?:^|[/\\\\])\\.gemini[/\\\\](?:config|settings)\\.(?:json|yaml|yml)$",
          label: "Gemini CLI config file",
        },
      ],
    },
    {
      type: "credential_match",
      patterns: [
        {
          // Claude Code sandbox settings: "sandbox": false, "toolSandboxing": false
          regex: "(?:sandbox|toolSandboxing|allowUnsandboxed)\\b[^\\n]*(?:false|0|null|disabled|none)",
          type: "sandbox-disable-value",
        },
        {
          // Codex: --dangerously-skip-permissions or equivalent config
          regex: "(?:dangerously.?skip.?permissions|bypass.?permissions|skip.?sandbox)",
          type: "codex-permission-bypass",
        },
        {
          // Gemini: sandbox_mode: none/disabled/false
          regex: "(?:sandbox_mode|execution_mode)\\b[^\\n]*(?:none|disabled|false|unrestricted)",
          type: "gemini-sandbox-disable",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "sandbox_disable",
  description_template:
    "Sandbox disable attempt detected in {{matched_label}} ({{matched_path}}) via {{tool_name}}: {{credential_types}}. " +
    "Disabling the agent sandbox removes a critical security boundary.",
  blocking_hint: "deny",
};

export const RULE_SANDBOX_DISABLE_BASH: RuleDefinition = {
  rule_id: "RULE_SANDBOX_DISABLE_BASH",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          // Claude Code CLI flag
          regex: "--dangerously-skip-permissions\\b",
          type: "claude-skip-permissions-flag",
        },
        {
          // Codex CLI sandbox bypass flags
          regex: "\\bcodex\\b[^\\n]*(?:--full-auto|--danger-mode|--no-sandbox)\\b",
          type: "codex-sandbox-bypass-flag",
        },
        {
          // Gemini environment variable sandbox disable
          regex: "\\b(?:export\\s+)?GEMINI_(?:SANDBOX|SANDBOX_MODE)\\s*=\\s*(?:none|false|disabled|0)\\b",
          type: "gemini-env-sandbox-disable",
        },
        {
          // sed/cp/mv targeting agent settings files (postinstall-style persistence)
          regex: "(?:sed|cp|mv)\\b[^\\n]*(?:\\.claude[/\\\\]settings|\\.codex[/\\\\]config|\\.gemini[/\\\\]config)",
          type: "settings-file-replace",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "sandbox_disable",
  description_template:
    "Sandbox disable via shell command detected ({{tool_name}}): {{credential_types}}. " +
    "Command-line or environment-based sandbox bypass is a strong indicator of compromise.",
  blocking_hint: "deny",
};
