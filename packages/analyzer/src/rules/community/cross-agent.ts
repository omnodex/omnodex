// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Cross-agent security detection rules.
 *
 * RULE_CROSS_AGENT_AUTH_ACCESS (HIGH)
 *   Fires when an agent accesses authentication or credential files
 *   belonging to a different AI agent platform. For example, Claude Code
 *   reading Cursor's auth tokens, or Codex reading Gemini CLI's
 *   credentials. This cross-pollination is a supply chain attack vector:
 *   a compromised agent session on one platform can harvest credentials
 *   for other platforms the developer uses.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_CROSS_AGENT_AUTH_ACCESS: RuleDefinition = {
  rule_id: "RULE_CROSS_AGENT_AUTH_ACCESS",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          // Cursor authentication and config paths
          regex: "(?:^|[/\\\\])(?:\\.cursor[/\\\\]|\\.cursor-server[/\\\\]).*(?:auth|token|credential|session|key)",
          label: "Cursor auth file",
        },
        {
          // Windsurf / Codeium authentication paths
          regex: "(?:^|[/\\\\])\\.windsurf[/\\\\].*(?:auth|token|credential|session)",
          label: "Windsurf auth file",
        },
        {
          // Gemini CLI authentication paths
          regex: "(?:^|[/\\\\])\\.gemini[/\\\\].*(?:auth|token|credential|key|cookie)",
          label: "Gemini CLI auth file",
        },
        {
          // OpenAI Codex authentication paths
          regex: "(?:^|[/\\\\])\\.codex[/\\\\].*(?:auth|token|credential|key)",
          label: "Codex auth file",
        },
        {
          // GitHub Copilot authentication paths (VS Code extension storage)
          regex: "(?:^|[/\\\\])github-copilot[/\\\\].*(?:auth|token|key|hosts\\.json)",
          label: "GitHub Copilot auth file",
        },
        {
          // Aider authentication config
          regex: "(?:^|[/\\\\])\\.aider\\.conf\\.yml$",
          label: "Aider config (may contain API keys)",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "cross_agent",
  description_template:
    "Access to {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "An agent accessing another platform's credentials is a cross-agent supply chain risk.",
  blocking_hint: "deny",
};
