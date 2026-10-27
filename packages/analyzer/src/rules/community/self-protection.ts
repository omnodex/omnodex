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
 *   the interceptor, pause recording or uploads, or manipulate the hook
 *   configuration via CLI. Pausing is for a person at a terminal; the
 *   CLI also refuses it without one. Also covers the agent's own CLI
 *   removing or disabling the Omnodex plugin or MCP server, and shell
 *   commands that delete, overwrite or reset an agent's hook file.
 *
 * RULE_SELF_PROTECTION_HOOK_REMOVED (HIGH)
 *   Fires when an edit to an agent's configuration takes out the Omnodex
 *   hook entry, MCP server entry or plugin enablement: the text is in what
 *   the edit replaces and not in what it writes. Matched on the entry
 *   itself, so a settings file moved with CLAUDE_CONFIG_DIR or CODEX_HOME
 *   is covered.
 *
 * RULE_SELF_PROTECTION_HOOKS_DISABLED (HIGH)
 *   Fires when an edit switches hooks off without touching the Omnodex
 *   entry: Claude Code's disableAllHooks, Codex's features.hooks = false
 *   (or the older codex_hooks key), or enabled: false on the Omnodex hook
 *   group in Antigravity's hooks.json.
 *
 * RULE_SELF_PROTECTION_HOOK_FILE_REWRITE (MEDIUM)
 *   Fires when an agent's hook file is written whole, or deleted, without
 *   the Omnodex entry. The earlier content is unknown, so this reports a
 *   possible removal: writing a project's first settings file looks the
 *   same.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

/**
 * The Omnodex entries an agent's configuration carries: the managed tag
 * and launcher names in hook entries, the MCP server entry, and plugin
 * enablement. Matched against edited text.
 */
const OMNODEX_ENTRIES = [
  {
    regex: "omnodex-managed|(?:claude|codex|antigravity)-hook-(?:launcher|shim)\\.js",
    label: "Omnodex hook entry",
  },
  {
    regex: "\\[mcp_servers\\.omnodex\\]|\"omnodex\"\\s*:\\s*\\{",
    label: "Omnodex MCP server entry",
  },
  {
    regex: "\"omnodex-(?:cowork|codex|antigravity)(?:@[^\"]*)?\"\\s*:\\s*true|\"name\"\\s*:\\s*\"omnodex-(?:cowork|codex|antigravity)\"",
    label: "Omnodex plugin",
  },
];

/**
 * Agents' hook files, as shell commands name them: default locations and
 * the CLAUDE_CONFIG_DIR / CODEX_HOME forms.
 */
const HOOK_FILE =
  "(?:\\.claude|\\$\\{?CLAUDE_CONFIG_DIR\\}?)[/\\\\]settings(?:\\.local)?\\.json" +
  "|(?:\\.codex|\\$\\{?CODEX_HOME\\}?)[/\\\\]hooks\\.json" +
  "|\\.gemini[/\\\\]config[/\\\\]hooks\\.json";

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
  version: "1.3.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      // Commands that run; text written into a script or config file is
      // reported one severity lower. Mentions in documents are ignored.
      scope: ["exec", "staged"],
      patterns: [
        {
          // Clearing the event log erases an agent's audit trail.
          regex: "\\bomnodex\\s+clear(?:\\s|$)",
          type: "omnodex-clear",
        },
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
        {
          // Pausing recording or uploads (resume is allowed)
          regex: "\\bomnodex\\s+(?:record|sync|enforce)\\s+pause\\b",
          type: "omnodex-capture-pause",
        },
        {
          // The agent's own CLI removing or disabling the Omnodex plugin or MCP server
          regex: "\\b(?:claude|codex|agy|antigravity)\\s+(?:plugin|plugins|mcp)\\s+(?:disable|uninstall|remove|rm)\\b[^\\n]*omnodex",
          type: "omnodex-plugin-removal",
        },
        {
          // Starting an agent with hooks switched off: Codex --disable hooks or
          // -c features.hooks=false, Claude Code --bare
          regex: "\\bcodex\\b[^\\n]*(?:--disable[=\\s]+[\"']?hooks\\b|-c\\s+[\"']?features\\.(?:codex_)?hooks\\s*=\\s*false)" +
            "|\\bclaude\\b[^\\n]*\\s--bare\\b",
          type: "agent-started-without-hooks",
        },
        {
          // Deleting an installed Omnodex plugin
          regex: "\\brm\\b[^\\n]*plugins[/\\\\]omnodex-(?:cowork|codex|antigravity)",
          type: "omnodex-plugin-deletion",
        },
        {
          // Deleting, truncating or resetting an agent's hook file
          regex: "\\b(?:rm|unlink|truncate|shred)\\b[^\\n]*(?:" + HOOK_FILE + ")" +
            "|\\bgit\\s+(?:checkout|restore)\\b[^\\n]*(?:" + HOOK_FILE + ")",
          type: "hook-file-reset",
        },
        {
          // Overwriting an agent's hook file: redirection, or cp/mv onto it
          regex: "(?:^|[^<>&\\d])>{1,2}\\s*[\"']?\\S*(?:" + HOOK_FILE + ")" +
            "|\\b(?:cp|mv)\\b[^\\n;&|]*\\s[\"']?\\S*(?:" + HOOK_FILE + ")[\"']?\\s*(?:$|[;&|\\n])",
          type: "hook-file-overwrite",
        },
        {
          // A Python or Node one-liner writing an agent's hook file
          regex: "\\b(?:python3?|node)\\s+-[ce]\\b[^\\n]*(?:" + HOOK_FILE + ")[^\\n]*(?:write|dump|open\\([^)]*[\"']w)" +
            "|\\b(?:python3?|node)\\s+-[ce]\\b[^\\n]*(?:write|dump|open\\([^)]*[\"']w)[^\\n]*(?:" + HOOK_FILE + ")",
          type: "hook-file-script-write",
        },
        {
          // Switching every hook off from the shell (jq, sed, echo)
          regex: "disableAllHooks[\"']?\\s*[:=]\\s*true",
          type: "hooks-disabled",
          // Direct settings changes already get the HIGH file-edit finding.
          // Keep this pattern for commands and scripts, and keep every other
          // shell pattern active in settings files.
          exclude_staged_paths: ["(?:^|/)settings(?:\\.local)?\\.json$"],
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

export const RULE_SELF_PROTECTION_HOOK_REMOVED: RuleDefinition = {
  rule_id: "RULE_SELF_PROTECTION_HOOK_REMOVED",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "file_edit",
      // Agent configuration is JSON or TOML; the entry itself identifies it.
      paths: [{ regex: "\\.(?:json|toml)$", label: "agent configuration" }],
      change: "removed",
      patterns: OMNODEX_ENTRIES,
    },
  ],
  severity: "HIGH",
  category: "self_protection",
  description_template:
    "{{tool_name}} removed the {{matched_label}} from {{matched_path}}. " +
    "Without it the agent's activity is no longer recorded; an agent taking out its own monitoring is a strong indicator of compromise.",
  blocking_hint: "deny",
};

export const RULE_SELF_PROTECTION_HOOKS_DISABLED: RuleDefinition = {
  rule_id: "RULE_SELF_PROTECTION_HOOKS_DISABLED",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "file_edit",
      // Any folder, so CLAUDE_CONFIG_DIR and CODEX_HOME are covered.
      paths: [
        { regex: "(?:^|/)settings(?:\\.local)?\\.json$", label: "Claude Code settings file" },
        { regex: "(?:^|/)config\\.toml$", label: "Codex config file" },
        { regex: "(?:^|/)hooks\\.json$", label: "hooks file" },
      ],
      change: "added",
      patterns: [
        { regex: "\"disableAllHooks\"\\s*:\\s*true", label: "disableAllHooks" },
        { regex: "(?:^|\\n)\\s*(?:features\\.)?(?:codex_)?hooks\\s*=\\s*false", label: "hooks = false" },
        {
          regex: "\"enabled\"\\s*:\\s*false[\\s\\S]{0,400}antigravity-hook-launcher|antigravity-hook-launcher[\\s\\S]{0,400}\"enabled\"\\s*:\\s*false",
          label: "enabled: false on the Omnodex hook group",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "self_protection",
  description_template:
    "{{tool_name}} set {{matched_label}} in {{matched_path}}, which switches off Omnodex's hooks. " +
    "The agent's activity stops being recorded while its configuration still looks intact.",
  blocking_hint: "deny",
};

export const RULE_SELF_PROTECTION_HOOK_FILE_REWRITE: RuleDefinition = {
  rule_id: "RULE_SELF_PROTECTION_HOOK_FILE_REWRITE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "file_edit",
      paths: [
        { regex: "(?:^|/)\\.codex/hooks\\.json$", label: "Codex hooks file" },
        { regex: "(?:^|/)\\.gemini/config/hooks\\.json$", label: "Antigravity hooks file" },
        { regex: "(?:^|/)\\.claude/settings(?:\\.local)?\\.json$", label: "Claude Code settings file" },
      ],
      change: "absent",
      patterns: [OMNODEX_ENTRIES[0]!],
      // A settings file with no hooks section is about something else.
      when: "\"hooks\"\\s*:|^$",
    },
  ],
  severity: "MEDIUM",
  category: "self_protection",
  description_template:
    "{{tool_name}} rewrote or deleted {{matched_path}} without the Omnodex hook entry. " +
    "If Omnodex was installed there, this removes it; a newly created file looks the same.",
  blocking_hint: "deny",
};
