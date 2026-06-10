// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Supply chain attack detection rules.
 *
 * Four rules that together cover the primary supply chain attack patterns
 * documented in the ClawSwarm incident (April 2026) and the elementary-data
 * PyPI compromise (April 2026).
 *
 * RULE_SUPPLY_CHAIN_TOOL_SHADOW (HIGH)
 *   Fires when an MCP-namespaced tool has a name that exactly matches a
 *   Claude Code built-in (read, write, edit, bash, etc.). A malicious MCP
 *   server registering a tool with the same name as a built-in can cause
 *   the model to call the imposter instead of the real tool, leaking context
 *   and enabling privilege escalation.
 *
 * RULE_SUPPLY_CHAIN_NEW_MCP_SERVER (LOW)
 *   Fires the first time each non-builtin MCP server invokes a tool within
 *   a session. Provides an audit trail of every MCP server active in a
 *   session. A new server appearing mid-session (after other servers have
 *   already been used) may indicate dynamic plugin injection via prompt
 *   injection or compromised skill installation.
 *
 * RULE_SUPPLY_CHAIN_SKILL_MANIPULATION (HIGH)
 *   Fires when tool parameters suggest the agent is being directed to
 *   install or load new plugins/skills, inject MCP server definitions into
 *   Claude Code settings, or redirect package manager configuration to
 *   attacker-controlled registries system-wide.
 *
 * RULE_SUPPLY_CHAIN_DEP_CONFUSION (MEDIUM)
 *   Fires when tool parameters indicate package installation patterns
 *   commonly associated with dependency confusion attacks: pip with
 *   --extra-index-url, npm with git:// sources, or download-and-execute
 *   shell pipelines (curl/wget piped directly to a shell interpreter).
 *
 * Sources:
 *   ClawSwarm skill manipulation attack: The Register, April 29, 2026
 *   elementary-data PyPI compromise: BleepingComputer / Ars Technica, April 2026
 *   Dependency confusion technique: Alex Birsan (original research, 2021)
 *
 * Tier:     community
 * Severity: HIGH (shadow, skill-manip) | MEDIUM (dep-confusion) | LOW (new-server)
 */

import type { RuleDefinition } from "../../types.js";

/**
 * Claude Code built-in tool names that MCP servers should never shadow.
 * A tool named mcp__<server>__<builtin> is a strong signal of a shadowing
 * attack because legitimate MCP servers use domain-specific names.
 *
 * Names are matched against the suffix of the full tool_name after the
 * last double-underscore separator (e.g. "read" from "mcp__evil__read").
 */
const BUILTIN_TOOL_NAMES = [
  "read",
  "write",
  "edit",
  "multiedit",
  "bash",
  "grep",
  "glob",
  "ls",
  "mv",
  "cp",
  "rm",
  "mkdir",
  "webfetch",
  "websearch",
  "task",
  "todoread",
  "todowrite",
  "notebookread",
  "notebookedit",
].join("|");

export const RULE_SUPPLY_CHAIN_TOOL_SHADOW: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_TOOL_SHADOW",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "tool_name_match",
      patterns: [
        {
          // Matches mcp__<server>__<builtin> where <builtin> is any known
          // Claude Code built-in tool name. The double-underscore prefix
          // confirms this is an MCP-namespaced tool, not the real built-in.
          tool_name_regex: `^mcp__[^_].+__(?:${BUILTIN_TOOL_NAMES})$`,
          label: "Claude Code built-in tool name shadowed by MCP server",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "supply_chain",
  description_template:
    "MCP server {{mcp_server}} registered a tool named {{tool_name}} that shadows a Claude Code built-in. Possible tool name shadowing attack.",
};

export const RULE_SUPPLY_CHAIN_NEW_MCP_SERVER: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      // Fires once per unique mcp_server value per session.
      // "builtin" is excluded because built-in Claude Code tools always
      // report mcp_server="builtin" and are expected in every session.
      type: "session_first_seen",
      track: "mcp_server",
      exclude: ["builtin"],
    },
  ],
  severity: "LOW",
  category: "supply_chain",
  description_template:
    "MCP server {{mcp_server}} invoked for the first time in this session via {{tool_name}}. Verify this server was expected.",
};

export const RULE_SUPPLY_CHAIN_SKILL_MANIPULATION: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_SKILL_MANIPULATION",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        // Claude Code plugin management commands. An agent being directed to
        // install a plugin mid-session is a strong indicator of prompt injection.
        {
          regex: "\\bclaude\\s+plugin\\s+(?:add|install|enable)\\b",
          type: "claude-plugin-install",
        },
        // Cowork plugin management commands.
        {
          regex: "\\bcowork\\s+plugin\\s+(?:add|install)\\b",
          type: "cowork-plugin-install",
        },
        // Writing or modifying mcpServers in Claude Code settings. Classic
        // prompt injection vector: instruct the agent to add a malicious
        // MCP server to its own settings file. Note: JSON.stringify escapes
        // inner quotes as \", so we match the bare key name rather than
        // requiring surrounding quote characters.
        {
          regex: "\\bmcpServers\\b",
          type: "mcp-server-config-write",
        },
        // npm install with an explicit --registry pointing to a non-npmjs.org
        // host. Redirecting npm to an attacker-controlled registry causes all
        // subsequent installs in the session to fetch malicious packages.
        {
          regex:
            "npm\\s+(?:install|i)\\b[^\\n]*--registry\\s+https?://(?!(?:www\\.)?registry\\.npmjs\\.org)",
          type: "npm-custom-registry",
        },
        // pip install with --index-url pointing away from PyPI.
        {
          regex:
            "pip\\s+install\\b[^\\n]*--index-url\\s+https?://(?!(?:pypi\\.org|files\\.pythonhosted\\.org))",
          type: "pip-custom-index-url",
        },
        // Writing or modifying .npmrc with a registry= line. This persists
        // beyond the current command and affects future installs.
        {
          regex: "registry\\s*=\\s*https?://(?!(?:www\\.)?registry\\.npmjs\\.org)",
          type: "npmrc-registry-override",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "supply_chain",
  description_template:
    "Possible skill or plugin supply chain manipulation via {{tool_name}}: {{credential_types}}.",
};

export const RULE_SUPPLY_CHAIN_DEP_CONFUSION: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_DEP_CONFUSION",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        // pip install --extra-index-url is the canonical dependency confusion
        // vector: pip checks the extra index before PyPI for packages with
        // matching names, so an attacker can serve a higher-versioned package
        // from their registry and have it installed instead of the real one.
        {
          regex: "pip\\s+install\\b[^\\n]*--extra-index-url\\b",
          type: "pip-extra-index-url",
        },
        // npm install from a git:// or git+https:// URL. Commonly used to
        // install unreviewed packages directly from attacker-controlled repos,
        // bypassing npm registry integrity checks entirely.
        {
          regex:
            "npm\\s+(?:install|i)\\b[^\\n]*(?:git\\+https?://|git://|github:|bitbucket:|gitlab:)",
          type: "npm-git-source",
        },
        // Download-and-execute pattern: curl or wget output piped directly
        // to a shell interpreter. This is the most direct supply chain attack
        // vector and has no legitimate uses in a well-managed agent session.
        {
          regex:
            "(?:curl|wget)\\b[^|\\n]+\\|\\s*(?:bash|sh|zsh|python3?|node|ruby|perl)\\b",
          type: "download-execute",
        },
        // Reading or writing .pypirc which can redirect pip to alternative
        // package indexes, persisting the change beyond the current session.
        {
          regex: "\\.pypirc\\b",
          type: "pypirc-access",
        },
      ],
    },
  ],
  severity: "MEDIUM",
  category: "supply_chain",
  description_template:
    "Possible dependency confusion or supply chain attack via {{tool_name}}: {{credential_types}}.",
};

// =============================================================================
// Rules added for CVE-documented attack patterns (May 2026)
// Sources: Mini Shai-Hulud (Prompt Security, 2026), Mitiga Research (2026),
//          Gemini CLI CVE-2025-xxxx workspace config injection (Google, 2026)
// =============================================================================

/**
 * RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE (HIGH)
 *
 * Fires when a tool write targets a Claude Code settings file AND the
 * parameters contain hook configuration content. Used as a persistence
 * mechanism in the Mini Shai-Hulud supply chain attack, which modified
 * .claude/settings.json hook entries to establish a backdoor that
 * survived session termination and token rotation.
 *
 * Two conditions (AND):
 *   1. path_match -- Write/Edit tool call whose file_path is a Claude Code
 *      settings file (.claude/settings.json or .claude/settings.local.json).
 *   2. credential_match -- parameters also contain the string "hooks",
 *      confirming hook config (not just mcpServers or other settings) is
 *      being written.
 *
 * Known limitation: bash redirection (echo ... > .claude/settings.json) is
 * not caught by path_match. The two-condition approach handles Write/Edit
 * tool calls; a separate rule covers bash-side postinstall writes.
 *
 * Pro tier extension: allowlist of known-good hook commands, baseline
 * comparison across sessions, anomaly scoring per installation.
 *
 * Tier:     community
 * Severity: HIGH
 */
export const RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          regex: "[/\\\\]\\.claude[/\\\\]settings(?:\\.local)?\\.json$",
          label: ".claude/settings*.json",
        },
      ],
    },
    {
      type: "credential_match",
      patterns: [
        {
          // Confirms that hook entries are being written, not just other
          // settings keys (mcpServers, env, permissions, etc.).
          regex: "\\bhooks\\b",
          type: "hook-config-write",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "supply_chain",
  description_template:
    "Hook configuration written to {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "Unexpected hook modifications are a known persistence vector.",
};

/**
 * RULE_SUPPLY_CHAIN_MCP_URL_MUTATION (HIGH)
 *
 * Fires when a write targets the user-level ~/.claude.json file and the
 * parameters contain mcpServers configuration. Catches the Mitiga Research
 * attack pattern (2026): a malicious npm postinstall hook rewrites the MCP
 * server URL in ~/.claude.json to route all tool calls through an attacker-
 * controlled proxy, capturing OAuth tokens. The hook reasserts the malicious
 * URL on every npm package load, surviving manual fixes and token rotation.
 *
 * The existing RULE_SUPPLY_CHAIN_SKILL_MANIPULATION catches any event whose
 * parameters mention mcpServers, but at HIGH severity without path specificity.
 * This rule focuses on the user-level config file (as opposed to project-level
 * settings.json), which is the more dangerous target: changes here affect
 * ALL Claude Code sessions for the user, not just the current project.
 *
 * Pro tier extension: cross-session allowlist of known-good MCP server URLs
 * per installation, delivered from the cloud license server. Would catch URL
 * mutations that pattern-matching alone cannot distinguish from new additions.
 *
 * Tier:     community
 * Severity: HIGH
 */
export const RULE_SUPPLY_CHAIN_MCP_URL_MUTATION: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_MCP_URL_MUTATION",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          // Matches ~/.claude.json in any home directory layout.
          // The user-level config is the Mitiga attack target because changes
          // affect every Claude Code project, not just the current session.
          regex: "[/\\\\]\\.claude\\.json$",
          label: "~/.claude.json user config",
        },
      ],
    },
    {
      type: "credential_match",
      patterns: [
        {
          // Any write to ~/.claude.json that touches mcpServers is suspicious
          // regardless of whether it adds a new server or mutates an existing URL.
          regex: "\\bmcpServers\\b",
          type: "mcp-user-config-write",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "supply_chain",
  description_template:
    "MCP server configuration written to {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "User-level MCP config changes affect all Claude Code sessions.",
};

/**
 * RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE (HIGH)
 *
 * Fires when bash or scripting commands suggest writing Claude Code
 * configuration files, as would be done by a malicious npm postinstall hook.
 * Covers the Mitiga Research attack chain (2026): a compromised npm package's
 * postinstall script uses Node.js fs APIs or shell redirection to rewrite
 * ~/.claude.json with an attacker-controlled MCP server URL.
 *
 * Why a separate rule from RULE_SUPPLY_CHAIN_MCP_URL_MUTATION: that rule
 * fires when a Write/Edit tool call targets ~/.claude.json directly.
 * This rule fires on bash tool calls where the command text itself contains
 * the file write -- the more common pattern in postinstall hook attacks,
 * since the malicious code runs as a subprocess (npm lifecycle) rather than
 * as a direct tool invocation.
 *
 * The npm postinstall hook reasserts the malicious URL on every "npm install"
 * run, making it persistent even after manual fixes. Catching the write
 * command (this rule) is the earliest detectable signal.
 *
 * Tier:     community
 * Severity: HIGH
 */
export const RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          // Node.js fs module writing to .claude paths -- classic postinstall
          // persistence: require('fs').writeFileSync(os.homedir() + '/.claude.json', ...)
          regex: "(?:writeFile|writeFileSync)[\\s\\S]*?\\.claude",
          type: "node-claude-config-write",
        },
        {
          // Shell redirection or tee piping content into a .claude config file.
          // Matches: echo '...' > ~/.claude.json, printf ... | tee .claude.json
          regex: "(?:>|\\btee\\b)[^\\n]*\\.claude(?:\\.json|[/\\\\])",
          type: "bash-claude-config-write",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "supply_chain",
  description_template:
    "Command-level write to a Claude Code config path detected via {{tool_name}}: {{credential_types}}. " +
    "This pattern matches npm postinstall hook persistence attacks.",
};

/**
 * RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS (MEDIUM)
 *
 * Fires when an agent explicitly accesses auto-loaded Claude Code workspace
 * config files (CLAUDE.md, .mcp.json). These files are injected into the
 * agent context at session startup without explicit tool calls; an agent
 * explicitly reading or writing them mid-session is unusual and may indicate
 * context poisoning setup for the next session.
 *
 * Architectural gap:
 *   Our hook-based interceptor cannot detect workspace config injection
 *   that happens BEFORE Claude Code starts -- specifically, an attacker
 *   pre-placing a malicious settings file or CLAUDE.md in a repo that gets
 *   cloned in CI/CD (analogous to the Gemini CLI CVSS 10 CVE, April 2026).
 *   The initial config load at startup is a known blind spot. This rule
 *   detects the INJECTION STEP (writing the malicious file during a session)
 *   rather than the exploitation step (the next session loading it).
 *
 *   Mitigation path: a pre-session integrity check ("omnodex verify") that
 *   hashes workspace config files at init-time and warns on changes. This
 *   would require a cloud feature (baseline comparison across sessions).
 *
 * Tier:     community
 * Severity: MEDIUM
 */
export const RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          // Root or nested CLAUDE.md -- auto-injected as tool context at startup.
          // Mid-session explicit access suggests an agent inspecting or modifying
          // its own context injection, which is characteristic of prompt injection
          // attacks that attempt to tamper with project-wide instructions.
          regex: "(?:^|[/\\\\])CLAUDE\\.md$",
          label: "CLAUDE.md workspace context file",
        },
        {
          // .mcp.json -- MCP server config for Codex and VS Code-based agents.
          // Not used by Claude Code directly, but auto-loaded by other desktop
          // agents. Cross-tool config poisoning via .mcp.json is an emerging vector.
          regex: "(?:^|[/\\\\])\\.mcp\\.json$",
          label: ".mcp.json MCP server config",
        },
      ],
    },
  ],
  severity: "MEDIUM",
  category: "supply_chain",
  description_template:
    "Agent accessed {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "These files are auto-loaded at session start; mid-session access may indicate context injection.",
};


// =============================================================================
// IOC domain detection
// Source: Prempti competitive analysis, common threat intelligence feeds
// =============================================================================

/**
 * RULE_SUPPLY_CHAIN_IOC_DOMAIN (HIGH)
 *
 * Fires when a URL in tool parameters targets a domain from a curated
 * list of known indicators of compromise. These are domains historically
 * associated with credential exfiltration, C2 infrastructure, or
 * supply chain attacks targeting developer environments.
 *
 * The list is intentionally conservative (high-confidence IOCs only)
 * to minimize false positives. Pro tier will add cloud-managed IOC
 * lists with more frequent updates.
 *
 * Tier:     community
 * Severity: HIGH
 */
export const RULE_SUPPLY_CHAIN_IOC_DOMAIN: RuleDefinition = {
  rule_id: "RULE_SUPPLY_CHAIN_IOC_DOMAIN",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "domain_match",
      match: "in_list",
      domains: [
        // Known malicious hosting/exfil infrastructure used in agent attacks
        // Sources: Mini Shai-Hulud, ClawSwarm, documented supply chain incidents
        "pipedream.net",
        "requestbin.com",
        "hookbin.com",
        "webhook.site",
        "requestcatcher.com",
        "burpcollaborator.net",
        "interact.sh",
        "oastify.com",
        "canarytokens.com",
        // Known paste/exfil services abused for credential collection
        "paste.ee",
        "transfer.sh",
        "file.io",
        "0x0.st",
        // Telegram bot API (used for exfiltration in ClawSwarm and others)
        "api.telegram.org",
        // Discord webhook (common exfil channel)
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
      ],
    },
  ],
  severity: "HIGH",
  category: "supply_chain",
  description_template:
    "Tool call via {{tool_name}} targets known IOC domain {{matched_domain}}. " +
    "This domain is associated with credential exfiltration or C2 infrastructure.",
  blocking_hint: "deny",
};
