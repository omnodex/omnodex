// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Threat command detection rules.
 *
 * Rules covering dangerous shell commands and command patterns commonly
 * used in attacks against AI agent environments. All rules use existing
 * credential_match or ip_destination condition types against bash command
 * strings or tool parameters.
 *
 * RULE_THREAT_DESTRUCTIVE_COMMAND (HIGH)
 *   Fires on shell commands that destroy data or damage the system:
 *   rm -rf /, mkfs, dd writing to block devices, fdisk, wipefs.
 *
 * RULE_THREAT_ENCODED_PAYLOAD (HIGH)
 *   Fires on obfuscated command execution: base64 decode piped to a
 *   shell, python -c with exec/eval, perl -e.
 *
 * RULE_THREAT_REVERSE_SHELL (CRITICAL)
 *   Fires on reverse shell patterns: mkfifo+nc, bash -i redirects,
 *   python pty.spawn, ruby/perl socket shells.
 *
 * RULE_THREAT_IMDS_ACCESS (HIGH)
 *   Fires on access to cloud instance metadata services
 *   (169.254.169.254, fd00:ec2::254) used for credential theft.
 *
 * RULE_THREAT_CREDENTIAL_ARCHIVE (HIGH)
 *   Fires on archiving credential directories (~/.ssh, ~/.aws,
 *   ~/.gnupg, ~/.config/gcloud) via tar, zip, or similar.
 *
 * RULE_THREAT_SSH_TUNNEL (MEDIUM)
 *   Fires on SSH reverse tunnels and SOCKS proxies (ssh -R, ssh -D)
 *   used for persistent access and traffic exfiltration.
 *
 * RULE_THREAT_AUDIT_TRAIL_DESTRUCTION (HIGH)
 *   Fires on commands that wipe shell history, shred files, or delete
 *   logs to cover tracks.
 *
 * RULE_THREAT_PACKAGE_PUBLISH (MEDIUM)
 *   Fires on package publish commands (npm publish, cargo publish,
 *   gem push, twine upload) which should not happen in agent sessions.
 *
 * Tier:     community
 * Severity: varies (see individual rules)
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_THREAT_DESTRUCTIVE_COMMAND: RuleDefinition = {
  rule_id: "RULE_THREAT_DESTRUCTIVE_COMMAND",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\brm\\s+(?:-[a-zA-Z]*\\s+)*(?:-[a-zA-Z]*r[a-zA-Z]*|--recursive)\\b[^\\n]*(?:\\/[\\s\"\\\\}]|\\/\\*|~\\/)",
          type: "recursive-delete",
        },
        {
          regex: "\\bmkfs(?:\\.\\w+)?\\s",
          type: "filesystem-format",
        },
        {
          regex: "\\bdd\\b[^\\n]*\\bof=\\/dev\\/(?:sd|nvme|vd|xvd|hd)",
          type: "dd-block-device-write",
        },
        {
          regex: "\\b(?:fdisk|parted|wipefs)\\s",
          type: "disk-partition-tool",
        },
        {
          regex: "\\b(?:chmod|chown)\\s+(-[a-zA-Z]*R[a-zA-Z]*|--recursive)\\b[^\\n]*\\/\\s*$",
          type: "recursive-permission-change-root",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "threat_command",
  description_template:
    "Destructive system command detected via {{tool_name}}: {{credential_types}}. " +
    "This command could cause data loss or system damage.",
  blocking_hint: "deny",
};

export const RULE_THREAT_ENCODED_PAYLOAD: RuleDefinition = {
  rule_id: "RULE_THREAT_ENCODED_PAYLOAD",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\bbase64\\s+(?:-d|--decode)\\b[^\\n]*\\|\\s*(?:bash|sh|zsh|python3?|node|ruby|perl)\\b",
          type: "base64-decode-to-shell",
        },
        {
          regex: "\\bpython3?\\s+-c\\s+['\"].*(?:exec|eval|compile|__import__)\\b",
          type: "python-inline-exec",
        },
        {
          regex: "\\bperl\\s+-e\\s+['\"].*(?:system|exec|`)",
          type: "perl-inline-exec",
        },
        {
          regex: "\\becho\\s+[^\\n]*\\|\\s*(?:base64\\s+(?:-d|--decode)|xxd\\s+-r|openssl\\s+enc\\s+-d)\\s*\\|",
          type: "decode-pipe-chain",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "threat_command",
  description_template:
    "Encoded or obfuscated payload execution detected via {{tool_name}}: {{credential_types}}. " +
    "Obfuscated commands are a strong indicator of malicious activity.",
  blocking_hint: "deny",
};

export const RULE_THREAT_REVERSE_SHELL: RuleDefinition = {
  rule_id: "RULE_THREAT_REVERSE_SHELL",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\bmkfifo\\b[^\\n]*\\bnc\\b",
          type: "mkfifo-netcat",
        },
        {
          regex: "\\bbash\\s+-i\\s*[>&]+\\s*\\/dev\\/tcp\\/",
          type: "bash-redirect-devtcp",
        },
        {
          regex: "\\bpython3?\\s+-c\\s+[^\\n]*(?:pty\\.spawn|socket\\.socket)[^\\n]*connect",
          type: "python-reverse-shell",
        },
        {
          regex: "\\bnc\\s+(?:-[a-zA-Z]*e[a-zA-Z]*\\s|--exec\\s)",
          type: "netcat-exec",
        },
        {
          regex: "\\bsocat\\b[^\\n]*\\bexec\\b",
          type: "socat-exec",
        },
      ],
    },
  ],
  severity: "CRITICAL",
  category: "threat_command",
  description_template:
    "Reverse shell attempt detected via {{tool_name}}: {{credential_types}}. " +
    "This is a strong indicator of active compromise.",
  blocking_hint: "deny",
};

export const RULE_THREAT_IMDS_ACCESS: RuleDefinition = {
  rule_id: "RULE_THREAT_IMDS_ACCESS",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "169\\.254\\.169\\.254",
          type: "imds-ipv4",
        },
        {
          regex: "fd00:ec2::254",
          type: "imds-ipv6",
        },
        {
          regex: "metadata\\.google\\.internal",
          type: "gcp-metadata",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "threat_command",
  description_template:
    "Cloud metadata service (IMDS) access detected via {{tool_name}}: {{credential_types}}. " +
    "IMDS access is a primary vector for cloud credential theft.",
  blocking_hint: "deny",
};

export const RULE_THREAT_CREDENTIAL_ARCHIVE: RuleDefinition = {
  rule_id: "RULE_THREAT_CREDENTIAL_ARCHIVE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\b(?:tar|zip|7z|rar)\\b[^\\n]*(?:\\.ssh|\\.aws|\\.gnupg|\\.config\\/gcloud|\\.azure|\\.kube)",
          type: "archive-credential-dir",
        },
        {
          regex: "\\bcp\\s+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)\\b[^\\n]*(?:\\.ssh|\\.aws|\\.gnupg)",
          type: "recursive-copy-credential-dir",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "threat_command",
  description_template:
    "Credential directory archiving detected via {{tool_name}}: {{credential_types}}. " +
    "Bulk credential collection is a common exfiltration precursor.",
  blocking_hint: "deny",
};

export const RULE_THREAT_SSH_TUNNEL: RuleDefinition = {
  rule_id: "RULE_THREAT_SSH_TUNNEL",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\bssh\\b[^\\n]*\\s-R\\s+\\d+:",
          type: "ssh-reverse-tunnel",
        },
        {
          regex: "\\bssh\\b[^\\n]*\\s-D\\s+\\d+",
          type: "ssh-socks-proxy",
        },
        {
          regex: "\\bssh\\b[^\\n]*\\s-L\\s+\\d+:[^l][^o][^c]",
          type: "ssh-local-forward-remote",
        },
      ],
    },
  ],
  severity: "MEDIUM",
  category: "threat_command",
  description_template:
    "SSH tunnel or proxy detected via {{tool_name}}: {{credential_types}}. " +
    "SSH tunnels can be used for persistent access or traffic exfiltration.",
  blocking_hint: "confirm",
};

export const RULE_THREAT_AUDIT_TRAIL_DESTRUCTION: RuleDefinition = {
  rule_id: "RULE_THREAT_AUDIT_TRAIL_DESTRUCTION",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\b(?:history\\s+-c|history\\s+-w\\s*\\/dev\\/null)\\b",
          type: "history-clear",
        },
        {
          regex: "\\brm\\b[^\\n]*(?:\\.bash_history|\\.zsh_history|\\.python_history)",
          type: "history-file-delete",
        },
        {
          regex: "\\btruncate\\b[^\\n]*(?:\\.bash_history|\\.zsh_history|\\blog\\/|syslog|auth\\.log)",
          type: "log-truncate",
        },
        {
          regex: "\\bshred\\b[^\\n]*(?:\\.bash_history|\\.zsh_history|\\blog\\/)",
          type: "log-shred",
        },
        {
          regex: ">\\s*(?:~\\/|\\$HOME\\/)\\.(?:bash_history|zsh_history)",
          type: "history-redirect-empty",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "threat_command",
  description_template:
    "Audit trail destruction detected via {{tool_name}}: {{credential_types}}. " +
    "Erasing shell history or logs is a strong indicator of an attempt to cover tracks.",
  blocking_hint: "deny",
};

export const RULE_THREAT_PACKAGE_PUBLISH: RuleDefinition = {
  rule_id: "RULE_THREAT_PACKAGE_PUBLISH",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "\\bnpm\\s+publish\\b",
          type: "npm-publish",
        },
        {
          regex: "\\bcargo\\s+publish\\b",
          type: "cargo-publish",
        },
        {
          regex: "\\bgem\\s+push\\b",
          type: "gem-push",
        },
        {
          regex: "\\btwine\\s+upload\\b",
          type: "twine-upload",
        },
        {
          regex: "\\bpip\\s+upload\\b",
          type: "pip-upload",
        },
      ],
    },
  ],
  severity: "MEDIUM",
  category: "threat_command",
  description_template:
    "Package publish command detected via {{tool_name}}: {{credential_types}}. " +
    "Publishing packages from an agent session is unexpected and could distribute malicious code.",
  blocking_hint: "confirm",
};


// =============================================================================
// API base URL override detection
// Source: Prempti competitive analysis
// =============================================================================

/**
 * RULE_THREAT_API_BASE_URL_OVERRIDE (HIGH)
 *
 * Fires when a tool call writes API base URL overrides into environment
 * files. Overriding OPENAI_BASE_URL, ANTHROPIC_BASE_URL, or similar
 * variables redirects all API traffic through an attacker-controlled
 * proxy, enabling credential interception and response manipulation.
 *
 * Tier:     community
 * Severity: HIGH
 */
export const RULE_THREAT_API_BASE_URL_OVERRIDE: RuleDefinition = {
  rule_id: "RULE_THREAT_API_BASE_URL_OVERRIDE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        {
          regex: "(?:OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|ANTHROPIC_API_BASE|GEMINI_API_BASE|AZURE_OPENAI_ENDPOINT)\\s*=\\s*https?://",
          type: "api-base-url-override",
        },
        {
          regex: "(?:api_base|base_url|endpoint)\\b[^\\n]*https?://(?!(?:api\\.openai\\.com|api\\.anthropic\\.com|generativelanguage\\.googleapis\\.com))",
          type: "api-base-url-suspicious-target",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "threat_command",
  description_template:
    "API base URL override detected via {{tool_name}}: {{credential_types}}. " +
    "Redirecting API traffic to a non-standard endpoint enables credential interception.",
  blocking_hint: "deny",
};
