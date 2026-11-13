// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_THREAT_SHELL_EXPANSION_IN_TEXT (MEDIUM)
 *
 * Fires when a double-quoted text argument of a git, gh or glab command
 * holds a backtick pair or a $( ) command substitution: a commit message,
 * pull request or issue body, title, release notes. The shell runs what
 * sits between the backticks before the command starts, so Markdown code
 * spans written into a double-quoted body become commands. An agent that
 * writes `docker volume prune` as code formatting in a pull request body
 * runs it.
 *
 * Safe forms do not fire: single quotes, a backslash before the backtick or
 * dollar sign, and a command substitution that only reads a heredoc with a
 * quoted delimiter ($(cat <<'EOF' ... EOF), the form agents use to pass a
 * multi-line message safely.
 *
 * Tier:     community
 * Severity: MEDIUM
 */

import type { RuleDefinition } from "../../types.js";

// The flag that takes a text value, then its double-quoted value up to the
// first expansion. A backslash escapes the next character; "$((" is
// arithmetic, not a command.
const TEXT_FLAG =
  "(?:--(?:body|title|message|notes|description|comment|subject)(?:=|\\s+)|-[A-Za-z]*[mbt]\\s*=?\\s*)";
const PROGRAM = "\\b(?:git|gh|glab)\\b[^\\n]*?\\s";
const QUOTED_PREFIX = '"(?:[^"\\\\`$]|\\\\[\\s\\S]|\\$(?!\\())*';
const SAFE_HEREDOC = "\\s*cat\\s+<<-?\\s*(?:'|\"|\\\\)";

export const RULE_THREAT_SHELL_EXPANSION_IN_TEXT: RuleDefinition = {
  rule_id: "RULE_THREAT_SHELL_EXPANSION_IN_TEXT",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      scope: ["exec"],
      patterns: [
        {
          regex: PROGRAM + TEXT_FLAG + QUOTED_PREFIX + "`[^`]*`",
          type: "backtick-expansion",
        },
        {
          regex: PROGRAM + TEXT_FLAG + QUOTED_PREFIX + "\\$\\((?!\\()(?!" + SAFE_HEREDOC + ")",
          type: "command-substitution",
        },
      ],
    },
  ],
  severity: "MEDIUM",
  category: "threat_command",
  description_template:
    "Shell expansion inside quoted text sent through {{tool_name}}: {{credential_types}}. " +
    "The shell runs backticks and $( ) in a double-quoted argument before the command starts; " +
    "use single quotes or a quoted heredoc for text that contains code.",
  blocking_hint: "confirm",
};
