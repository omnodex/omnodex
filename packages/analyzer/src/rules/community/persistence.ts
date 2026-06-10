// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Persistence vector detection rules.
 *
 * Rules covering file-based persistence techniques an attacker can use
 * to maintain access or re-execute malicious code across sessions.
 *
 * RULE_PERSISTENCE_SHELL_STARTUP (HIGH)
 *   Fires when an agent writes to shell startup files (.bashrc, .zshrc,
 *   .profile, .bash_profile, .zprofile, .bash_login, .bash_logout).
 *   These files execute automatically on shell login, making them a
 *   common persistence vector. Used in Mini Shai-Hulud (2026).
 *
 * RULE_PERSISTENCE_GIT_HOOKS (HIGH)
 *   Fires when an agent writes to a .git/hooks/ directory. Git hooks
 *   execute automatically on git operations (commit, push, merge, etc.)
 *   and are a known persistence mechanism. A malicious hook runs with
 *   the user's full permissions every time the developer interacts
 *   with the repository.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_PERSISTENCE_SHELL_STARTUP: RuleDefinition = {
  rule_id: "RULE_PERSISTENCE_SHELL_STARTUP",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          regex: "(?:^|[/\\\\])(?:\\.bashrc|\\.zshrc|\\.profile|\\.bash_profile|\\.zprofile|\\.bash_login|\\.bash_logout)$",
          label: "shell startup file",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "persistence",
  description_template:
    "Write to {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "Shell startup files execute on every login and are a common persistence vector.",
  blocking_hint: "confirm",
};

export const RULE_PERSISTENCE_GIT_HOOKS: RuleDefinition = {
  rule_id: "RULE_PERSISTENCE_GIT_HOOKS",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        {
          regex: "[/\\\\]\\.git[/\\\\]hooks[/\\\\]",
          label: "git hooks directory",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "persistence",
  description_template:
    "Write to {{matched_label}} ({{matched_path}}) via {{tool_name}}. " +
    "Git hooks execute automatically on git operations and are a known persistence mechanism.",
  blocking_hint: "confirm",
};
