// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_CREDENTIAL_SETTINGS_LOCAL_GIT (HIGH)
 *
 * Fires when a git command names Claude Code's per-project local settings
 * file (.claude/settings.local.json) to stage, commit or stash it. Choosing
 * "Yes, and don't ask again" saves the exact approved command to that file,
 * secrets typed into the command included, and the file is meant to stay on
 * the machine. Staging it by name puts those commands into the repository's
 * history.
 *
 * A broad "git add ." or "git commit -a" does not name the file and is not
 * flagged; the session start check reports whether the file holds a
 * credential and whether the repository's own .gitignore covers it.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_CREDENTIAL_SETTINGS_LOCAL_GIT: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_SETTINGS_LOCAL_GIT",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      scope: ["exec"],
      patterns: [
        {
          regex:
            "\\bgit\\b[^\\n;&|]*\\s(?:add|commit|stash|rm)\\b[^\\n;&|]*(?:settings\\.local\\.json|\\.claude[\\\\/]\\*\\.local\\.json)",
          type: "claude-settings-local",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "credential_exposure",
  description_template:
    "A git command via {{tool_name}} names Claude Code's local settings file: {{credential_types}}. " +
    "The file can hold the exact commands you approved, secrets included, and is meant to stay out of the repository.",
  blocking_hint: "confirm",
};
