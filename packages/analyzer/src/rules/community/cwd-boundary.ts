// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Working-directory boundary detection rule.
 *
 * RULE_CWD_BOUNDARY_WRITE (MEDIUM)
 *   Fires when an agent writes to a file outside the session's workspace:
 *   the directory the session started in and its current working
 *   directory, the git checkouts those belong to (including sibling
 *   worktrees), and any configured workspace_roots. The starting directory
 *   matters because an agent that runs cd moves the cwd later calls report. Agents should generally stay within the project they
 *   were invoked in; writes outside the project directory are a signal
 *   of either misconfiguration or malicious activity (config poisoning,
 *   persistence installation, credential access).
 *
 *   Requires cwd to be populated on the ToolInvokedEvent (populated
 *   by all hook-based interceptors since schema version 1). Events
 *   without cwd are silently skipped (backwards compatible).
 *
 *   Severity is MEDIUM because legitimate cross-project writes exist
 *   (e.g. writing to a shared config directory). Higher-severity rules
 *   for specific outside-cwd targets (sensitive paths, shell startup
 *   files, etc.) take precedence.
 *
 * Sources:
 *   Prempti default ruleset: "Monitor activity outside working directory"
 *   and "Ask before writing outside working directory" (Apache 2.0)
 *
 * Tier:     community
 * Severity: MEDIUM
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_CWD_BOUNDARY_WRITE: RuleDefinition = {
  rule_id: "RULE_CWD_BOUNDARY_WRITE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "cwd_boundary",
      // Writes only: reading outside the workspace is routine, and the
      // sensitive reads are the sensitive-path and credential rules' job.
      access: "write",
    },
  ],
  severity: "MEDIUM",
  category: "cwd_boundary",
  description_template:
    "{{matched_label}}: {{matched_path}} written via {{tool_name}}. " +
    "The session's workspace is the directory it started in and its current working directory, their git checkouts and any configured workspace roots.",
  blocking_hint: "confirm",
};
