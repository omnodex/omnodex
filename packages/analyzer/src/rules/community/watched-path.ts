// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_WATCHED_PATH (HIGH)
 *
 * The user chose this path with `omnodex policy watch`, usually their own
 * monitoring code or alert configuration, and an agent's tool call changed,
 * moved or deleted it. The list is the user's, so the rule has no patterns of
 * its own and does nothing until a path is watched. It does not block by
 * itself: a watch added with --block or --hold does, in guardrails mode.
 */

import { WATCHED_PATH_RULE_ID } from "@omnodex/shared";
import type { RuleDefinition } from "../../types.js";

export const RULE_WATCHED_PATH: RuleDefinition = {
  rule_id: WATCHED_PATH_RULE_ID,
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [{ type: "watched_path" }],
  severity: "HIGH",
  category: "self_protection",
  description_template:
    "{{tool_name}} changed {{matched_path}}, a path you are watching. " +
    "Confirm the change was meant to happen; watched paths are often the monitoring or alerts that would report a problem.",
};
