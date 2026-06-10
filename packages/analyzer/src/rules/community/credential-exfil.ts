// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_CREDENTIAL_EXFIL
 *
 * Fires when credentials are present in the parameters of a tool that makes
 * an outbound HTTP call. This is the highest-confidence exfiltration signal:
 * the agent has both a credential and is sending data to an external host.
 *
 * Compound condition (AND):
 *   1. outbound_call  -- the tool is making an HTTP request to an external host
 *   2. credential_match -- the parameters contain at least one credential
 *
 * Tier:     community
 * Severity: CRITICAL
 */

import type { RuleDefinition } from "../../types.js";
import { CREDENTIAL_PATTERNS } from "./credential-in-params.js";

export const RULE_CREDENTIAL_EXFIL: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_EXFIL",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    { type: "outbound_call" },
    {
      type: "credential_match",
      patterns: CREDENTIAL_PATTERNS,
    },
  ],
  severity: "CRITICAL",
  category: "credential_exfiltration",
  description_template:
    "Credential(s) transmitted to external endpoint via {{tool_name}}: {{credential_types}}.",
};
