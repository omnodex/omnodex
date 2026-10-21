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
 * A credential sent as authentication to its own service (a GitHub token
 * in the Authorization header of a call to api.github.com, a Google API key
 * in the URL of a googleapis.com call) is the service being used, and does
 * not count.
 *
 * Tier:     community
 * Severity: CRITICAL
 */

import type { RuleDefinition } from "../../types.js";
import { CREDENTIAL_PATTERNS } from "./credential-in-params.js";

export const RULE_CREDENTIAL_EXFIL: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_EXFIL",
  version: "1.1.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    { type: "outbound_call" },
    {
      type: "credential_match",
      // Secrets and payloads: a match in any field is the risk.
      scope: "all",
      patterns: CREDENTIAL_PATTERNS,
      provider_auth: "skip",
    },
  ],
  severity: "CRITICAL",
  category: "credential_exfiltration",
  description_template:
    "Credential(s) transmitted to {{matched_destination}} via {{tool_name}}: {{credential_types}}.",
};
