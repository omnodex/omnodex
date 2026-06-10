// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_CREDENTIAL_IN_PARAMS
 *
 * Fires when a tool's parameters contain a value that looks like a credential
 * -- API key, bearer token, password, cloud provider key, etc. One risk
 * finding is emitted per invocation regardless of how many credential types
 * are found; the types are joined in the description.
 *
 * Tier:     community
 * Severity: MEDIUM
 *
 * The credential patterns are exported so RULE_CREDENTIAL_EXFIL can reuse
 * them without duplicating the list.
 */

import type { CredentialPattern, RuleDefinition } from "../../types.js";

export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // Bearer token in Authorization header value or parameter.
  { regex: "Bearer\\s+([A-Za-z0-9_\\-.]+)",                              type: "bearer",      group: 1 },
  // Stripe live and test secret keys.
  { regex: "sk_live_[A-Za-z0-9_-]+",                                     type: "stripe-live"           },
  { regex: "sk_test_[A-Za-z0-9_-]+",                                     type: "stripe-test"           },
  // Generic api_key / api-key / apikey assignment.
  { regex: "api[_-]?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_-]{16,})",  type: "api-key",     group: 1 },
  // Generic token assignment.
  { regex: "token[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_-]{16,})",        type: "token",       group: 1 },
  // Generic password assignment.
  { regex: "password[\"']?\\s*[:=]\\s*[\"']?([^\\s\"',}]{4,})",        type: "password",    group: 1 },
  // GitHub personal access token.
  { regex: "ghp_[A-Za-z0-9]{36,}",                                       type: "github-pat"            },
  // Slack bot token.
  { regex: "xoxb-[A-Za-z0-9-]+",                                         type: "slack-bot"             },
  // AWS access key ID.
  { regex: "AKIA[A-Z0-9]{16}",                                           type: "aws-key"               },
];

export const RULE_CREDENTIAL_IN_PARAMS: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_IN_PARAMS",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: CREDENTIAL_PATTERNS,
    },
  ],
  severity: "MEDIUM",
  category: "credential_exposure",
  description_template:
    "Credential(s) found in tool parameters for {{tool_name}}: {{credential_types}}.",
};
