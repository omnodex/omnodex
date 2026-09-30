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

// Every pattern checks its value (see CredentialPattern.check), so text that
// talks about credentials, such as "Bearer tokens", "${API_TOKEN}" or a
// vendor's documentation key in a test, is not reported as one.
export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // Bearer token in Authorization header value or parameter. Real tokens run
  // to 20 characters and more; "Bearer" followed by a word is prose.
  { regex: "Bearer\\s+([A-Za-z0-9_\\-.=+/]{20,})",                        type: "bearer",      group: 1, check: "secret" },
  // Stripe live and test secret keys.
  { regex: "sk_live_[A-Za-z0-9]{16,}",                                   type: "stripe-live",           check: "secret" },
  { regex: "sk_test_[A-Za-z0-9]{16,}",                                   type: "stripe-test",           check: "secret" },
  // Generic assignments. Parameters are scanned as JSON, where a quote in
  // code reads \", so each allows a backslash before its optional quotes.
  // api_key / api-key / apikey:
  { regex: "api[_-]?key\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?([A-Za-z0-9_-]{16,})",  type: "api-key",     group: 1, check: "secret" },
  // token:
  { regex: "token\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?([A-Za-z0-9_-]{16,})",        type: "token",       group: 1, check: "secret" },
  // password, which may be letters alone:
  { regex: "password\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?([^\\s\"'`,;}\\\\]{4,})", type: "password", group: 1, check: "placeholder" },
  // GitHub personal access token.
  { regex: "ghp_[A-Za-z0-9]{36,}",                                       type: "github-pat",            check: "secret" },
  // Slack bot token.
  { regex: "xoxb-[A-Za-z0-9-]+",                                         type: "slack-bot",             check: "secret" },
  // AWS access key ID.
  { regex: "AKIA[A-Z0-9]{16}",                                           type: "aws-key",               check: "secret" },
];

export const RULE_CREDENTIAL_IN_PARAMS: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_IN_PARAMS",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      // Secrets and payloads: a match in any field is the risk.
      scope: "all",
      patterns: CREDENTIAL_PATTERNS,
    },
  ],
  severity: "MEDIUM",
  category: "credential_exposure",
  description_template:
    "Credential(s) found in tool parameters for {{tool_name}}: {{credential_types}}.",
};
