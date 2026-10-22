// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_UNRECOGNIZED_SECRET
 *
 * Fires when a tool's parameters use a machine-made value as a credential
 * and no known format or generic pattern of RULE_CREDENTIAL_IN_PARAMS
 * reports it: a field or variable named for a secret, key or auth
 * (CLIENT_SECRET=..., "signingKey": "..."), a credential flag
 * (--client-secret ...), or an Authorization header that is not a Bearer
 * token ("Authorization: token ...", "Authorization: Basic ...").
 *
 * The name gives the context and the value must look generated (see
 * CredentialPattern.check "generated"), so a git hash, UUID, integrity
 * string, file path or ordinary word in such a field is not reported.
 *
 * Tier:     community
 * Severity: LOW. This is a heuristic with no vendor format behind it, kept
 * apart from the credential rule so it can be muted or tuned on its own.
 */

import type { CredentialPattern, RuleDefinition } from "../../types.js";
import { CREDENTIAL_PATTERNS } from "./credential-in-params.js";

const TYPE = "unrecognized-secret";

// A value: 16 or more key, token or base64 characters, after an optional
// quote. Parameters are scanned as JSON, where a quote in code reads \".
const VALUE = "\\\\?[\"']?([A-Za-z0-9_\\-.+/=]{16,})";

const CANDIDATE_PATTERNS: CredentialPattern[] = [
  // A field, variable or header named for a secret, key or auth. A public
  // key is not a secret.
  { regex: `(?:secret|(?<!public[_-]?)key|auth|credential|passwd|pwd)\\\\?["']?\\s*[:=]\\s*${VALUE}`, type: TYPE, group: 1, check: "generated" },
  // A command-line flag for one: --client-secret VALUE, --auth-key=VALUE.
  { regex: `--[a-z-]*(?:secret|key|token|auth|password)[= ]\\s*${VALUE}`, type: TYPE, group: 1, check: "generated" },
  // An Authorization header with a scheme other than Bearer.
  { regex: `authorization\\\\?["']?\\s*:\\s*\\\\?["']?(?:token|basic|apikey)\\s+([A-Za-z0-9_\\-.+/=]{16,})`, type: TYPE, group: 1, check: "generated" },
];

export const RULE_UNRECOGNIZED_SECRET: RuleDefinition = {
  rule_id: "RULE_UNRECOGNIZED_SECRET",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      scope: "all",
      // The credential rule's patterns come first and claim what they
      // match, so a value it reports is not reported twice.
      patterns: [...CREDENTIAL_PATTERNS, ...CANDIDATE_PATTERNS],
      report: [TYPE],
    },
  ],
  severity: "LOW",
  category: "credential_exposure",
  description_template:
    "A value used as a secret, key or token in {{tool_name}} matches no known credential format. Check whether it is a live credential.",
};
