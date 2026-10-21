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
 * them without duplicating the list. Vendor formats cover cloud, payment
 * and source-hosting keys and the AI model providers agents are most often
 * configured with.
 */

import type { CredentialPattern, RuleDefinition } from "../../types.js";

// Every pattern checks its value (see CredentialPattern.check), so text that
// talks about credentials, such as "Bearer tokens", "${API_TOKEN}" or a
// vendor's documentation key in a test, is not reported as one.
//
// Vendor formats come first: a value is reported under the first pattern
// that matches it, so a key in "Bearer <key>" or "token=<key>" is labeled by
// its vendor. A vendor key may not run on into more key characters, so a
// longer token is not mistaken for one. No leading boundary: in scanned JSON
// an escaped newline puts a letter ("\n") right before the prefix.
const END = "(?![A-Za-z0-9_-])";

export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // AI providers. Formats follow the gitleaks and trufflehog detectors.
  // Anthropic admin and API keys.
  { regex: `sk-ant-admin01-[A-Za-z0-9_-]{93}AA${END}`,                   type: "anthropic-admin",      check: "prefixed" },
  { regex: `sk-ant-api03-[A-Za-z0-9_-]{93}AA${END}`,                     type: "anthropic",            check: "prefixed" },
  // OpenAI project, service account and admin keys, and legacy user keys.
  // Each carries the T3BlbkFJ marker.
  { regex: `sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58,74}T3BlbkFJ[A-Za-z0-9_-]{58,74}${END}`, type: "openai", check: "prefixed" },
  { regex: `sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}${END}`,            type: "openai",               check: "prefixed" },
  // OpenRouter, xAI, Groq and Perplexity.
  { regex: `sk-or-v1-[0-9a-f]{64}${END}`,                                type: "openrouter",           check: "prefixed" },
  { regex: `xai-[A-Za-z0-9_]{80}${END}`,                                 type: "xai",                  check: "prefixed" },
  { regex: `gsk_[A-Za-z0-9]{52}${END}`,                                  type: "groq",                 check: "prefixed" },
  { regex: `pplx-[A-Za-z0-9]{48}${END}`,                                 type: "perplexity",           check: "prefixed" },
  // Hugging Face user access and organization tokens: letters alone.
  { regex: `hf_[A-Za-z]{34}${END}`,                                      type: "huggingface",          check: "prefixed" },
  { regex: `api_org_[A-Za-z]{34}${END}`,                                 type: "huggingface",          check: "prefixed" },
  // Google API key, which Gemini (Google AI Studio) keys are.
  { regex: `AIza[A-Za-z0-9_-]{35}${END}`,                                type: "google-api-key",       check: "prefixed" },
  // Stripe live and test secret keys.
  { regex: "sk_live_[A-Za-z0-9]{16,}",                                   type: "stripe-live",          check: "secret" },
  { regex: "sk_test_[A-Za-z0-9]{16,}",                                   type: "stripe-test",          check: "secret" },
  // GitHub personal access tokens, classic and fine-grained.
  { regex: "ghp_[A-Za-z0-9]{36,}",                                       type: "github-pat",           check: "secret" },
  { regex: `github_pat_[A-Za-z0-9_]{82}${END}`,                          type: "github-pat",           check: "secret" },
  // GitHub OAuth, app (user-to-server and server-to-server) and refresh tokens.
  { regex: `gho_[A-Za-z0-9]{36}${END}`,                                  type: "github-oauth",         check: "secret" },
  { regex: `gh[us]_[A-Za-z0-9]{36}${END}`,                               type: "github-app",           check: "secret" },
  { regex: `ghr_[A-Za-z0-9]{36}${END}`,                                  type: "github-refresh",       check: "secret" },
  // Slack bot token.
  { regex: "xoxb-[A-Za-z0-9-]+",                                         type: "slack-bot",            check: "secret" },
  // AWS access key ID.
  { regex: "AKIA[A-Z0-9]{16}",                                           type: "aws-key",              check: "secret" },
  // Bearer token in Authorization header value or parameter. Real tokens run
  // to 20 characters and more; "Bearer" followed by a word is prose.
  { regex: "Bearer\\s+([A-Za-z0-9_\\-.=+/]{20,})",                        type: "bearer",      group: 1, check: "secret" },
  // Generic assignments. Parameters are scanned as JSON, where a quote in
  // code reads \", so each allows a backslash before its optional quotes.
  // api_key / api-key / apikey:
  { regex: "api[_-]?key\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?([A-Za-z0-9_-]{16,})",  type: "api-key",     group: 1, check: "secret" },
  // token:
  { regex: "token\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?([A-Za-z0-9_-]{16,})",        type: "token",       group: 1, check: "secret" },
  // password, which may be letters alone:
  { regex: "password\\\\?[\"']?\\s*[:=]\\s*\\\\?[\"']?([^\\s\"'`,;}\\\\]{4,})", type: "password", group: 1, check: "placeholder" },
];

export const RULE_CREDENTIAL_IN_PARAMS: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_IN_PARAMS",
  version: "1.1.0",
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
