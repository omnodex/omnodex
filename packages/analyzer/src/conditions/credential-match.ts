// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * credential_match condition evaluator.
 *
 * Scans the JSON-serialized event parameters for credential-like patterns.
 * Returns a single MatchContext with all found credential type labels joined,
 * or an empty array when no credentials are detected.
 *
 * The actual credential values are never stored. Only the type labels (e.g.
 * "aws-key", "bearer") appear in risk findings so the event log itself never
 * becomes a credential store.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { CredentialMatchCondition, MatchContext } from "../types.js";
import { compiled } from "./regex-cache.js";
import { extractExecText, extractStagedContent } from "./scope.js";
import { extractPaths } from "./path-match.js";

/**
 * Scan a string for credential patterns and return the unique set of
 * matched type labels.
 *
 * All patterns are evaluated with flags "gi" (global, case-insensitive).
 * When a group index is specified, that capture group's value is used to
 * determine whether the match is non-trivially short, reducing false
 * positives on key= assignments with empty values.
 */
export function findCredentialTypes(
  text: string,
  patterns: CredentialMatchCondition["patterns"],
): string[] {
  const types = new Set<string>();

  for (const { regex, type, group, check } of patterns) {
    const re = compiled(regex, "gi");
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = group !== undefined ? (m[group] ?? "") : m[0];
      // Skip trivially short matches to reduce noise from partial patterns.
      if (value.length < 4) continue;
      if (check === "secret" && !looksLikeSecret(value)) continue;
      if (check === "placeholder" && isPlaceholder(value)) continue;
      types.add(type);
    }
  }

  return [...types];
}

/**
 * Words that mark a value as a stand-in rather than a secret. Matched
 * case-insensitively anywhere in the value.
 */
const PLACEHOLDER_WORDS = [
  "example", "sample", "placeholder", "dummy", "fake", "notreal", "notareal",
  "redacted", "changeme", "your", "xxxx", "****", "...",
];

/**
 * Vendor documentation keys that appear in docs, tutorials and tests, never
 * as live credentials. Stored without their vendor prefix so the literal is
 * not itself a credential-shaped string.
 */
const DOCUMENTATION_KEYS = [
  "4eC39HqLyjWDarjtT1zdp7dc", // Stripe API docs
  "16C7e42F292c6912E7710c838347Ae178B4a", // GitHub token docs
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // jwt.io example signature
];

/**
 * Values that name something in code rather than hold a secret, as in
 * `argon2id({ password: passphrase })` or `password = null`.
 */
const CODE_REFERENCES = new Set([
  "passphrase", "password", "passwd", "secret", "token", "value", "input",
  "undefined", "null", "none", "true", "false", "required", "string",
]);

/**
 * True when a value is a stand-in: a variable or template reference, an
 * angle-bracket or placeholder word, one character repeated, a run of
 * consecutive letters or digits ("abcdef", "123456"), words joined by
 * underscores or hyphens ("dev_stream_token_1"), or a code identifier.
 */
export function isPlaceholder(value: string): boolean {
  if (/^[$%]|\$\{|\$\(|\{\{|<|>/.test(value)) return true;
  if (/(.)\1{5,}/.test(value)) return true;
  if (hasSequentialRun(value, 6)) return true;
  // Readable words, optionally ending in a short number: an identifier.
  if (/^[a-z]+(?:[_-][a-z]+)+(?:[_-]?\d{1,4})?$/i.test(value)) return true;
  if (CODE_REFERENCES.has(value.toLowerCase()) || /^[a-z]+(?:[A-Z][a-z]+)+$/.test(value)) return true;
  const lower = value.toLowerCase();
  return PLACEHOLDER_WORDS.some((w) => lower.includes(w));
}

/** True when the value holds `length` consecutive ascending letters or digits. */
function hasSequentialRun(value: string, length: number): boolean {
  const lower = value.toLowerCase();
  let run = 1;
  for (let i = 1; i < lower.length; i++) {
    const step = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
    const sameClass = /[a-z]/.test(lower[i]!) === /[a-z]/.test(lower[i - 1]!);
    run = step === 1 && sameClass && /[a-z0-9]/.test(lower[i]!) ? run + 1 : 1;
    if (run >= length) return true;
  }
  return false;
}

/**
 * True when a matched value plausibly is a live secret: not a placeholder,
 * not a documentation key, and a mix of letters and digits, which every
 * generated token has and prose does not.
 */
export function looksLikeSecret(value: string): boolean {
  if (isPlaceholder(value)) return false;
  if (DOCUMENTATION_KEYS.some((k) => value.includes(k))) return false;
  return /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

/**
 * Evaluate a credential_match condition against a tool.invoked event.
 *
 * Returns a single-element array with the matched credential types when
 * credentials are found, or an empty array when none are detected.
 *
 * With scope "all" (the default) every parameter is scanned. With a list of
 * scopes only those texts are: "exec" is the command a shell tool runs,
 * "staged" is content written into a script or config file, "target" is
 * the file paths the call reads or writes. A staged match
 * carries the file's path, so the engine can report it as written, not run.
 */
export function evaluateCredentialMatch(
  condition: CredentialMatchCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const scope = condition.scope ?? "all";
  if (scope === "all") {
    const types = findCredentialTypes(JSON.stringify(event.parameters), condition.patterns);
    return types.length > 0 ? [{ credential_types: types }] : [];
  }

  if (scope.includes("exec")) {
    const command = extractExecText(event);
    if (command !== null) {
      const types = findCredentialTypes(command, condition.patterns);
      if (types.length > 0) return [{ credential_types: types }];
    }
  }
  if (scope.includes("target")) {
    const types = findCredentialTypes(extractPaths(event).join("\n"), condition.patterns);
    if (types.length > 0) return [{ credential_types: types }];
  }
  if (scope.includes("staged")) {
    for (const { path, text } of extractStagedContent(event)) {
      const types = findCredentialTypes(text, condition.patterns);
      if (types.length > 0) return [{ credential_types: types, staged_path: path }];
    }
  }
  return [];
}
