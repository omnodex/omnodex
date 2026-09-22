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

  for (const { regex, type, group } of patterns) {
    const re = compiled(regex, "gi");
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = group !== undefined ? (m[group] ?? "") : m[0];
      // Skip trivially short matches to reduce noise from partial patterns.
      if (value.length >= 4) {
        types.add(type);
      }
    }
  }

  return [...types];
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
