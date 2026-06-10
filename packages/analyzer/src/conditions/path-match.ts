// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * path_match condition evaluator.
 *
 * Extracts file paths from a tool.invoked event, then tests each path
 * against the rule's pattern list. Returns one MatchContext per matched
 * path so the engine can emit a separate finding for each sensitive access.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { MatchContext, PathMatchCondition } from "../types.js";

// ---------------------------------------------------------------------------
// Path extraction
// ---------------------------------------------------------------------------

/**
 * Extract file paths from a tool.invoked event's parameters.
 *
 * Covers:
 *   - Standard parameter keys used by builtin and MCP filesystem tools
 *   - Bash command strings: common file-reading/copying commands
 *
 * NOTE: Grep/Glob invocations expose the pattern string, not the individual
 * files read. Counting them as path references is a known approximation.
 * Accurate per-file read counting requires host-level syscall interception.
 * Accurate per-file read counting requires host-level syscall interception.
 */
export function extractPaths(event: ToolInvokedEvent): string[] {
  const params = event.parameters;
  const paths: string[] = [];

  // Standard parameter keys across builtin and MCP filesystem tools.
  // Standard keys (Claude Code, Codex) + Antigravity keys (DirectoryPath, Cwd, CommandLine)
  for (const key of ["file_path", "path", "filePath", "filename", "pattern", "DirectoryPath", "directory_path"]) {
    const val = params[key];
    if (typeof val === "string" && val.length > 0) paths.push(val);
  }

  // Bash/shell commands: extract paths from command strings heuristically.
  // Covers Claude Code "command", Antigravity "CommandLine", and similar.
  for (const cmdKey of ["command", "CommandLine"]) {
  if (typeof params[cmdKey] === "string") {
    const cmd = params[cmdKey] as string;
    const cmdPatterns = [
      /cat\s+([^\s|;&]+)/g,
      /less\s+([^\s|;&]+)/g,
      /head\s+(?:-\S+\s+)*([^\s|;&]+)/g,
      /tail\s+(?:-\S+\s+)*([^\s|;&]+)/g,
      /cp\s+(?:-\S+\s+)*([^\s|;&]+)/g,
      /scp\s+(?:-\S+\s+)*([^\s|;&]+)/g,
    ];
    for (const re of cmdPatterns) {
      let m;
      while ((m = re.exec(cmd)) !== null) {
        if (m[1]) paths.push(m[1]);
      }
    }
  }
  }

  return paths;
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a path_match condition against a tool.invoked event.
 *
 * Returns one partial MatchContext per path that matches any pattern.
 * An empty array means no match (the condition fails).
 */
export function evaluatePathMatch(
  condition: PathMatchCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const paths = extractPaths(event);
  const matched: Partial<MatchContext>[] = [];

  for (const p of paths) {
    for (const { regex, label } of condition.patterns) {
      if (new RegExp(regex).test(p)) {
        matched.push({ matched_path: p, matched_label: label });
        break; // One finding per path -- first matching pattern wins.
      }
    }
  }

  return matched;
}
