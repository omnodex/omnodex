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
 *
 * With access: "write" only the files the call writes to are tested, which
 * is what a rule about planting something in a file needs: reading that file
 * is not planting anything.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { MatchContext, PathMatchCondition } from "../types.js";
import { normalizeAction } from "../action.js";
import { compiled } from "./regex-cache.js";
import { isWriteTool, patchTargets } from "./scope.js";

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
 */
export function extractPaths(event: ToolInvokedEvent): string[] {
  const params = event.parameters;
  const paths: string[] = [];

  // Standard parameter keys across builtin and MCP filesystem tools.
  // Standard keys (Claude Code, Codex) and Antigravity file and directory keys.
  for (const key of ["file_path", "path", "filePath", "filename", "pattern", "DirectoryPath", "directory_path", "TargetFile", "AbsolutePath", "Path"]) {
    const val = params[key];
    if (typeof val === "string" && val.length > 0) paths.push(val);
  }

  // Patch targets are file references even when the sandbox denies the write.
  // Gate on the tool so quoted patch examples never become file operations.
  if (isWriteTool(event)) {
    const patch = [params.command, params.input, params.patch].find(
      (v): v is string => typeof v === "string" && v.includes("*** "),
    );
    if (patch) return [...new Set([...paths, ...patchTargets(patch)])];
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
  const action = normalizeAction(event);
  const paths = condition.access === "write"
    ? action.writes
    : condition.access === "read"
      ? action.paths.filter((p) => !action.writes.includes(p))
      : action.paths;
  const matched: Partial<MatchContext>[] = [];

  for (const p of paths) {
    for (const { regex, label, credential_type } of condition.patterns) {
      if (compiled(regex).test(p)) {
        matched.push({ matched_path: p, matched_label: label, ...(credential_type ? { path_credential_type: credential_type } : {}) });
        break; // One finding per path -- first matching pattern wins.
      }
    }
  }

  return matched;
}
