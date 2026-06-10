// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * cwd_boundary condition evaluator.
 *
 * Matches when a file path extracted from the event is outside the
 * session's working directory (cwd). This detects agents writing or
 * reading files beyond the project boundary, which is a common signal
 * of both accidental misuse and deliberate attack.
 *
 * Requires the ToolInvokedEvent to have cwd populated (added in schema
 * version 1, optional field). Events without cwd never match.
 *
 * Path comparison is prefix-based: a file at /home/user/other/file.txt
 * is outside cwd=/home/user/project because the file path does not
 * start with the cwd. Both paths are normalized (trailing slashes
 * stripped, forward slashes enforced) before comparison.
 *
 * Yields one MatchContext per file path that is outside cwd, with
 * matched_path populated. Empty array if all paths are within cwd
 * or if no file paths are found.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { CwdBoundaryCondition, MatchContext } from "../types.js";
import { extractPaths } from "./path-match.js";

/**
 * Normalize a path for prefix comparison: lowercase on Windows-style
 * paths (drive letter), enforce forward slashes, strip trailing slash.
 */
function normalizePath(p: string): string {
  let normalized = p.replace(/\\/g, "/").replace(/\/+$/, "");
  // Don't lowercase the whole path (Unix is case-sensitive),
  // but handle Windows drive letters if present
  if (/^[A-Z]:/.test(normalized)) {
    normalized = normalized[0].toLowerCase() + normalized.slice(1);
  }
  return normalized;
}

/**
 * Returns true if filePath is inside cwdPath (prefix match with
 * directory boundary check).
 */
function isInsideCwd(filePath: string, cwdPath: string): boolean {
  const normFile = normalizePath(filePath);
  const normCwd = normalizePath(cwdPath);

  // Exact match (file IS the cwd, which shouldn't happen but handle it)
  if (normFile === normCwd) return true;

  // Prefix match: file must start with cwd + "/"
  return normFile.startsWith(normCwd + "/");
}

/**
 * Evaluate a cwd_boundary condition against a tool.invoked event.
 *
 * Returns one partial MatchContext per file path that is outside the
 * event's cwd. Empty array if:
 *   - event.cwd is not populated (backwards compatibility)
 *   - no file paths extracted from event
 *   - all file paths are within cwd
 */
export function evaluateCwdBoundary(
  _condition: CwdBoundaryCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  // If cwd is not available, we can't evaluate this condition.
  // Return empty (condition does not match) rather than false positive.
  if (!event.cwd) return [];

  const paths = extractPaths(event);
  if (paths.length === 0) return [];

  const results: Partial<MatchContext>[] = [];
  for (const p of paths) {
    // Skip relative paths (they're relative to cwd by definition)
    if (!p.startsWith("/") && !p.startsWith("~") && !/^[A-Za-z]:/.test(p)) {
      continue;
    }

    // Expand ~ to a generic home prefix for comparison
    // We don't know the actual home dir, but if cwd doesn't start with ~
    // then a ~/ path is definitionally outside cwd
    if (p.startsWith("~/") || p.startsWith("~\\")) {
      if (!event.cwd.startsWith("~/") && !event.cwd.startsWith("~\\")) {
        results.push({
          matched_path: p,
          matched_label: "file outside working directory (home-relative path)",
        });
        continue;
      }
    }

    if (!isInsideCwd(p, event.cwd)) {
      results.push({
        matched_path: p,
        matched_label: "file outside working directory",
      });
    }
  }

  return results;
}
