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
import type { CwdBoundaryCondition, EvaluationContext, MatchContext } from "../types.js";
import { extractPaths } from "./path-match.js";
import { extractWriteTargets } from "./write-targets.js";

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
 * Returns true if filePath is inside root (prefix match with directory
 * boundary check).
 */
function isInside(filePath: string, root: string): boolean {
  const normFile = normalizePath(filePath);
  const normRoot = normalizePath(root);
  return normFile === normRoot || normFile.startsWith(normRoot + "/");
}

/**
 * Evaluate a cwd_boundary condition against a tool.invoked event.
 *
 * Returns one partial MatchContext per file path outside every workspace
 * root (the host's roots from the context, or just the event's cwd). Empty
 * when the event has no cwd, names no absolute path, or stays inside.
 */
export function evaluateCwdBoundary(
  condition: CwdBoundaryCondition,
  event: ToolInvokedEvent,
  context: EvaluationContext = {},
): Partial<MatchContext>[] {
  // If cwd is not available, we can't evaluate this condition.
  // Return empty (condition does not match) rather than false positive.
  if (!event.cwd) return [];

  const paths = condition.access === "write" ? extractWriteTargets(event) : extractPaths(event);
  if (paths.length === 0) return [];

  const roots = context.workspaceRoots?.length ? context.workspaceRoots : [event.cwd];
  const results: Partial<MatchContext>[] = [];
  for (const raw of paths) {
    let p = raw;
    if ((p === "~" || p.startsWith("~/") || p.startsWith("~\\")) && context.home) {
      p = context.home + p.slice(1);
    }

    // Skip relative paths and variables: they are relative to cwd or unknown.
    if (!p.startsWith("/") && !p.startsWith("~") && !/^[A-Za-z]:/.test(p)) {
      continue;
    }

    // An unexpanded ~ path is outside unless a root is itself home-relative.
    if (p.startsWith("~")) {
      if (!roots.some((r) => r.startsWith("~"))) {
        results.push({
          matched_path: raw,
          matched_label: "file outside the workspace (home-relative path)",
        });
      }
      continue;
    }

    if (!roots.some((root) => isInside(p, root))) {
      results.push({
        matched_path: raw,
        matched_label: "file outside the workspace",
      });
    }
  }

  return results;
}
