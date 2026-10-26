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
 *
 * The agent harness's own scratch folder for the event's session (Claude
 * Code's <temp>/claude-<uid>/<project>/<session id>/) counts as workspace:
 * the harness tells agents to write there. Other system temp folders are
 * judged separately: `temp: "exclude"` skips them and `temp: "only"`
 * judges nothing else, so a temp write can carry its own lower severity.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { CwdBoundaryCondition, EvaluationContext, MatchContext } from "../types.js";
import { normalizeAction } from "../action.js";

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

/** System temp folders by shape, on Linux, macOS and Windows (normalized paths). */
const TEMP_FOLDERS = [
  /^\/(?:private\/)?(?:var\/)?tmp(?:\/|$)/,
  /^\/(?:private\/)?var\/folders\/[^/]+\/[^/]+\/T(?:\/|$)/,
  /^[a-z]:\/users\/[^/]+\/appdata\/local\/temp(?:\/|$)/i,
  /^[a-z]:\/windows\/temp(?:\/|$)/i,
];

function isTemp(normPath: string, tempDirs: readonly string[]): boolean {
  return TEMP_FOLDERS.some((re) => re.test(normPath)) || tempDirs.some((d) => isInside(normPath, d));
}

/**
 * Whether a normalized path is in the harness's scratch folder for this
 * session: <temp>/claude-<uid>/<project>/<session id>/... Bound to the
 * session ID, so another session's scratch folder is still outside.
 */
function isSessionScratch(normPath: string, sessionId: string, tempDirs: readonly string[]): boolean {
  if (!sessionId) return false;
  const parts = normPath.split("/");
  const i = parts.indexOf(sessionId);
  if (i < 3 || !/^claude-\d+$/.test(parts[i - 2])) return false;
  return isTemp(parts.slice(0, i - 2).join("/"), tempDirs);
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

  const action = normalizeAction(event);
  const paths = condition.access === "write" ? action.writes : action.paths;
  if (paths.length === 0) return [];

  const roots = context.workspaceRoots?.length ? context.workspaceRoots : [event.cwd];
  const tempDirs = (context.tempDirs ?? []).map(normalizePath);
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
      if (condition.temp !== "only" && !roots.some((r) => r.startsWith("~"))) {
        results.push({
          matched_path: raw,
          matched_label: "file outside the workspace (home-relative path)",
        });
      }
      continue;
    }

    if (roots.some((root) => isInside(p, root))) continue;
    const norm = normalizePath(p);
    if (isSessionScratch(norm, event.session_id, tempDirs)) continue;
    const temp = isTemp(norm, tempDirs);
    if (condition.temp === "exclude" && temp) continue;
    if (condition.temp === "only" && !temp) continue;
    results.push({
      matched_path: raw,
      matched_label: temp ? "file in a temp folder outside the workspace" : "file outside the workspace",
    });
  }

  return results;
}
