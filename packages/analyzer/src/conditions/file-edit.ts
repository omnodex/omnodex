// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * file_edit condition evaluator.
 *
 * Looks at what a file-writing call does to the text of each file it
 * touches, file by file, so a pattern found in one file of a multi-file
 * patch is never paired with a path from another.
 *
 *   removed -- the pattern is in the text the call replaces and not in the
 *              text it puts in its place (Edit, MultiEdit, the removed
 *              lines of an apply_patch hunk)
 *   added   -- the pattern is in the new text and not in the text it
 *              replaces; a full write counts as all new text
 *   absent  -- the call writes the whole file and the pattern is not in
 *              it: a Write, a patch that adds the file, or a patch that
 *              deletes it. What the file held before is unknown, so this
 *              means "may have removed"
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { FileEditCondition, MatchContext } from "../types.js";
import { compiled } from "./regex-cache.js";
import { isWriteTool } from "./scope.js";

/** Antigravity's file tools, which name their fields differently. */
const ANTIGRAVITY_WRITE_TOOLS = new Set(["write_to_file", "replace_file_content", "multi_replace_file_content"]);

/** What one call does to one file. */
interface FileChange {
  path: string;
  /** Text the call replaces; empty for a full write. */
  before: string;
  /** Text the call writes. */
  after: string;
  /** True when the call sets the whole file (write, add, delete). */
  whole: boolean;
}

const PATH_KEYS = ["file_path", "path", "filePath", "filename", "notebook_path", "TargetFile"];

function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** Per-file hunks of an apply_patch body. */
function patchChanges(patch: string): FileChange[] {
  const out: FileChange[] = [];
  let current: FileChange | null = null;
  for (const line of patch.split("\n")) {
    const header = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line);
    if (header) {
      current = { path: header[2].trim(), before: "", after: "", whole: header[1] !== "Update" };
      out.push(current);
      continue;
    }
    if (/^\*\*\* /.test(line)) {
      current = null;
      continue;
    }
    if (!current) continue;
    if (line.startsWith("-")) current.before += line.slice(1) + "\n";
    else if (line.startsWith("+")) current.after += line.slice(1) + "\n";
  }
  return out;
}

/** What a file-writing call does to each file it touches. */
export function extractFileChanges(event: ToolInvokedEvent): FileChange[] {
  if (!isWriteTool(event) && !ANTIGRAVITY_WRITE_TOOLS.has(event.tool_name.toLowerCase())) return [];
  const params = (event.parameters ?? {}) as Record<string, unknown>;

  const patch = [params.command, params.input, params.patch].find(
    (v): v is string => typeof v === "string" && v.includes("*** "),
  );
  if (patch) return patchChanges(patch);

  const path = PATH_KEYS.map((k) => str(params[k])).find((v): v is string => v !== null);
  if (!path) return [];

  const content = str(params.content) ?? str(params.text) ?? str(params.CodeContent);
  if (content !== null) return [{ path, before: "", after: content, whole: true }];

  const pairs: [unknown, unknown][] = [
    [params.old_string, params.new_string],
    [params.TargetContent, params.ReplacementContent],
  ];
  if (Array.isArray(params.edits)) {
    for (const edit of params.edits as Record<string, unknown>[]) pairs.push([edit?.old_string, edit?.new_string]);
  }
  if (Array.isArray(params.ReplacementChunks)) {
    for (const chunk of params.ReplacementChunks as Record<string, unknown>[]) pairs.push([chunk?.TargetContent, chunk?.ReplacementContent]);
  }
  let before = "";
  let after = "";
  for (const [o, n] of pairs) {
    if (typeof o === "string") before += o + "\n";
    if (typeof n === "string") after += n + "\n";
  }
  return before || after ? [{ path, before, after, whole: false }] : [];
}

/**
 * Evaluate a file_edit condition. One context per file that matches, naming
 * the file as {{matched_path}} and the pattern's label as {{matched_label}}.
 */
export function evaluateFileEdit(
  condition: FileEditCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const out: Partial<MatchContext>[] = [];
  for (const change of extractFileChanges(event)) {
    const p = change.path.replace(/\\/g, "/");
    if (!condition.paths.some(({ regex }) => compiled(regex).test(p))) continue;
    if (condition.when !== undefined && !compiled(condition.when).test(change.after)) continue;
    for (const { regex, label } of condition.patterns) {
      const re = compiled(regex);
      const inBefore = re.test(change.before);
      const inAfter = re.test(change.after);
      const hit =
        condition.change === "removed" ? !change.whole && inBefore && !inAfter
        : condition.change === "added" ? inAfter && !inBefore
        : change.whole && !inAfter;
      if (hit) {
        out.push({ matched_path: change.path, matched_label: label });
        break;
      }
    }
  }
  return out;
}
