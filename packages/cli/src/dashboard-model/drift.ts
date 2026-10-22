// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What a drift finding says changed about an MCP server, for the detail
 * panel. The finding carries tool names and change kinds; the before and
 * after text comes from the tool lists the MCP proxy kept on this machine,
 * looked up by the fingerprints in the finding.
 */

import type { EvidenceDrift } from "@omnodex/shared";

export { driftSummaryRows, type DriftSummaryRow } from "@omnodex/shared";

/** A tool's text as the agent is given it. */
export interface ToolText {
  description: string;
  /** The input schema as indented JSON. */
  schema: string;
}

/** One tool in the before and after. Only the fields that differ are compared. */
export interface ToolChange {
  name: string;
  kind: "added" | "removed" | "changed";
  before?: ToolText;
  after?: ToolText;
  descriptionChanged: boolean;
  schemaChanged: boolean;
}

function toolText(list: readonly unknown[] | undefined, name: string): ToolText | undefined {
  const tool = list?.find((t): t is Record<string, unknown> => !!t && typeof t === "object" && (t as { name?: unknown }).name === name);
  if (!tool) return undefined;
  return {
    description: typeof tool.description === "string" ? tool.description : "",
    schema: tool.inputSchema === undefined ? "" : JSON.stringify(tool.inputSchema, null, 2),
  };
}

/**
 * The before and after of each tool the finding names, from the kept tool
 * lists. A side is missing when its list was not kept (pruned, or captured
 * on another machine); the change is still listed by name.
 */
export function toolChanges(drift: EvidenceDrift, before?: readonly unknown[], after?: readonly unknown[]): ToolChange[] {
  const entry = (name: string, kind: ToolChange["kind"]): ToolChange => {
    const b = kind === "added" ? undefined : toolText(before, name);
    const a = kind === "removed" ? undefined : toolText(after, name);
    return {
      name,
      kind,
      ...(b ? { before: b } : {}),
      ...(a ? { after: a } : {}),
      descriptionChanged: kind === "changed" && !!b && !!a && b.description !== a.description,
      schemaChanged: kind === "changed" && !!b && !!a && b.schema !== a.schema,
    };
  };
  return [
    ...drift.tools_changed.map((n) => entry(n, "changed")),
    ...drift.tools_added.map((n) => entry(n, "added")),
    ...drift.tools_removed.map((n) => entry(n, "removed")),
  ];
}

/** One line of a line diff, or a run of unchanged lines left out. */
export type DiffLine =
  | { kind: "same" | "added" | "removed"; text: string }
  | { kind: "skipped"; count: number };

/**
 * The lines of `after` against `before`, with `context` unchanged lines
 * kept around each change and longer unchanged runs left out.
 */
export function lineDiff(before: string, after: string, context = 2): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  // Past a size a page should not spend on, every line counts as changed.
  if (a.length * b.length > 1_000_000) {
    return [...a.map((text) => ({ kind: "removed" as const, text })), ...b.map((text) => ({ kind: "added" as const, text }))];
  }
  // Longest common subsequence table, from the end.
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const all: { kind: "same" | "added" | "removed"; text: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      all.push({ kind: "same", text: a[i]! });
      i++;
      j++;
    } else if (i < a.length && (j >= b.length || lcs[i + 1]![j]! >= lcs[i]![j + 1]!)) {
      all.push({ kind: "removed", text: a[i]! });
      i++;
    } else {
      all.push({ kind: "added", text: b[j]! });
      j++;
    }
  }
  const near = all.map((_, k) => all.slice(Math.max(0, k - context), k + context + 1).some((l) => l.kind !== "same"));
  const out: DiffLine[] = [];
  for (let k = 0; k < all.length; k++) {
    if (near[k]) {
      out.push(all[k]!);
      continue;
    }
    const last = out[out.length - 1];
    if (last?.kind === "skipped") last.count++;
    else out.push({ kind: "skipped", count: 1 });
  }
  return out;
}
