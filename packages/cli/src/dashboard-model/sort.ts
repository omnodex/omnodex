// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/** Sorting for the tool calls panel. */

import type { CollapsedToolCallRow } from "@omnodex/projection";

export type CallSortKey = "time" | "tool" | "server" | "status" | "duration" | "bytes";
export type SortDir = "asc" | "desc";

const VALUE: Record<CallSortKey, (tc: CollapsedToolCallRow) => string | number> = {
  time: (tc) => tc.started_at || "",
  tool: (tc) => tc.tool_name.toLowerCase(),
  server: (tc) => tc.mcp_server.toLowerCase(),
  status: (tc) => tc.status,
  duration: (tc) => tc.duration_ms ?? -1,
  bytes: (tc) => tc.response_bytes ?? -1,
};

/** A sorted copy; ties fall back to time, newest first. */
export function sortCalls(calls: readonly CollapsedToolCallRow[], key: CallSortKey, dir: SortDir): CollapsedToolCallRow[] {
  const get = VALUE[key];
  const sign = dir === "asc" ? 1 : -1;
  return [...calls].sort((a, b) => {
    const x = get(a), y = get(b);
    const c = x < y ? -1 : x > y ? 1 : 0;
    return c !== 0 ? c * sign : (b.started_at || "").localeCompare(a.started_at || "");
  });
}
