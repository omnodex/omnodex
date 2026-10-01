// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * The connection graph as a tree: runtime, then server, then that server's
 * tools by call count. This module only shapes the data; the page lays it
 * out. Servers a session configured but never called are gathered into one
 * "idle" node per runtime so they stay visible without a column each.
 */

import type { CollapsedToolCallRow, SessionRow } from "@omnodex/projection";
import { BUILTIN_SERVER, type GraphPath } from "./filters.js";
import { runtimeLabel } from "./labels.js";

export type GraphNodeKind = "runtime" | "server" | "builtin" | "idle";

export interface ToolCount {
  name: string;
  calls: number;
}

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  calls: number;
  path: GraphPath;
  children: GraphNode[];
  /** Server and builtin nodes: tools by call count. Idle nodes: the uncalled servers. */
  tools?: ToolCount[];
}

/** Runtimes with their servers, each sorted by call count, busiest first. */
export function connectionTree(sessions: readonly SessionRow[], toolCalls: readonly CollapsedToolCallRow[]): GraphNode[] {
  const bySession = new Map(sessions.map((s) => [s.session_id, s]));
  const runtimes = new Map<string, Map<string, Map<string, number>>>();
  const configured = new Map<string, Set<string>>();

  for (const s of sessions) {
    const rt = runtimeLabel(s);
    if (!runtimes.has(rt)) runtimes.set(rt, new Map());
    const set = configured.get(rt) ?? new Set<string>();
    for (const srv of s.mcp_servers ?? []) set.add(srv);
    configured.set(rt, set);
  }
  for (const tc of toolCalls) {
    const rt = runtimeLabel(bySession.get(tc.session_id));
    const servers = runtimes.get(rt) ?? new Map<string, Map<string, number>>();
    runtimes.set(rt, servers);
    const tools = servers.get(tc.mcp_server) ?? new Map<string, number>();
    servers.set(tc.mcp_server, tools);
    tools.set(tc.tool_name, (tools.get(tc.tool_name) ?? 0) + 1);
  }

  const byCalls = (a: { calls: number; label?: string; name?: string }, b: { calls: number; label?: string; name?: string }) =>
    b.calls - a.calls || (a.label ?? a.name ?? "").localeCompare(b.label ?? b.name ?? "");

  const tree: GraphNode[] = [];
  for (const [rt, servers] of runtimes) {
    const children: GraphNode[] = [];
    for (const [server, tools] of servers) {
      const toolList = [...tools].map(([name, calls]) => ({ name, calls })).sort(byCalls);
      const calls = toolList.reduce((n, t) => n + t.calls, 0);
      children.push({
        id: `${rt}/${server}`,
        kind: server === BUILTIN_SERVER ? "builtin" : "server",
        label: server === BUILTIN_SERVER ? "Built-in tools" : server,
        calls,
        path: { runtime: rt, server },
        children: [],
        tools: toolList,
      });
    }
    children.sort(byCalls);
    const idle = [...(configured.get(rt) ?? [])].filter((srv) => srv !== BUILTIN_SERVER && !servers.has(srv)).sort();
    if (idle.length > 0) {
      children.push({
        id: `${rt}/\u0000idle`,
        kind: "idle",
        label: `${idle.length} idle server${idle.length === 1 ? "" : "s"}`,
        calls: 0,
        path: { runtime: rt },
        children: [],
        tools: idle.map((name) => ({ name, calls: 0 })),
      });
    }
    tree.push({ id: rt, kind: "runtime", label: rt, calls: children.reduce((n, c) => n + c.calls, 0), path: { runtime: rt }, children });
  }
  return tree.sort(byCalls);
}

/** True when the selection is this node or one of its ancestors. */
export function pathSelects(selected: GraphPath | null, node: GraphPath): boolean {
  if (!selected) return false;
  return selected.runtime === node.runtime && selected.server === node.server && selected.tool === node.tool;
}
