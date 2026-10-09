// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * What the dashboard shows for a selection: one session, or every session
 * with activity merged. Works on the collapsed snapshot the server returns,
 * so a routed call is one call and one finding everywhere on the page.
 */

import type { FileEventRow, PromptRow, ReadModelSnapshot, RiskEventRow, SessionRow, SubagentRow } from "@omnodex/projection";
import type { CollapsedToolCallRow } from "@omnodex/projection";
import { riskScoreFor } from "@omnodex/shared";
import { totalEvents } from "./labels.js";

/** The selection value for every session with activity. */
export const ALL_SESSIONS = "__all_active__";

export interface SessionView {
  /** The session selected, or null for all sessions. */
  session: SessionRow | null;
  /** The sessions the view covers. */
  sessions: SessionRow[];
  toolCalls: CollapsedToolCallRow[];
  fileEvents: FileEventRow[];
  riskEvents: RiskEventRow[];
  prompts: PromptRow[];
  subagents: SubagentRow[];
}

/**
 * True when a session holds any activity: a call, a file read or write, a
 * prompt, a finding or a subagent. The hosted dashboard uses the same rule.
 * A session without any is mostly an MCP proxy that a client started,
 * listed tools from and closed, which some desktop apps do several times an
 * hour; it is not listed, counted or offered in the filter menus.
 */
export function hasActivity(snapshot: ReadModelSnapshot, s: SessionRow): boolean {
  const id = s.session_id;
  return totalEvents(s) > 0 || !!snapshot.tool_calls[id]?.length || !!snapshot.file_events[id]?.length
    || !!snapshot.risk_events[id]?.length || !!snapshot.prompts?.[id]?.length || !!snapshot.subagents?.[id]?.length;
}

/** Sessions worth listing: those with any activity. */
export function listedSessions(snapshot: ReadModelSnapshot): SessionRow[] {
  return snapshot.sessions.filter((s) => hasActivity(snapshot, s));
}

/**
 * The rows for a selection. All sessions lists calls and findings newest
 * first; one session keeps the order the snapshot holds.
 */
export function selectView(snapshot: ReadModelSnapshot, selection: string): SessionView {
  if (selection !== ALL_SESSIONS) {
    const session = snapshot.sessions.find((s) => s.session_id === selection) ?? null;
    if (!session) return { session: null, sessions: [], toolCalls: [], fileEvents: [], riskEvents: [], prompts: [], subagents: [] };
    const id = session.session_id;
    return {
      session,
      sessions: [session],
      toolCalls: [...(snapshot.tool_calls[id] ?? [])],
      fileEvents: [...(snapshot.file_events[id] ?? [])],
      riskEvents: [...(snapshot.risk_events[id] ?? [])],
      prompts: [...(snapshot.prompts?.[id] ?? [])],
      subagents: [...(snapshot.subagents?.[id] ?? [])],
    };
  }
  const sessions = listedSessions(snapshot);
  const toolCalls = sessions.flatMap((s) => snapshot.tool_calls[s.session_id] ?? []);
  const fileEvents = sessions.flatMap((s) => snapshot.file_events[s.session_id] ?? []);
  const riskEvents = sessions.flatMap((s) => snapshot.risk_events[s.session_id] ?? []);
  const prompts = sessions.flatMap((s) => snapshot.prompts?.[s.session_id] ?? []);
  const subagents = sessions.flatMap((s) => snapshot.subagents?.[s.session_id] ?? []);
  toolCalls.sort((a, b) => (b.started_at || "").localeCompare(a.started_at || ""));
  riskEvents.sort((a, b) => (b.detected_at || "").localeCompare(a.detected_at || ""));
  return { session: null, sessions, toolCalls, fileEvents, riskEvents, prompts, subagents };
}

export interface ViewTotals {
  toolCalls: number;
  fileReads: number;
  fileWrites: number;
  risk: number;
  mcpServers: number;
  sessions: number;
}

/** The stats row: session counters summed over the view. */
export function viewTotals(sessions: readonly SessionRow[]): ViewTotals {
  const servers = new Set<string>();
  let toolCalls = 0, fileReads = 0, fileWrites = 0, risk = 0;
  for (const s of sessions) {
    toolCalls += s.tool_call_count || 0;
    fileReads += s.file_read_count || 0;
    fileWrites += s.file_write_count || 0;
    risk += s.risk_score || 0;
    for (const srv of s.mcp_servers ?? []) servers.add(srv);
  }
  return { toolCalls, fileReads, fileWrites, risk, mcpServers: servers.size, sessions: sessions.length };
}

/**
 * The stats row from the rows shown, for when a time range or a graph
 * selection covers only part of each session, so session totals would
 * overstate it.
 */
export function rowTotals(view: SessionView): ViewTotals {
  const servers = new Set(view.toolCalls.map((tc) => tc.mcp_server).filter((s) => s && s !== "builtin"));
  const sessions = new Set([...view.toolCalls, ...view.fileEvents, ...view.riskEvents].map((r) => r.session_id));
  return {
    toolCalls: view.toolCalls.length,
    fileReads: view.fileEvents.filter((e) => e.direction === "read").length,
    fileWrites: view.fileEvents.filter((e) => e.direction === "write").length,
    risk: view.riskEvents.reduce((n, r) => n + riskScoreFor(r.severity), 0),
    mcpServers: servers.size,
    sessions: sessions.size,
  };
}

export type { CollapsedToolCallRow, FileEventRow, PromptRow, ReadModelSnapshot, RiskEventRow, SessionRow, SubagentRow };
