// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * Filters for the local dashboard: which sessions, and which of their rows,
 * the page shows. Sessions are narrowed by runtime, status, risk, root,
 * time range and the browser's hidden list; rows by time range and by the
 * node selected in the connection graph.
 */

import type { RiskSeverity } from "@omnodex/shared";
import { riskBandFor } from "@omnodex/shared";
import type { SessionRow } from "@omnodex/projection";
import { runtimeLabel } from "./labels.js";
import type { SessionView } from "./view.js";

/** The server name hooks give a runtime's own tools (Bash, Read, Edit...). */
export const BUILTIN_SERVER = "builtin";

/** Time range presets, in milliseconds back from now; null is all time. */
export const TIME_RANGES = {
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 7 * 86_400_000,
  "30d": 30 * 86_400_000,
  all: null,
} as const satisfies Record<string, number | null>;
export type TimeRangeKey = keyof typeof TIME_RANGES;

/** Lowest band a session's risk must reach; "any" includes sessions with none. */
export type RiskFloor = "any" | RiskSeverity;
const BAND_ORDER: readonly RiskSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** A node selected in the connection graph: a runtime, and optionally a server and tool. */
export interface GraphPath {
  runtime?: string;
  server?: string;
  tool?: string;
}

export interface DashboardFilters {
  /** Runtime labels to show; empty shows all. */
  runtimes: readonly string[];
  /** Session statuses to show; empty shows all. */
  statuses: readonly string[];
  risk: RiskFloor;
  time: TimeRangeKey;
  /** Source roots to show; empty shows all. */
  roots: readonly string[];
  /** Session ids hidden in this browser. */
  hidden: readonly string[];
  showHidden: boolean;
  graph: GraphPath | null;
}

export const NO_FILTERS: DashboardFilters = {
  runtimes: [], statuses: [], risk: "any", time: "all", roots: [], hidden: [], showHidden: false, graph: null,
};

/** True when anything but the hidden list narrows the page. */
export function isFiltered(f: DashboardFilters): boolean {
  return f.runtimes.length > 0 || f.statuses.length > 0 || f.risk !== "any" || f.time !== "all" || f.roots.length > 0 || f.graph !== null;
}

/** The start of the time range, or null for all time. */
export function rangeStart(time: TimeRangeKey, now: number): number | null {
  const span = TIME_RANGES[time];
  return span === null ? null : now - span;
}

function riskReaches(score: number, floor: RiskFloor): boolean {
  if (floor === "any") return true;
  const band = riskBandFor(score || 0);
  return band !== null && BAND_ORDER.indexOf(band) >= BAND_ORDER.indexOf(floor);
}

/** Sessions that pass the session-level filters. */
export function filterSessions(sessions: readonly SessionRow[], f: DashboardFilters, now: number): SessionRow[] {
  const start = rangeStart(f.time, now);
  const hidden = new Set(f.hidden);
  return sessions.filter((s) => {
    if (!f.showHidden && hidden.has(s.session_id)) return false;
    if (f.runtimes.length && !f.runtimes.includes(runtimeLabel(s))) return false;
    if (f.statuses.length && !f.statuses.includes(s.status)) return false;
    if (f.roots.length && !f.roots.includes(s.source_root ?? "")) return false;
    if (!riskReaches(s.risk_score, f.risk)) return false;
    if (start !== null && Date.parse(s.last_event_at || s.started_at) < start) return false;
    return true;
  });
}

/**
 * Rows of a view narrowed to the time range and the graph selection. A
 * finding follows its call: it stays when the call it fired on stays.
 */
export function narrowView(view: SessionView, f: DashboardFilters, now: number): SessionView {
  const start = rangeStart(f.time, now);
  const inRange = (iso: string | null | undefined) => start === null || (iso ? Date.parse(iso) >= start : false);
  const runtimeOf = new Map(view.sessions.map((s) => [s.session_id, runtimeLabel(s)]));
  const g = f.graph;
  const toolCalls = view.toolCalls.filter((tc) => {
    if (!inRange(tc.started_at)) return false;
    if (!g) return true;
    if (g.runtime && runtimeOf.get(tc.session_id) !== g.runtime) return false;
    if (g.server && tc.mcp_server !== g.server) return false;
    if (g.tool && tc.tool_name !== g.tool) return false;
    return true;
  });
  const kept = new Set(toolCalls.map((tc) => tc.tool_call_id));
  const riskEvents = view.riskEvents.filter((r) => inRange(r.detected_at) && (!g || kept.has(r.related_event_id)));
  // File events come from the runtime's own tools, so an MCP server or tool
  // selection leaves none.
  const fileEvents = view.fileEvents.filter((e) =>
    inRange(e.at) &&
    (!g?.runtime || runtimeOf.get(e.session_id) === g.runtime) &&
    (!g?.server || g.server === BUILTIN_SERVER) &&
    !g?.tool);
  // Prompts and subagents belong to the agent, not to a server or tool, so
  // only a runtime selection keeps them.
  const agentLevel = (sessionId: string) => !g || (!g.server && !g.tool && (!g.runtime || runtimeOf.get(sessionId) === g.runtime));
  const prompts = view.prompts.filter((p) => inRange(p.at) && agentLevel(p.session_id));
  const subagents = view.subagents.filter((a) => inRange(a.started_at ?? a.ended_at) && agentLevel(a.session_id));
  return { ...view, toolCalls, riskEvents, fileEvents, prompts, subagents };
}

/** Distinct values to offer in the filter menus, sorted. */
export function filterOptions(sessions: readonly SessionRow[]): { runtimes: string[]; statuses: string[]; roots: string[] } {
  const runtimes = new Set<string>();
  const statuses = new Set<string>();
  const roots = new Set<string>();
  for (const s of sessions) {
    runtimes.add(runtimeLabel(s));
    statuses.add(s.status);
    if (s.source_root) roots.add(s.source_root);
  }
  return { runtimes: [...runtimes].sort(), statuses: [...statuses].sort(), roots: [...roots].sort() };
}
