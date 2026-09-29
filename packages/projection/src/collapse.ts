// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Collapse the two observations of one routed tool call into one, for
 * readers that show what an agent did.
 *
 * A call routed through the MCP proxy is recorded twice: by the platform
 * hook in the agent's session, and by the proxy in a session of its own.
 * The correlation pass (correlate.ts) stamps both rows, and any finding
 * either host raised on them, with a shared correlation_id. The read model
 * keeps both rows, because both observations are real; this is where a
 * reader turns the pair into the one call a person means.
 *
 * The kept call lives in the agent's session. The proxy's session keeps its
 * own identity, but its correlated calls and findings move out of it, or
 * every total above session level would count them twice. Session
 * tool_call_count and risk_score are recomputed from what remains.
 */

import { riskScoreFor, roundRiskScore } from "@omnodex/shared";
import {
  findingKey,
  type FileEventRow,
  type ReadModelStore,
  type RiskEventRow,
  type SessionRow,
  type ToolCallRow,
} from "./read-model.js";

/** A tool call as a reader sees it: a correlated pair carries both sources. */
export interface CollapsedToolCallRow extends ToolCallRow {
  /** Interceptors that observed the call, in display order. Only on merged rows. */
  sources?: string[];
}

/** Everything a dashboard reads, keyed by session like the sync payload. */
export interface ReadModelSnapshot {
  sessions: SessionRow[];
  tool_calls: Record<string, CollapsedToolCallRow[]>;
  file_events: Record<string, FileEventRow[]>;
  risk_events: Record<string, RiskEventRow[]>;
}

/** Read every session and its rows from a store. */
export async function readSnapshot(store: ReadModelStore): Promise<ReadModelSnapshot> {
  const sessions = await store.listSessions();
  const snapshot: ReadModelSnapshot = { sessions, tool_calls: {}, file_events: {}, risk_events: {} };
  for (const { session_id: id } of sessions) {
    snapshot.tool_calls[id] = await store.listToolCalls(id);
    snapshot.file_events[id] = await store.listFileEvents(id);
    snapshot.risk_events[id] = await store.listRiskEvents(id);
  }
  return snapshot;
}

/** Collapse correlated calls, then the findings on them. */
export function collapseCorrelated(snapshot: ReadModelSnapshot): ReadModelSnapshot {
  return collapseCorrelatedFindings(collapseCorrelatedToolCalls(snapshot));
}

const PROXY = "mcp-proxy";
const SOURCE_ORDER = ["claude-code-hook", "codex-hook", "antigravity-hook", PROXY];

function sortSources(sources: Iterable<string>): string[] {
  const rank = (s: string): number => {
    const i = SOURCE_ORDER.indexOf(s);
    return i < 0 ? SOURCE_ORDER.length : i;
  };
  return [...new Set(sources)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/**
 * Merge the rows of one correlated call. Attribution comes from the row that
 * is not the proxy's: that is the call the agent made, under its own name.
 * Timing and outcome come from the proxy's, which measured the upstream
 * round trip; an error on either side is an error, because the hook fires
 * before the call is forwarded and cannot see the upstream fail.
 */
function mergeRows(rows: CollapsedToolCallRow[]): CollapsedToolCallRow {
  const proxy = rows.find((r) => r.interceptor === PROXY);
  const primary = rows.find((r) => r.interceptor !== PROXY) ?? rows[0];
  const merged: CollapsedToolCallRow = {
    ...primary,
    sources: sortSources(rows.flatMap((r) => r.sources ?? [r.interceptor ?? "unknown"])),
  };
  if (proxy && proxy !== primary) {
    if (proxy.duration_ms != null) merged.duration_ms = proxy.duration_ms;
    if (proxy.response_bytes != null) merged.response_bytes = proxy.response_bytes;
    if (proxy.ended_at) merged.ended_at = proxy.ended_at;
    if (proxy.status === "error") {
      merged.status = "error";
      merged.error_message = proxy.error_message ?? merged.error_message;
    } else if (merged.status === "in_progress") {
      merged.status = proxy.status;
    }
    if (!primary.mcp_server) merged.mcp_server = proxy.mcp_server;
  }
  return merged;
}

/** Each correlated pair appears once, in the agent's session. */
export function collapseCorrelatedToolCalls(snapshot: ReadModelSnapshot): ReadModelSnapshot {
  const groups = new Map<string, CollapsedToolCallRow[]>();
  for (const rows of Object.values(snapshot.tool_calls)) {
    for (const row of rows) {
      if (!row.correlation_id) continue;
      const bucket = groups.get(row.correlation_id);
      if (bucket) bucket.push(row);
      else groups.set(row.correlation_id, [row]);
    }
  }
  if (groups.size === 0) return snapshot;

  const merged = new Map<string, CollapsedToolCallRow>();
  for (const [id, rows] of groups) merged.set(id, mergeRows(rows));

  const toolCalls: ReadModelSnapshot["tool_calls"] = {};
  for (const [sid, rows] of Object.entries(snapshot.tool_calls)) {
    const kept: CollapsedToolCallRow[] = [];
    const emitted = new Set<string>();
    for (const row of rows) {
      if (!row.correlation_id) {
        kept.push(row);
        continue;
      }
      const call = merged.get(row.correlation_id)!;
      if (call.session_id !== sid || emitted.has(row.correlation_id)) continue;
      emitted.add(row.correlation_id);
      kept.push(call);
    }
    toolCalls[sid] = kept;
  }

  const sessions = snapshot.sessions.map((s) => {
    const rows = toolCalls[s.session_id];
    return !rows || rows.length === s.tool_call_count ? s : { ...s, tool_call_count: rows.length };
  });
  return { ...snapshot, tool_calls: toolCalls, sessions };
}

/**
 * A finding two hosts raised on one routed call appears once, with its call
 * in the agent's session, repointed at the call that survived. A finding
 * only one host raised moves with its call. Session risk scores are
 * recomputed for the sessions that gained or lost findings.
 */
export function collapseCorrelatedFindings(snapshot: ReadModelSnapshot): ReadModelSnapshot {
  // Where each correlated call lives once collapsed: the agent's session.
  const homes = new Map<string, { sessionId: string; toolCallId: string }>();
  for (const [sid, rows] of Object.entries(snapshot.tool_calls)) {
    for (const row of rows) {
      if (!row.correlation_id) continue;
      if (!homes.has(row.correlation_id) || row.interceptor !== PROXY) {
        homes.set(row.correlation_id, { sessionId: sid, toolCallId: row.tool_call_id });
      }
    }
  }

  const next = new Map<string, RiskEventRow[]>(Object.keys(snapshot.risk_events).map((sid) => [sid, []]));
  const kept = new Set<string>();
  const changed = new Set<string>();

  // Home sessions first, so where two hosts raised one rule, the copy
  // already in the right session is the one kept.
  const homeSessions = new Set([...homes.values()].map((h) => h.sessionId));
  const order = Object.keys(snapshot.risk_events).sort(
    (a, b) => (homeSessions.has(a) ? 0 : 1) - (homeSessions.has(b) ? 0 : 1),
  );

  for (const sid of order) {
    for (const row of snapshot.risk_events[sid] ?? []) {
      const key = findingKey(row);
      if (kept.has(key)) {
        changed.add(sid);
        continue;
      }
      kept.add(key);
      const home = row.correlation_id ? homes.get(row.correlation_id) : undefined;
      if (!home || (home.sessionId === sid && home.toolCallId === row.related_event_id)) {
        next.get(sid)!.push(row);
        continue;
      }
      changed.add(sid);
      changed.add(home.sessionId);
      const bucket = next.get(home.sessionId) ?? [];
      bucket.push({ ...row, session_id: home.sessionId, related_event_id: home.toolCallId });
      next.set(home.sessionId, bucket);
    }
  }
  if (changed.size === 0) return snapshot;

  const riskEvents = Object.fromEntries(next);
  const sessions = snapshot.sessions.map((s) => {
    if (!changed.has(s.session_id)) return s;
    const score = roundRiskScore(
      (riskEvents[s.session_id] ?? []).reduce((sum, r) => sum + riskScoreFor(r.severity), 0),
    );
    return score === s.risk_score ? s : { ...s, risk_score: score };
  });
  return { ...snapshot, risk_events: riskEvents, sessions };
}
