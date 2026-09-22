// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * In-memory ReadModelStore. Zero dependencies. Used by tests and by the
 * default CLI wiring when no persistent store is configured.
 */

import { roundRiskScore } from "@omnodex/shared";
import type {
  FileEventRow,
  ReadModelStore,
  RiskEventRow,
  SessionRow,
  ToolCallRow,
} from "./read-model.js";

/**
 * Natural key of a risk finding. A finding is identified by what it says
 * about which target in which session, not by the event that reported it,
 * so two analyzer passes over one tool call collapse onto a single row.
 * Mirrors the unique index in SqliteReadModelStore.
 */
function riskFindingKey(row: RiskEventRow): string {
  return `${row.session_id}::${row.rule_id}::${row.related_event_id}`;
}

export class InMemoryReadModelStore implements ReadModelStore {
  private sessions = new Map<string, SessionRow>();
  private toolCalls = new Map<string, ToolCallRow>();
  private fileEvents: FileEventRow[] = [];
  private riskEvents: RiskEventRow[] = [];
  /** Stand-ins for the unique indexes the SQLite store gets from the schema. */
  private fileEventIds = new Set<string>();
  private riskFindingKeys = new Set<string>();

  async reset(): Promise<void> {
    this.sessions.clear();
    this.toolCalls.clear();
    this.fileEvents = [];
    this.riskEvents = [];
    this.fileEventIds.clear();
    this.riskFindingKeys.clear();
  }

  async upsertSession(row: SessionRow): Promise<void> {
    const existing = this.sessions.get(row.session_id);
    if (!existing) {
      this.sessions.set(row.session_id, { ...row });
      return;
    }
    // The counters belong to the events that moved them, not to the session
    // row being upserted, which always carries zeroes. Overwriting them here
    // let a repeated session.started reset a session's totals to nothing.
    // SqliteReadModelStore keeps them by leaving them out of its ON CONFLICT
    // update; this is the same rule spelled out.
    this.sessions.set(row.session_id, {
      ...row,
      tool_call_count: existing.tool_call_count,
      file_read_count: existing.file_read_count,
      file_write_count: existing.file_write_count,
      risk_score: existing.risk_score,
    });
  }

  async patchSession(
    sessionId: string,
    patch: Partial<Omit<SessionRow, "session_id">>,
  ): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (!existing) return;
    this.sessions.set(sessionId, { ...existing, ...patch });
  }

  async incrementSessionCounter(
    sessionId: string,
    field: "tool_call_count" | "file_read_count" | "file_write_count",
    delta: number,
  ): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (!existing) return;
    existing[field] = existing[field] + delta;
  }

  async addToRiskScore(sessionId: string, delta: number): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (!existing) return;
    // Matches the ROUND in SqliteReadModelStore, so the two stores agree on
    // the score as well as on the rows.
    existing.risk_score = roundRiskScore(existing.risk_score + delta);
  }

  async insertToolCall(row: ToolCallRow): Promise<boolean> {
    if (this.toolCalls.has(row.tool_call_id)) return false;
    this.toolCalls.set(row.tool_call_id, { ...row });
    return true;
  }

  async patchToolCall(
    toolCallId: string,
    patch: Partial<Omit<ToolCallRow, "tool_call_id" | "session_id">>,
  ): Promise<void> {
    const existing = this.toolCalls.get(toolCallId);
    if (!existing) return;
    this.toolCalls.set(toolCallId, { ...existing, ...patch });
  }

  async addMcpServer(sessionId: string, mcpServer: string): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (!existing) return;
    if (existing.mcp_servers.includes(mcpServer)) return;
    existing.mcp_servers = [...existing.mcp_servers, mcpServer];
  }

  async insertFileEvent(row: FileEventRow): Promise<boolean> {
    if (this.fileEventIds.has(row.event_id)) return false;
    this.fileEventIds.add(row.event_id);
    this.fileEvents.push({ ...row });
    return true;
  }

  async insertRiskEvent(row: RiskEventRow): Promise<boolean> {
    const key = riskFindingKey(row);
    if (this.riskFindingKeys.has(key)) return false;
    this.riskFindingKeys.add(key);
    this.riskEvents.push({ ...row });
    return true;
  }

  async setRiskCorrelation(relatedEventIds: readonly string[], correlationId: string): Promise<number> {
    const ids = new Set(relatedEventIds);
    let changed = 0;
    for (const row of this.riskEvents) {
      if (ids.has(row.related_event_id) && row.correlation_id !== correlationId) {
        row.correlation_id = correlationId;
        changed++;
      }
    }
    return changed;
  }

  async getSession(sessionId: string): Promise<SessionRow | null> {
    const row = this.sessions.get(sessionId);
    return row ? { ...row } : null;
  }

  async listSessions(): Promise<SessionRow[]> {
    return [...this.sessions.values()]
      .sort((a, b) => (b.last_event_at || '').localeCompare(a.last_event_at || ''))
      .map((r) => ({ ...r }));
  }

  async listToolCalls(sessionId: string): Promise<ToolCallRow[]> {
    return [...this.toolCalls.values()]
      .filter((t) => t.session_id === sessionId)
      .map((r) => ({ ...r }));
  }

  async listAllToolCalls(): Promise<ToolCallRow[]> {
    return [...this.toolCalls.values()]
      .sort((a, b) => a.started_at.localeCompare(b.started_at))
      .map((r) => ({ ...r }));
  }

  async listFileEvents(sessionId: string): Promise<FileEventRow[]> {
    return this.fileEvents
      .filter((e) => e.session_id === sessionId)
      .map((r) => ({ ...r }));
  }

  async listRiskEvents(sessionId: string): Promise<RiskEventRow[]> {
    return this.riskEvents
      .filter((e) => e.session_id === sessionId)
      .map((r) => ({ ...r }));
  }

  async close(): Promise<void> {
    // Nothing to do.
  }
}
