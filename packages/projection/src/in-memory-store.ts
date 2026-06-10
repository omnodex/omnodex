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

import type {
  FileEventRow,
  ReadModelStore,
  RiskEventRow,
  SessionRow,
  ToolCallRow,
} from "./read-model.js";

export class InMemoryReadModelStore implements ReadModelStore {
  private sessions = new Map<string, SessionRow>();
  private toolCalls = new Map<string, ToolCallRow>();
  private fileEvents: FileEventRow[] = [];
  private riskEvents: RiskEventRow[] = [];

  async reset(): Promise<void> {
    this.sessions.clear();
    this.toolCalls.clear();
    this.fileEvents = [];
    this.riskEvents = [];
  }

  async upsertSession(row: SessionRow): Promise<void> {
    this.sessions.set(row.session_id, { ...row });
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
    existing.risk_score = existing.risk_score + delta;
  }

  async insertToolCall(row: ToolCallRow): Promise<void> {
    this.toolCalls.set(row.tool_call_id, { ...row });
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

  async insertFileEvent(row: FileEventRow): Promise<void> {
    this.fileEvents.push({ ...row });
  }

  async insertRiskEvent(row: RiskEventRow): Promise<void> {
    this.riskEvents.push({ ...row });
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
