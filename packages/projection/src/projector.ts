// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Projector. Pure function from a stream of events to read model state.
 * The projector never reads the event log directly; callers drive it via
 * `apply(event)` or `replay(events)`. This keeps it testable against an
 * in-memory store without touching disk.
 *
 * See DEVELOPMENT.md for architectural context.
 */

import type {
  FileReadEvent,
  FileWrittenEvent,
  RiskDetectedEvent,
  SessionEndedEvent,
  SessionStartedEvent,
  ToolCompletedEvent,
  ToolInvokedEvent,
  TraceEvent,
} from "@omnodex/shared";
import type { ReadModelStore, SessionRow } from "./read-model.js";

const SEVERITY_SCORE: Record<string, number> = {
  LOW: 5,
  MEDIUM: 15,
  HIGH: 30,
  CRITICAL: 60,
};

export class Projector {
  constructor(private readonly store: ReadModelStore) {}

  /** Wipe the read model and replay a stream of events from scratch. */
  async replay(events: Iterable<TraceEvent> | AsyncIterable<TraceEvent>): Promise<void> {
    await this.store.reset();
    for await (const event of events as AsyncIterable<TraceEvent>) {
      await this.apply(event);
    }
  }

  /**
   * The source root this projector is associated with.
   * Set via setSourceRoot() before applying events from a specific root.
   * Null means single-root mode (backwards compatible).
   */
  private sourceRoot: string | null = null;

  /** Set the source root for subsequent apply() calls. */
  setSourceRoot(root: string | null): void {
    this.sourceRoot = root;
  }

  /**
   * Ensure a session row exists before inserting child rows that reference it.
   * Some interceptors (e.g. Antigravity) do not have a SessionStart hook, so
   * the first event for a session may be a tool.invoked. This creates a
   * minimal session row on-demand to satisfy the FK constraint. If a
   * session.started event arrives later, upsertSession overwrites the stub.
   */
  private async ensureSession(sessionId: string, occurredAt: string, interceptor: string): Promise<void> {
    const existing = await this.store.getSession(sessionId);
    if (existing) return;
    await this.store.upsertSession({
      session_id: sessionId,
      user: "unknown",
      project_path: "",
      mcp_servers: [],
      interceptor: interceptor as SessionRow["interceptor"],
      started_at: occurredAt,
      ended_at: null,
      duration_ms: null,
      status: "in_progress",
      tool_call_count: 0,
      file_read_count: 0,
      file_write_count: 0,
      risk_score: 0,
      last_event_at: occurredAt,
      source_root: this.sourceRoot,
    });
  }

  /** Apply a single event to the store. Idempotent within a single session replay. */
  async apply(event: TraceEvent): Promise<void> {
    switch (event.event_type) {
      case "session.started":
        await this.onSessionStarted(event);
        return;
      case "session.ended":
        await this.onSessionEnded(event);
        return;
      case "tool.invoked":
        await this.onToolInvoked(event);
        return;
      case "tool.completed":
        await this.onToolCompleted(event);
        return;
      case "file.read":
        await this.onFileRead(event);
        return;
      case "file.written":
        await this.onFileWritten(event);
        return;
      case "risk.detected":
        await this.onRiskDetected(event);
        return;
    }
  }

  private async onSessionStarted(event: SessionStartedEvent): Promise<void> {
    await this.store.upsertSession({
      session_id: event.session_id,
      user: event.user,
      project_path: event.project_path,
      mcp_servers: event.mcp_servers,
      interceptor: event.interceptor,
      started_at: event.occurred_at,
      ended_at: null,
      duration_ms: null,
      status: "in_progress",
      tool_call_count: 0,
      file_read_count: 0,
      file_write_count: 0,
      risk_score: 0,
      last_event_at: event.occurred_at,
      source_root: this.sourceRoot,
    });
  }

  private async onSessionEnded(event: SessionEndedEvent): Promise<void> {
    await this.store.patchSession(event.session_id, {
      ended_at: event.occurred_at,
      duration_ms: event.duration_ms,
      status: event.status,
    });
  }

  private async onToolInvoked(event: ToolInvokedEvent): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor);
    await this.store.insertToolCall({
      tool_call_id: event.tool_call_id,
      session_id: event.session_id,
      tool_name: event.tool_name,
      mcp_server: event.mcp_server,
      parameters_json: JSON.stringify(event.parameters),
      started_at: event.occurred_at,
      ended_at: null,
      duration_ms: null,
      status: "in_progress",
      response_bytes: null,
      error_message: null,
    });
    await this.store.incrementSessionCounter(
      event.session_id,
      "tool_call_count",
      1,
    );
    // Derive mcp_servers from tool events rather than relying on the
    // SessionStart payload, which Claude Code does not reliably populate.
    // "builtin" is Claude Code's own tool runtime, not an MCP server.
    if (event.mcp_server !== "builtin") {
      await this.store.addMcpServer(event.session_id, event.mcp_server);
    }
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onToolCompleted(event: ToolCompletedEvent): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor);
    await this.store.patchToolCall(event.tool_call_id, {
      ended_at: event.occurred_at,
      duration_ms: event.duration_ms,
      status: event.status,
      response_bytes: event.response_bytes,
      error_message: event.error_message ?? null,
    });
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onFileRead(event: FileReadEvent): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor);
    await this.store.insertFileEvent({
      session_id: event.session_id,
      direction: "read",
      path: event.path,
      bytes: event.bytes,
      at: event.occurred_at,
    });
    await this.store.incrementSessionCounter(
      event.session_id,
      "file_read_count",
      1,
    );
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onFileWritten(event: FileWrittenEvent): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor);
    await this.store.insertFileEvent({
      session_id: event.session_id,
      direction: "write",
      path: event.path,
      bytes: event.bytes,
      at: event.occurred_at,
    });
    await this.store.incrementSessionCounter(
      event.session_id,
      "file_write_count",
      1,
    );
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onRiskDetected(event: RiskDetectedEvent): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor);
    await this.store.insertRiskEvent({
      session_id: event.session_id,
      related_event_id: event.related_event_id,
      severity: event.severity,
      category: event.category,
      description: event.description,
      rule_id: event.rule_id,
      detected_at: event.occurred_at,
    });
    const score = SEVERITY_SCORE[event.severity] ?? 0;
    if (score) {
      await this.store.addToRiskScore(event.session_id, score);
    }
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }
}
