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
  PromptSubmittedEvent,
  RiskDetectedEvent,
  SessionEndedEvent,
  SessionRenamedEvent,
  SessionStartedEvent,
  SubagentStartedEvent,
  SubagentStoppedEvent,
  ToolCompletedEvent,
  ToolInvokedEvent,
  TraceEvent,
} from "@omnodex/shared";
import { riskScoreFor, splitMcpToolName } from "@omnodex/shared";
import type { ReadModelStore, SessionRow } from "./read-model.js";

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
   * The default source root for apply() calls that do not pass one.
   * Null means single-root mode (backwards compatible).
   */
  private sourceRoot: string | null = null;

  /**
   * Set the default source root for subsequent apply() calls. Fine for a
   * sequential replay of one root; a caller interleaving sessions from
   * several roots must pass the root to each apply() instead, because a
   * value shared across concurrent tails is whichever root set it last.
   */
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
  private async ensureSession(
    sessionId: string,
    occurredAt: string,
    interceptor: string,
    platform: SessionRow["platform"],
    root: string | null,
  ): Promise<void> {
    const existing = await this.store.getSession(sessionId);
    if (existing) {
      // A session created without a platform learns it from the first
      // later event that carries one.
      if (!existing.platform && platform) await this.store.patchSession(sessionId, { platform });
      return;
    }
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
      source_root: root,
      platform,
    });
  }

  /**
   * Apply a single event to the store. Idempotent within a single session
   * replay. `sourceRoot`, when given, is the root this event was read from;
   * otherwise the one set by setSourceRoot() applies.
   */
  async apply(event: TraceEvent, opts: { sourceRoot?: string | null } = {}): Promise<void> {
    const root = opts.sourceRoot !== undefined ? opts.sourceRoot : this.sourceRoot;
    switch (event.event_type) {
      case "session.started":
        await this.onSessionStarted(event, root);
        return;
      case "session.ended":
        await this.onSessionEnded(event);
        return;
      case "session.renamed":
        await this.onSessionRenamed(event, root);
        return;
      case "tool.invoked":
        await this.onToolInvoked(event, root);
        return;
      case "tool.completed":
        await this.onToolCompleted(event, root);
        return;
      case "file.read":
        await this.onFileRead(event, root);
        return;
      case "file.written":
        await this.onFileWritten(event, root);
        return;
      case "risk.detected":
        await this.onRiskDetected(event, root);
        return;
      case "prompt.submitted":
        await this.onPromptSubmitted(event, root);
        return;
      case "subagent.started":
        await this.onSubagentStarted(event, root);
        return;
      case "subagent.stopped":
        await this.onSubagentStopped(event, root);
        return;
      // permission.* events are not projected yet.
    }
  }

  private async onSessionStarted(event: SessionStartedEvent, root: string | null): Promise<void> {
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
      source_root: root,
      platform: event.platform ?? null,
      ...(event.mcp_server_transports?.length ? { mcp_server_transports: event.mcp_server_transports } : {}),
      ...(event.mcp_client?.name ? { mcp_client_name: event.mcp_client.name } : {}),
    });
  }

  private async onSessionEnded(event: SessionEndedEvent): Promise<void> {
    await this.store.patchSession(event.session_id, {
      ended_at: event.occurred_at,
      duration_ms: event.duration_ms,
      status: event.status,
    });
  }

  private async onSessionRenamed(event: SessionRenamedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    await this.store.patchSession(event.session_id, { title: event.title });
  }

  private async onToolInvoked(event: ToolInvokedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    const mcpServer =
      event.mcp_server === "builtin"
        ? splitMcpToolName(event.tool_name)?.mcpServer ?? event.mcp_server
        : event.mcp_server;
    const inserted = await this.store.insertToolCall({
      tool_call_id: event.tool_call_id,
      session_id: event.session_id,
      tool_name: event.tool_name,
      mcp_server: mcpServer,
      parameters_json: JSON.stringify(event.parameters),
      started_at: event.occurred_at,
      ended_at: null,
      duration_ms: null,
      status: "in_progress",
      response_bytes: null,
      error_message: null,
      // Per row, not per session: correlating a hook call with its proxy
      // counterpart pairs rows from two sessions with different interceptors.
      interceptor: event.interceptor,
      correlation_id: null,
      ...(event.agent_id ? { agent_id: event.agent_id } : {}),
    });
    // The store suppressed a row it already had, so this event has been
    // projected before. Bumping the counter anyway is what used to leave
    // tool_call_count higher than the number of tool calls on record.
    if (!inserted) return;
    await this.store.incrementSessionCounter(
      event.session_id,
      "tool_call_count",
      1,
    );
    // Derive mcp_servers from tool events rather than relying on the
    // SessionStart payload, which Claude Code does not reliably populate.
    // "builtin" is Claude Code's own tool runtime, not an MCP server.
    if (mcpServer !== "builtin") {
      await this.store.addMcpServer(event.session_id, mcpServer);
    }
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onToolCompleted(event: ToolCompletedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    await this.store.patchToolCall(event.tool_call_id, {
      ended_at: event.occurred_at,
      duration_ms: event.duration_ms,
      status: event.status,
      response_bytes: event.response_bytes,
      error_message: event.error_message ?? null,
    });
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onFileRead(event: FileReadEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    const inserted = await this.store.insertFileEvent({
      event_id: event.event_id,
      session_id: event.session_id,
      direction: "read",
      path: event.path,
      bytes: event.bytes,
      at: event.occurred_at,
    });
    if (!inserted) return;
    await this.store.incrementSessionCounter(
      event.session_id,
      "file_read_count",
      1,
    );
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onFileWritten(event: FileWrittenEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    const inserted = await this.store.insertFileEvent({
      event_id: event.event_id,
      session_id: event.session_id,
      direction: "write",
      path: event.path,
      bytes: event.bytes,
      at: event.occurred_at,
    });
    if (!inserted) return;
    await this.store.incrementSessionCounter(
      event.session_id,
      "file_write_count",
      1,
    );
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onPromptSubmitted(event: PromptSubmittedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    const inserted = await this.store.insertPrompt({
      event_id: event.event_id,
      session_id: event.session_id,
      prompt: event.prompt,
      ...(event.prompt_id ? { prompt_id: event.prompt_id } : {}),
      at: event.occurred_at,
    });
    if (!inserted) return;
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onSubagentStarted(event: SubagentStartedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    // Start time and type only: a start that arrives after the stop must not
    // put a finished subagent back in progress.
    await this.store.upsertSubagent(event.session_id, event.agent_id, {
      started_at: event.occurred_at,
      agent_type: event.agent_type,
    });
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onSubagentStopped(event: SubagentStoppedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    await this.store.upsertSubagent(event.session_id, event.agent_id, {
      agent_type: event.agent_type,
      ended_at: event.occurred_at,
      duration_ms: event.duration_ms ?? null,
      status: event.status ?? "completed",
      response_bytes: event.response_bytes ?? null,
    });
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }

  private async onRiskDetected(event: RiskDetectedEvent, root: string | null): Promise<void> {
    await this.ensureSession(event.session_id, event.occurred_at, event.interceptor, event.platform ?? null, root);
    const inserted = await this.store.insertRiskEvent({
      event_id: event.event_id,
      session_id: event.session_id,
      related_event_id: event.related_event_id,
      severity: event.severity,
      category: event.category,
      description: event.description,
      rule_id: event.rule_id,
      detected_at: event.occurred_at,
      ...(event.rule_tier ? { rule_tier: event.rule_tier } : {}),
      ...(event.related_event_ids?.length ? { related_event_ids: event.related_event_ids } : {}),
    });
    if (!inserted) return;
    const score = riskScoreFor(event.severity);
    if (score) {
      await this.store.addToRiskScore(event.session_id, score);
    }
    await this.store.patchSession(event.session_id, { last_event_at: event.occurred_at });
  }
}
