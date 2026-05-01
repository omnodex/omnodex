// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
/**
 * @omnodex/shared
 *
 * Core types shared across all Omnodex packages. Defines the trace event
 * schema (the source of truth wire format written into the append-only event
 * log) and the Interceptor interface, which every interception source
 * (Claude Code hooks, Cowork desktop seam, MCP proxy, mock generator) must
 * implement.
 *
 * Keep this file free of runtime dependencies so every other package can
 * import from it without pulling in transitive weight.
 */

export const SCHEMA_VERSION = 1 as const;

/** Severity levels used for risk events. */
export type RiskSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Logical category of the interception source that emitted an event. */
export type InterceptorKind =
  | "claude-code-hook"
  | "cowork-desktop"
  | "mcp-proxy"
  | "mock"
  | "analyzer";

/** Fields present on every trace event, regardless of type. */
export interface BaseEvent {
  /** Schema version of the event wire format. Bump when fields change. */
  schema_version: typeof SCHEMA_VERSION;
  /** Globally unique event id. UUID v4 is fine. */
  event_id: string;
  /** Session the event belongs to. */
  session_id: string;
  /** When the underlying thing actually happened, ISO 8601. */
  occurred_at: string;
  /** When Omnodex saw it, ISO 8601. May differ from occurred_at under async. */
  recorded_at: string;
  /** Which interceptor produced this event. */
  interceptor: InterceptorKind;
}

export interface SessionStartedEvent extends BaseEvent {
  event_type: "session.started";
  user: string;
  project_path: string;
  mcp_servers: string[];
}

export interface SessionEndedEvent extends BaseEvent {
  event_type: "session.ended";
  duration_ms: number;
  /** How the session terminated. */
  status: "completed" | "errored" | "interrupted";
}

export interface ToolInvokedEvent extends BaseEvent {
  event_type: "tool.invoked";
  tool_call_id: string;
  tool_name: string;
  /**
   * Name of the MCP server that owns the tool, or "builtin" for tools
   * implemented by the agent runtime itself (Read, Write, Bash, etc.).
   */
  mcp_server: string;
  /** Parameters as a JSON-serializable object. May be redacted upstream. */
  parameters: Record<string, unknown>;
}

export interface ToolCompletedEvent extends BaseEvent {
  event_type: "tool.completed";
  tool_call_id: string;
  duration_ms: number;
  status: "success" | "error";
  /** Byte size of the serialized response. Full body is not stored. */
  response_bytes: number;
  error_message?: string;
}

export interface FileReadEvent extends BaseEvent {
  event_type: "file.read";
  path: string;
  bytes: number;
}

export interface FileWrittenEvent extends BaseEvent {
  event_type: "file.written";
  path: string;
  bytes: number;
}

export interface RiskDetectedEvent extends BaseEvent {
  event_type: "risk.detected";
  severity: RiskSeverity;
  category: string;
  description: string;
  /**
   * Identifier of the triggering event. In practice this is the
   * `tool_call_id` of the tool call that caused the detection, which
   * lets the dashboard cross-link directly to the event timeline.
   * Future analyzers may reference a raw `event_id` instead.
   */
  related_event_id: string;
  /** Rule id that fired. */
  rule_id: string;
}

/** Discriminated union of every event type accepted by the event log. */
export type TraceEvent =
  | SessionStartedEvent
  | SessionEndedEvent
  | ToolInvokedEvent
  | ToolCompletedEvent
  | FileReadEvent
  | FileWrittenEvent
  | RiskDetectedEvent;

export type EventType = TraceEvent["event_type"];

/**
 * The Interceptor interface. Every interception source is a factory that
 * returns an object conforming to this interface. The event log and
 * downstream packages only ever see this shape, so a Claude Code
 * hook-backed interceptor and a future Cowork desktop interceptor are
 * interchangeable from the pipeline's point of view.
 *
 * Interceptors are async-only by design. They fire-and-forget events onto
 * the event log; they never block the agent's execution path.
 */
export interface Interceptor {
  /** Human readable name for logs and diagnostics. */
  readonly name: string;
  /** Which kind of source this is. */
  readonly kind: InterceptorKind;
  /**
   * Start producing events. The interceptor will invoke `emit` for every
   * event it observes. Returns a stop function for graceful shutdown.
   */
  start(emit: EmitFn): Promise<StopFn>;
}

/** Function passed to an interceptor to record an event. */
export type EmitFn = (event: TraceEvent) => void | Promise<void>;

/** Returned by `start()`; invoking it cleanly stops the interceptor. */
export type StopFn = () => Promise<void>;

/**
 * Narrow guard useful when consumers only care about a subset of events.
 */
export function isEventOfType<T extends EventType>(
  event: TraceEvent,
  type: T,
): event is Extract<TraceEvent, { event_type: T }> {
  return event.event_type === type;
}
