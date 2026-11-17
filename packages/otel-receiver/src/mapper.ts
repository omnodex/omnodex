// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Span to trace event mapper for OpenTelemetry GenAI spans and the Claude
 * API's own spans (Managed Agents and the Messages API).
 *
 * It keys on `gen_ai.operation.name` and on attributes, never on span names,
 * because the Claude API's span names and attributes can change while the
 * feature is in beta. Spans it does not understand are counted and ignored.
 *
 * Telemetry is detective only: a span ends after the thing it describes, so
 * nothing here can block a call. Delivery is at least once, so every event id
 * comes from the span's identity and a redelivered span maps to the same ids.
 */

import { SCHEMA_VERSION } from "@omnodex/shared";
import type {
  InterceptorKind,
  PlatformKind,
  SessionOrigin,
  TraceEvent,
} from "@omnodex/shared";
import { eventIdFor } from "./ids.js";
import type { AttrValue, OtelSpan } from "./otlp.js";

const INTERCEPTOR: InterceptorKind = "otel-receiver";
const MANAGED_PLATFORM: PlatformKind = "managed-agents";

/** Counts for one `mapSpans` call, for the receiver's health report. */
export interface MapStats {
  /** Spans offered. */
  spans: number;
  /** Spans that produced at least one event. */
  mapped: number;
  /** Spans the mapper has no mapping for (model requests, outcome checks, unknown names). */
  ignored: number;
  /** The Console's Test button span: proof the destination reaches the receiver, with no event. */
  testMarkers: number;
}

export interface MapResult {
  events: TraceEvent[];
  stats: MapStats;
}

export interface OtelMapperOptions {
  /** Epoch milliseconds, for `recorded_at` and for the denial grace period. Default `Date.now`. */
  clock?: () => number;
  /** Sessions kept in memory before the least recently started is forgotten. Default 5000. */
  maxSessions?: number;
  /**
   * How long an inferred denial waits for a late tool span before it is
   * written. Tool spans and the turn that made the call arrive in separate
   * export batches in no fixed order. Default 30000.
   */
  denialGraceMs?: number;
  /**
   * Tool names whose calls the API never gives a tool span for and that are
   * not denials: calls to other agents and to advisors. Default: names that
   * start with "agent", "advisor" or "multiagent".
   */
  isUnspannedTool?: (toolName: string) => boolean;
}

const DEFAULT_UNSPANNED = /^(?:agent|advisor|multiagent)(?:[_.:\-]|$)/i;
const MAX_TOOL_CALLS_PER_SESSION = 10_000;
const MAX_TRACE_SESSIONS = 20_000;
const MAX_PENDING_DENIALS = 1_000;

interface SessionState {
  /** The thread (`gen_ai.conversation.id`) that started the session. Other threads are subagents. */
  primaryThread?: string;
  /** Last model seen, per thread ("" for a span with no thread). */
  models: Map<string, string>;
  /** Subagent threads announced, with the time each began. */
  threads: Map<string, number>;
  /** Tool call ids that have a tool span, for denial inference. */
  toolCalls: Set<string>;
}

interface PendingDenial {
  sessionId: string;
  agentId?: string;
  traceId: string;
  spanId: string;
  callId: string;
  toolName: string;
  parameters: Record<string, unknown>;
  occurredAtMs: number;
  queuedAtMs: number;
}

interface SessionFacts {
  sessionId: string;
  managed: boolean;
  minStartMs: number;
  origin: Partial<SessionOrigin>;
  user: string;
  primaryThread?: string;
  /** Start of the earliest span that named a thread. */
  threadStartMs?: number;
  /** Model of the earliest turn in the primary thread. */
  firstModel?: { startMs: number; model: string };
}

interface Resolved {
  sessionId: string;
  managed: boolean;
}

// ---------------------------------------------------------------------------
// Attribute and time helpers
// ---------------------------------------------------------------------------

function str(attrs: Record<string, AttrValue>, key: string): string | undefined {
  const v = attrs[key];
  if (typeof v === "string" && v !== "") return v;
  if (typeof v === "number") return String(v);
  return undefined;
}

function nanoToMs(nano: string): number {
  try {
    return Number(BigInt(nano) / 1_000_000n);
  } catch {
    return 0;
  }
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** A JSON-valued attribute: delivered as a JSON string, or already structured. */
function jsonValue(v: AttrValue | undefined): unknown {
  if (typeof v !== "string") return v;
  const t = v.trim();
  if (t === "") return undefined;
  if (t.startsWith("{") || t.startsWith("[") || t.startsWith('"')) {
    try {
      return JSON.parse(t);
    } catch {
      return v;
    }
  }
  return v;
}

/** Tool arguments as the object `tool.invoked` carries. Never throws. */
function parametersOf(v: AttrValue | undefined): Record<string, unknown> {
  const parsed = jsonValue(v);
  if (parsed === undefined || parsed === null) return {};
  if (typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  if (typeof parsed === "string") return { raw: parsed };
  return { value: parsed };
}

function byteLength(v: AttrValue | undefined): number {
  if (v === undefined || v === null) return 0;
  const text = typeof v === "string" ? v : safeStringify(v);
  return Buffer.byteLength(text, "utf8");
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return "";
  }
}

interface MessagePart {
  type?: unknown;
  content?: unknown;
  text?: unknown;
  id?: unknown;
  name?: unknown;
  arguments?: unknown;
}

interface Message {
  role?: unknown;
  parts?: unknown;
}

/** The messages in a `gen_ai.input.messages` or `gen_ai.output.messages` attribute. */
function messagesOf(v: AttrValue | undefined): Message[] {
  const parsed = jsonValue(v);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((m): m is Message => typeof m === "object" && m !== null && !Array.isArray(m));
}

function partsOf(m: Message): MessagePart[] {
  if (!Array.isArray(m.parts)) return [];
  return m.parts.filter((p): p is MessagePart => typeof p === "object" && p !== null);
}

function partText(p: MessagePart): string | undefined {
  if (p.type !== undefined && p.type !== "text") return undefined;
  const t = typeof p.content === "string" ? p.content : typeof p.text === "string" ? p.text : undefined;
  return t === undefined || t === "" ? undefined : t;
}

/** The text of the last user message that has any: what this turn was asked. */
function lastUserText(v: AttrValue | undefined): string | undefined {
  const messages = messagesOf(v);
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.role !== "user") continue;
    const text = partsOf(m).map(partText).filter((t): t is string => t !== undefined).join("\n");
    if (text) return text;
  }
  return undefined;
}

function isError(span: OtelSpan): boolean {
  return span.status?.code === "error" || str(span.attributes, "error.type") !== undefined;
}

function errorMessage(span: OtelSpan): string | undefined {
  return span.status?.message ?? str(span.attributes, "error.type");
}

function firstString(obj: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v !== "") return v;
  }
  return undefined;
}

const PATH_KEYS = ["file_path", "path", "filePath"] as const;
const WRITE_BODY_KEYS = ["content", "file_text", "new_string", "new_str"] as const;

type SpanKind = "tool" | "turn" | "test" | "other";

function classify(span: OtelSpan): SpanKind {
  if (span.name === "anthropic.test") return "test";
  const op = str(span.attributes, "gen_ai.operation.name");
  if (op === "execute_tool") return "tool";
  if (op === "invoke_agent" || span.name === "anthropic.session.turn") return "turn";
  return "other";
}

// ---------------------------------------------------------------------------
// Mapper
// ---------------------------------------------------------------------------

export class OtelMapper {
  private readonly clock: () => number;
  private readonly maxSessions: number;
  private readonly graceMs: number;
  private readonly unspanned: (toolName: string) => boolean;
  private readonly sessions = new Map<string, SessionState>();
  private readonly traceSessions = new Map<string, string>();
  private pending: PendingDenial[] = [];

  constructor(options: OtelMapperOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.maxSessions = options.maxSessions ?? 5000;
    this.graceMs = options.denialGraceMs ?? 30_000;
    this.unspanned = options.isUnspannedTool ?? ((name) => DEFAULT_UNSPANNED.test(name));
  }

  /** Map one batch of spans. Spans may arrive in any order and in any batch. */
  mapSpans(spans: readonly OtelSpan[]): MapResult {
    const stats: MapStats = { spans: spans.length, mapped: 0, ignored: 0, testMarkers: 0 };
    const events: TraceEvent[] = [];

    // Learn which session each trace belongs to before mapping, so a span
    // that does not name its session still lands in the right one.
    for (const span of spans) {
      const sid = str(span.attributes, "anthropic.session.id");
      if (sid) this.rememberTrace(span.traceId, `ma:${sid}`);
    }

    const facts = this.collectFacts(spans);
    for (const f of facts.values()) {
      if (!this.sessions.has(f.sessionId)) events.push(this.startSession(f));
      else this.noteSession(f);
    }

    // Children end before their parents, so ordering by end time maps a
    // turn's tool spans before the turn, which is what denial inference needs.
    const ordered = [...spans].sort((a, b) => {
      const d = nanoToMs(a.endTimeUnixNano) - nanoToMs(b.endTimeUnixNano);
      return d !== 0 ? d : a.spanId.localeCompare(b.spanId);
    });

    for (const span of ordered) {
      const kind = classify(span);
      if (kind === "test") {
        stats.testMarkers++;
        continue;
      }
      if (kind === "other") {
        stats.ignored++;
        continue;
      }
      const resolved = this.resolve(span);
      const state = this.stateFor(resolved.sessionId);
      const out = kind === "tool" ? this.mapTool(span, resolved, state) : this.mapTurn(span, resolved, state);
      if (out.length > 0) stats.mapped++;
      else stats.ignored++;
      events.push(...out);
    }
    return { events, stats };
  }

  /**
   * Inferred denials whose grace period is over. Call it on a timer and, with
   * `force`, at shutdown. A denial whose tool span turned up meanwhile was
   * dropped when that span was mapped.
   */
  drainPending(options: { force?: boolean } = {}): TraceEvent[] {
    const now = this.clock();
    const events: TraceEvent[] = [];
    const keep: PendingDenial[] = [];
    for (const p of this.pending) {
      if (options.force || now - p.queuedAtMs >= this.graceMs) events.push(this.denialEvent(p));
      else keep.push(p);
    }
    this.pending = keep;
    return events;
  }

  /** Inferred denials still waiting, for the receiver's health report. */
  get pendingDenials(): number {
    return this.pending.length;
  }

  // -- session bookkeeping ---------------------------------------------------

  private rememberTrace(traceId: string, sessionId: string): void {
    this.traceSessions.delete(traceId);
    this.traceSessions.set(traceId, sessionId);
    if (this.traceSessions.size > MAX_TRACE_SESSIONS) {
      const oldest = this.traceSessions.keys().next().value;
      if (oldest !== undefined) this.traceSessions.delete(oldest);
    }
  }

  private resolve(span: OtelSpan): Resolved {
    const sid = str(span.attributes, "anthropic.session.id");
    if (sid) return { sessionId: `ma:${sid}`, managed: true };
    const viaTrace = this.traceSessions.get(span.traceId);
    if (viaTrace) return { sessionId: viaTrace, managed: true };
    const conversation = str(span.attributes, "gen_ai.conversation.id");
    return { sessionId: `otel:${conversation ?? span.traceId}`, managed: false };
  }

  private stateFor(sessionId: string): SessionState {
    let s = this.sessions.get(sessionId);
    if (!s) {
      s = { models: new Map(), threads: new Map(), toolCalls: new Set() };
      this.sessions.set(sessionId, s);
      this.evict();
    }
    return s;
  }

  private evict(): void {
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
  }

  /** What the batch says about each session it touches. */
  private collectFacts(spans: readonly OtelSpan[]): Map<string, SessionFacts> {
    const facts = new Map<string, SessionFacts>();
    for (const span of spans) {
      const kind = classify(span);
      if (kind === "test" || kind === "other") continue;
      const { sessionId, managed } = this.resolve(span);
      const a = span.attributes;
      const startMs = nanoToMs(span.startTimeUnixNano);
      let f = facts.get(sessionId);
      if (!f) {
        f = { sessionId, managed, minStartMs: startMs, origin: {}, user: "" };
        facts.set(sessionId, f);
      }
      f.minStartMs = Math.min(f.minStartMs, startMs);

      const user = str(a, "user.id");
      if (user && !f.user) f.user = user;

      const o = f.origin;
      o.org_id ??= str(a, "anthropic.organization.id");
      o.workspace_id ??= str(a, "anthropic.workspace.id");
      o.agent_id ??= str(a, "gen_ai.agent.id");
      o.agent_name ??= str(a, "gen_ai.agent.name");
      o.environment_id ??= str(a, "anthropic.environment.id");
      o.end_user ??= user;
      if (!o.service) {
        o.service = managed ? "claude-platform" : str(span.resource, "service.name") ?? "unknown";
      }

      // The thread that began earliest is the primary one.
      const thread = managed ? str(a, "gen_ai.conversation.id") : undefined;
      if (thread) {
        if (f.threadStartMs === undefined || startMs < f.threadStartMs) {
          f.primaryThread = thread;
          f.threadStartMs = startMs;
        }
      }
      if (kind === "turn") {
        const model = str(a, "gen_ai.request.model");
        if (model && (!thread || thread === f.primaryThread) && (!f.firstModel || startMs < f.firstModel.startMs)) {
          f.firstModel = { startMs, model };
        }
      }
    }
    return facts;
  }

  /** Fold a later batch's facts into a session already started. */
  private noteSession(f: SessionFacts): void {
    const s = this.stateFor(f.sessionId);
    if (s.primaryThread === undefined && f.primaryThread !== undefined) s.primaryThread = f.primaryThread;
  }

  private startSession(f: SessionFacts): TraceEvent {
    const s = this.stateFor(f.sessionId);
    s.primaryThread = f.primaryThread;
    if (f.firstModel) s.models.set(f.primaryThread ?? "", f.firstModel.model);
    const origin: SessionOrigin = { service: f.origin.service ?? "unknown" };
    for (const k of ["org_id", "workspace_id", "agent_id", "agent_name", "environment_id", "end_user"] as const) {
      const v = f.origin[k];
      if (v !== undefined) origin[k] = v;
    }
    const at = iso(f.minStartMs);
    return {
      ...this.base(f.sessionId, f.managed, at),
      event_id: eventIdFor(`${f.sessionId}:session.started`),
      event_type: "session.started",
      user: f.user,
      project_path: "",
      mcp_servers: [],
      ...(f.firstModel ? { model: f.firstModel.model } : {}),
      origin,
    };
  }

  // -- events ----------------------------------------------------------------

  private base(sessionId: string, managed: boolean, occurredAt: string, agentId?: string) {
    return {
      schema_version: SCHEMA_VERSION,
      session_id: sessionId,
      occurred_at: occurredAt,
      recorded_at: iso(this.clock()),
      interceptor: INTERCEPTOR,
      ...(managed ? { platform: MANAGED_PLATFORM } : {}),
      ...(agentId ? { agent_id: agentId } : {}),
    };
  }

  /** The subagent a span belongs to: its thread, when that is not the session's own. */
  private agentFor(span: OtelSpan, resolved: Resolved, state: SessionState): string | undefined {
    if (!resolved.managed) return undefined;
    const thread = str(span.attributes, "gen_ai.conversation.id");
    if (!thread || state.primaryThread === undefined || thread === state.primaryThread) return undefined;
    return thread;
  }

  private mapTool(span: OtelSpan, resolved: Resolved, state: SessionState): TraceEvent[] {
    const a = span.attributes;
    const agentId = this.agentFor(span, resolved, state);
    const startMs = nanoToMs(span.startTimeUnixNano);
    const endMs = Math.max(startMs, nanoToMs(span.endTimeUnixNano));
    const id = `${span.traceId}:${span.spanId}`;

    const callId = str(a, "gen_ai.tool.call.id") ?? `otel:${span.spanId}`;
    this.noteToolCall(state, callId);

    const nameFromSpan = span.name.includes(" ") ? span.name.slice(span.name.indexOf(" ") + 1).trim() : "";
    const toolName = str(a, "gen_ai.tool.name") ?? nameFromSpan;
    const isMcp = span.name.startsWith("anthropic.mcp_tool_use") || str(a, "anthropic.mcp.server.name") !== undefined;
    const isCustom = span.name.startsWith("anthropic.custom_tool_use");
    const server = isMcp ? str(a, "anthropic.mcp.server.name") ?? "unknown" : isCustom ? "custom" : "builtin";

    const result = a["anthropic.tool_result.content"] ?? a["gen_ai.tool.call.result"];
    const failed = isError(span);
    const mk = (at: number, kind: string) => ({
      ...this.base(resolved.sessionId, resolved.managed, iso(at), agentId),
      event_id: eventIdFor(`${id}:${kind}`),
    });

    // An MCP call that never got as far as naming a tool: the server did not
    // connect. Record the failed call without inventing a tool name.
    if (!toolName) {
      if (!isMcp) return [];
      return [
        {
          ...mk(endMs, "tool.completed"),
          event_type: "tool.completed",
          tool_call_id: callId,
          duration_ms: endMs - startMs,
          status: "error",
          response_bytes: 0,
          error_message: errorMessage(span) ?? `MCP server ${server} did not connect`,
        },
      ];
    }

    const parameters = parametersOf(a["gen_ai.tool.call.arguments"]);
    const events: TraceEvent[] = [];
    if (str(a, "anthropic.tool.evaluated_permission") === "ask") {
      events.push({
        ...mk(startMs, "permission.requested"),
        event_type: "permission.requested",
        tool_name: toolName,
        mcp_server: server,
        parameters,
        tool_call_id: callId,
      });
    }
    events.push({
      ...mk(startMs, "tool.invoked"),
      event_type: "tool.invoked",
      tool_call_id: callId,
      tool_name: toolName,
      mcp_server: server,
      parameters,
    });
    const responseBytes = byteLength(result);
    events.push({
      ...mk(endMs, "tool.completed"),
      event_type: "tool.completed",
      tool_call_id: callId,
      duration_ms: endMs - startMs,
      status: failed ? "error" : "success",
      response_bytes: responseBytes,
      ...(failed ? { error_message: errorMessage(span) ?? "tool call failed" } : {}),
    });

    if (!failed && server === "builtin") {
      const file = this.fileEvent(toolName, parameters, responseBytes, mk(endMs, "file"));
      if (file) events.push(file);
    }
    return events;
  }

  private fileEvent(
    toolName: string,
    parameters: Record<string, unknown>,
    responseBytes: number,
    base: ReturnType<OtelMapper["base"]> & { event_id: string },
  ): TraceEvent | null {
    const name = toolName.toLowerCase();
    const path = firstString(parameters, PATH_KEYS);
    if (!path) return null;
    if (name === "read") return { ...base, event_type: "file.read", path, bytes: responseBytes };
    if (name === "write" || name === "edit") {
      const body = firstString(parameters, WRITE_BODY_KEYS);
      return {
        ...base,
        event_type: "file.written",
        path,
        bytes: body !== undefined ? Buffer.byteLength(body, "utf8") : responseBytes,
      };
    }
    return null;
  }

  private noteToolCall(state: SessionState, callId: string): void {
    state.toolCalls.add(callId);
    if (state.toolCalls.size > MAX_TOOL_CALLS_PER_SESSION) {
      const oldest = state.toolCalls.values().next().value;
      if (oldest !== undefined) state.toolCalls.delete(oldest);
    }
    // A tool span that arrives after its turn cancels the denial guess.
    if (this.pending.length > 0) this.pending = this.pending.filter((p) => p.callId !== callId);
  }

  private mapTurn(span: OtelSpan, resolved: Resolved, state: SessionState): TraceEvent[] {
    const a = span.attributes;
    const startMs = nanoToMs(span.startTimeUnixNano);
    const endMs = Math.max(startMs, nanoToMs(span.endTimeUnixNano));
    const id = `${span.traceId}:${span.spanId}`;
    const thread = resolved.managed ? str(a, "gen_ai.conversation.id") : undefined;
    const agentId = this.agentFor(span, resolved, state);
    const events: TraceEvent[] = [];
    const mk = (at: number, kind: string) => ({
      ...this.base(resolved.sessionId, resolved.managed, iso(at), agentId),
      event_id: eventIdFor(`${id}:${kind}`),
    });

    // A thread other than the session's own is a subagent.
    if (agentId && !state.threads.has(agentId)) {
      state.threads.set(agentId, startMs);
      const agentType = str(a, "gen_ai.agent.name");
      events.push({
        ...this.base(resolved.sessionId, true, iso(startMs), agentId),
        event_id: eventIdFor(`${resolved.sessionId}:${agentId}:subagent.started`),
        event_type: "subagent.started",
        agent_id: agentId,
        ...(agentType ? { agent_type: agentType } : {}),
      });
    }

    const prompt = lastUserText(a["gen_ai.input.messages"]);
    if (prompt !== undefined) {
      events.push({
        ...mk(startMs, "prompt.submitted"),
        event_type: "prompt.submitted",
        prompt,
        prompt_id: span.spanId,
      });
    }

    const model = str(a, "gen_ai.request.model");
    if (model) {
      const key = thread ?? "";
      const previous = state.models.get(key);
      if (previous !== model) {
        state.models.set(key, model);
        events.push({
          ...mk(startMs, "session.model_changed"),
          event_type: "session.model_changed",
          model,
          ...(previous !== undefined ? { previous } : {}),
          // The platform reported it on its own event stream, as a hook would.
          source: "hook",
        });
      }
    }

    if (agentId) {
      const began = state.threads.get(agentId) ?? startMs;
      const output = a["gen_ai.output.messages"];
      events.push({
        ...mk(endMs, "subagent.stopped"),
        event_type: "subagent.stopped",
        agent_id: agentId,
        ...(str(a, "gen_ai.agent.name") ? { agent_type: str(a, "gen_ai.agent.name") } : {}),
        duration_ms: Math.max(0, endMs - began),
        status: isError(span) ? "errored" : "completed",
        response_bytes: byteLength(output),
      });
    }

    if (resolved.managed) this.queueDenials(span, resolved, state, agentId, endMs);
    return events;
  }

  /**
   * Tool calls in a turn's output that have no tool span. The API leaves out
   * the span for a denied call, so this is the best sign of one, but a span in
   * a later batch can still show up. Held until the grace period passes.
   */
  private queueDenials(
    span: OtelSpan,
    resolved: Resolved,
    state: SessionState,
    agentId: string | undefined,
    endMs: number,
  ): void {
    for (const message of messagesOf(span.attributes["gen_ai.output.messages"])) {
      for (const part of partsOf(message)) {
        if (part.type !== "tool_call") continue;
        const callId = typeof part.id === "string" && part.id ? part.id : undefined;
        const name = typeof part.name === "string" && part.name ? part.name : undefined;
        if (!callId || !name || this.unspanned(name) || state.toolCalls.has(callId)) continue;
        if (this.pending.some((p) => p.callId === callId)) continue;
        if (this.pending.length >= MAX_PENDING_DENIALS) this.pending.shift();
        this.pending.push({
          sessionId: resolved.sessionId,
          ...(agentId ? { agentId } : {}),
          traceId: span.traceId,
          spanId: span.spanId,
          callId,
          toolName: name,
          parameters: parametersOf(part.arguments as AttrValue | undefined),
          occurredAtMs: endMs,
          queuedAtMs: this.clock(),
        });
      }
    }
  }

  private denialEvent(p: PendingDenial): TraceEvent {
    return {
      ...this.base(p.sessionId, true, iso(p.occurredAtMs), p.agentId),
      event_id: eventIdFor(`${p.traceId}:${p.spanId}:permission.denied:${p.callId}`),
      event_type: "permission.denied",
      tool_name: p.toolName,
      // The turn output names no server, so the owner of the call is not known.
      mcp_server: "unknown",
      parameters: p.parameters,
      tool_call_id: p.callId,
      reason: "Inferred: the turn's output made this call and the API recorded no tool span for it",
    };
  }
}

/** A mapper with its own session memory. One per receiver. */
export function createOtelMapper(options: OtelMapperOptions = {}): OtelMapper {
  return new OtelMapper(options);
}
