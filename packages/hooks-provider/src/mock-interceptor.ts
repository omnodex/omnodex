// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
/**
 * Mock interceptor. Produces a deterministic-enough multi-MCP Claude Code
 * session for testing. The shape mirrors a realistic scenario: PostgreSQL
 * query, HTTP API fanout, CSV write, with a suspicious /etc/passwd read
 * thrown in.
 *
 * This is a reference implementation of the Interceptor interface that
 * can exercise the pipeline end-to-end without a real Claude Code install.
 * The Claude Code hook provider in `./claude-code-interceptor.ts` is the
 * real-session implementation.
 */

import type {
  EmitFn,
  Interceptor,
  StopFn,
  TraceEvent,
} from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

export interface MockInterceptorOptions {
  /**
   * Session ID to use. If omitted a unique timestamp-based ID is generated
   * so successive `spike` runs each produce a separate session.
   */
  sessionId?: string;
  user?: string;
  projectPath?: string;
  /** Milliseconds between successive events. Keeps the demo perceptibly streamy. */
  stepDelayMs?: number;
}

export class MockInterceptor implements Interceptor {
  readonly name = "mock-multi-mcp-session";
  readonly kind = "mock" as const;

  private readonly sessionId: string;
  private readonly user: string;
  private readonly projectPath: string;
  private readonly stepDelayMs: number;
  private stopped = false;

  constructor(options: MockInterceptorOptions = {}) {
    this.sessionId =
      options.sessionId ?? `sess_demo_${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}`;
    this.user = options.user ?? "brian@omnodex.local";
    this.projectPath = options.projectPath ?? "/home/brian/projects/demo";
    this.stepDelayMs = options.stepDelayMs ?? 0;
  }

  async start(emit: EmitFn): Promise<StopFn> {
    const events = this.buildSessionEvents();
    void this.drain(events, emit);
    return async () => {
      this.stopped = true;
    };
  }

  /** Public accessor for tests that want the full event list synchronously. */
  buildSessionEvents(): TraceEvent[] {
    return buildMultiMcpSession({
      sessionId: this.sessionId,
      user: this.user,
      projectPath: this.projectPath,
    });
  }

  private async drain(events: TraceEvent[], emit: EmitFn): Promise<void> {
    for (const event of events) {
      if (this.stopped) return;
      await emit(event);
      if (this.stepDelayMs > 0) {
        await new Promise((r) => setTimeout(r, this.stepDelayMs));
      }
    }
  }
}

interface BuildOptions {
  sessionId: string;
  user: string;
  projectPath: string;
}

function buildMultiMcpSession(opts: BuildOptions): TraceEvent[] {
  const start = new Date("2026-04-11T12:00:00.000Z").getTime();
  const at = (offsetMs: number) => new Date(start + offsetMs).toISOString();
  let eventSeq = 0;
  const newId = (prefix: string) => `${prefix}_${(++eventSeq).toString().padStart(4, "0")}`;

  const base = (occurredAt: string) => ({
    schema_version: SCHEMA_VERSION,
    event_id: newId("evt"),
    session_id: opts.sessionId,
    occurred_at: occurredAt,
    recorded_at: occurredAt,
    interceptor: "mock" as const,
  });

  const events: TraceEvent[] = [];

  // 1. Session start with 3 MCP servers plus builtin tools.
  events.push({
    ...base(at(0)),
    event_type: "session.started",
    user: opts.user,
    project_path: opts.projectPath,
    mcp_servers: ["postgres", "http-api", "filesystem"],
  });

  // 2. Query customers table via postgres MCP.
  const pgCallId = "call_pg_1";
  events.push({
    ...base(at(500)),
    event_type: "tool.invoked",
    tool_call_id: pgCallId,
    tool_name: "query",
    mcp_server: "postgres",
    parameters: { sql: "SELECT id, email FROM customers LIMIT 5" },
  });
  events.push({
    ...base(at(900)),
    event_type: "tool.completed",
    tool_call_id: pgCallId,
    duration_ms: 400,
    status: "success",
    response_bytes: 1820,
  });

  // 3. Fan-out HTTP enrichment calls.
  for (let i = 1; i <= 5; i++) {
    const callId = `call_http_${i}`;
    const t = 1000 + i * 300;
    events.push({
      ...base(at(t)),
      event_type: "tool.invoked",
      tool_call_id: callId,
      tool_name: "fetch",
      mcp_server: "http-api",
      parameters: {
        url: `https://enrich.example.com/v1/customer/${i}`,
        headers: {
          // Deliberately looks like a Stripe key so the analyzer rule can fire later.
          authorization: "Bearer sk_live_REDACTED_DEMO_TOKEN",
        },
      },
    });
    events.push({
      ...base(at(t + 180)),
      event_type: "tool.completed",
      tool_call_id: callId,
      duration_ms: 180,
      status: "success",
      response_bytes: 640,
    });
  }

  // 4. Read the customer CSV template (filesystem MCP).
  const templateCallId = "call_fs_read_1";
  events.push({
    ...base(at(3000)),
    event_type: "tool.invoked",
    tool_call_id: templateCallId,
    tool_name: "read_file",
    mcp_server: "filesystem",
    parameters: { path: "/home/brian/projects/demo/templates/customers.csv" },
  });
  events.push({
    ...base(at(3100)),
    event_type: "tool.completed",
    tool_call_id: templateCallId,
    duration_ms: 100,
    status: "success",
    response_bytes: 220,
  });
  events.push({
    ...base(at(3100)),
    event_type: "file.read",
    path: "/home/brian/projects/demo/templates/customers.csv",
    bytes: 220,
  });

  // 5. Sensitive read that should get flagged by the analyzer later.
  const passwdCallId = "call_fs_read_2";
  events.push({
    ...base(at(3500)),
    event_type: "tool.invoked",
    tool_call_id: passwdCallId,
    tool_name: "read_file",
    mcp_server: "filesystem",
    parameters: { path: "/etc/passwd" },
  });
  events.push({
    ...base(at(3550)),
    event_type: "tool.completed",
    tool_call_id: passwdCallId,
    duration_ms: 50,
    status: "success",
    response_bytes: 1530,
  });
  events.push({
    ...base(at(3550)),
    event_type: "file.read",
    path: "/etc/passwd",
    bytes: 1530,
  });

  // 6. Write the enriched CSV.
  const writeCallId = "call_fs_write_1";
  events.push({
    ...base(at(4000)),
    event_type: "tool.invoked",
    tool_call_id: writeCallId,
    tool_name: "write_file",
    mcp_server: "filesystem",
    parameters: { path: "/home/brian/projects/demo/out/enriched.csv" },
  });
  events.push({
    ...base(at(4120)),
    event_type: "tool.completed",
    tool_call_id: writeCallId,
    duration_ms: 120,
    status: "success",
    response_bytes: 0,
  });
  events.push({
    ...base(at(4120)),
    event_type: "file.written",
    path: "/home/brian/projects/demo/out/enriched.csv",
    bytes: 4480,
  });

  // 7. Synthetic risk detection added by a minimal analyzer. The real
  //    analyzer package will produce these itself; for now we inline
  //    canned detections so the projector has something non-trivial to
  //    apply.
  //
  //    related_event_id references the tool_call_id of the triggering
  //    tool call so the dashboard can cross-link risk events to timeline
  //    entries directly.
  events.push({
    ...base(at(4130)),
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "Session read /etc/passwd, a sensitive system file.",
    related_event_id: passwdCallId,
    rule_id: "RULE_SENSITIVE_PATH_READ",
  });

  // Flag the outbound HTTP calls that transmitted a live Stripe key.
  events.push({
    ...base(at(4140)),
    event_type: "risk.detected",
    severity: "CRITICAL",
    category: "credential_exfiltration",
    description: "Live Stripe API key transmitted to external enrichment endpoint via Bearer header.",
    related_event_id: "call_http_1",
    rule_id: "RULE_LIVE_CREDENTIAL_EXFIL",
  });

  // 8. Session end.
  events.push({
    ...base(at(4500)),
    event_type: "session.ended",
    duration_ms: 4500,
    status: "completed",
  });

  return events;
}
