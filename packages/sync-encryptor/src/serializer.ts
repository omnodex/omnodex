// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- serializer
 *
 * Reads the SQLite read model and serializes projection data into a JSON
 * payload suitable for encryption and upload.
 *
 * The payload is the hosted dashboard's contract, not a copy of the read
 * model: each row carries exactly the fields listed in PAYLOAD_FIELDS. A
 * column added to the read model for local use stays local until it is
 * listed here, and it should be listed only when the hosted dashboard
 * reads it.
 */

import type { CapturePauseRow } from "@omnodex/event-log";
import type { MonitoringChangeRow } from "@omnodex/shared";
import type {
  ReadModelStore,
  SessionRow,
  ToolCallRow,
  FileEventRow,
  RiskEventRow,
  PromptRow,
  SubagentRow,
} from "@omnodex/projection";

/**
 * Current payload format version. Bump when a consumer needs to tell this
 * payload apart from an older one, and say why in the payload_version doc
 * comment below.
 */
export const SYNC_PAYLOAD_VERSION = 2;

/**
 * The fields each payload row carries. Adding an optional field needs no
 * version bump: a reader that predates it ignores it, and a newer reader
 * treats its absence in an older blob as unknown.
 *
 * sessions.platform: the hosted dashboard labels a session by its surface,
 * and a Claude Code hook session in platform "cowork" is a Cowork cloud
 * task. Live events carry platform; without it here the same session
 * relabelled itself after a reload.
 *
 * sessions.mcp_client_name: a proxy session is labelled "<platform> via MCP
 * Proxy", or by the name its MCP client gave itself when no platform is
 * known. Hosted needs the name for that fallback.
 *
 * sessions.title: the session list names a session by its title when one
 * was recorded, rather than by its project folder.
 *
 * tool_calls.agent_id, prompts, subagents: the session view shows what the
 * session was asked, which subagents it ran, and which calls each made.
 * Prompt text travels only inside the encrypted payload, as tool parameters
 * do. Blobs from before these were added have no prompts or subagents.
 *
 * risk_events.rule_tier, related_event_ids, evidence: hosted hides
 * advanced-tier findings from an account that is not entitled to them, and
 * groups findings on a sequence of calls into one investigation by the
 * calls and destination their evidence names. Evidence summaries are built
 * from what a call read and reached, never from command text, and travel
 * only inside the encrypted payload, as tool parameters do.
 *
 * risk_events.enforcement: what enforcement made of a finding when it was
 * captured (the mode, the rule's candidate verdict, the verdict the user's
 * settings give, whether the call was held), so the hosted dashboard can show
 * what shadow mode would have stopped. Verdicts and rule ids only.
 *
 * capture_pauses (top level, not per session): each time recording or
 * uploads were paused on the machine, so the dashboard can show the gap
 * even if it was not open when the pause happened. They carry no captured
 * content. Blobs from before pauses existed have none.
 */
export const PAYLOAD_FIELDS = {
  sessions: [
    "session_id", "user", "project_path", "mcp_servers", "interceptor",
    "started_at", "ended_at", "duration_ms", "status",
    "tool_call_count", "file_read_count", "file_write_count", "risk_score",
    "last_event_at", "source_root", "platform", "mcp_client_name", "title",
  ],
  tool_calls: [
    "tool_call_id", "session_id", "tool_name", "mcp_server", "interceptor",
    "correlation_id", "parameters_json", "started_at", "ended_at",
    "duration_ms", "status", "response_bytes", "error_message", "agent_id",
  ],
  file_events: ["event_id", "session_id", "direction", "path", "bytes", "at"],
  risk_events: [
    "event_id", "session_id", "related_event_id", "severity", "category",
    "description", "rule_id", "detected_at", "correlation_id",
    "rule_tier", "related_event_ids", "evidence", "enforcement",
  ],
  prompts: ["event_id", "session_id", "prompt", "prompt_id", "at"],
  subagents: [
    "session_id", "agent_id", "agent_type", "started_at", "ended_at",
    "duration_ms", "status", "response_bytes",
  ],
} as const satisfies {
  sessions: readonly (keyof SessionRow)[];
  tool_calls: readonly (keyof ToolCallRow)[];
  file_events: readonly (keyof FileEventRow)[];
  risk_events: readonly (keyof RiskEventRow)[];
  prompts: readonly (keyof PromptRow)[];
  subagents: readonly (keyof SubagentRow)[];
};

/** The row with only the listed fields. A field the row lacks stays absent. */
function pick<T extends object, K extends keyof T>(row: T, fields: readonly K[]): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const field of fields) {
    if (row[field] !== undefined) out[field] = row[field];
  }
  return out;
}

/** The shape of the serialized sync payload (pre-encryption). */
export interface SyncPayload {
  /** ISO 8601 timestamp when this payload was produced. */
  serialized_at: string;
  /**
   * Schema version for forward-compat of the payload format.
   *
   * 1: risk_score on the old severity scale (LOW 5, MEDIUM 15, HIGH 30,
   *    CRITICAL 60).
   * 2: risk_score on the scale in RISK_SEVERITY_WEIGHT (LOW 0.1, MEDIUM 0.4,
   *    HIGH 0.7, CRITICAL 1.0), and correlation_id present on tool calls.
   *
   * A reader has to know which scale a blob is on: the two are not related by
   * a constant factor, so a v1 score cannot be converted arithmetically. It
   * can, however, be recomputed exactly from the risk_events the payload
   * already carries, which is what the hosted dashboard does on load. Version
   * the payload rather than guessing from the magnitude of the numbers.
   */
  payload_version: number;
  /** Session IDs included in this sync. */
  session_ids: string[];
  sessions: SessionRow[];
  tool_calls: Record<string, ToolCallRow[]>;
  file_events: Record<string, FileEventRow[]>;
  risk_events: Record<string, RiskEventRow[]>;
  prompts: Record<string, PromptRow[]>;
  subagents: Record<string, SubagentRow[]>;
  /** Pauses of recording or uploads on this machine. Absent before pauses existed. */
  capture_pauses?: CapturePauseRow[];
  /**
   * Installs, removals and other changes to Omnodex on this machine, so the
   * hosted dashboard can tell a planned change from an unexplained one.
   * Absent before monitoring markers existed.
   */
  monitoring_changes?: MonitoringChangeRow[];
}

/**
 * Serialize the read model into a SyncPayload.
 *
 * When sessionIds is provided, only those sessions are included.
 * When omitted, all sessions are serialized (full sync). Pauses, when given,
 * are carried as they are.
 */
export async function serializeReadModel(
  store: ReadModelStore,
  sessionIds?: string[],
  pauses?: CapturePauseRow[],
  monitoringChanges?: MonitoringChangeRow[],
): Promise<SyncPayload> {
  const sessions = sessionIds
    ? await Promise.all(
        sessionIds.map((id) => store.getSession(id)),
      ).then((rows) => rows.filter((r): r is SessionRow => r !== null))
    : await store.listSessions();

  const ids = sessions.map((s) => s.session_id);

  const toolCalls: Record<string, ToolCallRow[]> = {};
  const fileEvents: Record<string, FileEventRow[]> = {};
  const riskEvents: Record<string, RiskEventRow[]> = {};
  const prompts: Record<string, PromptRow[]> = {};
  const subagents: Record<string, SubagentRow[]> = {};

  for (const id of ids) {
    toolCalls[id] = (await store.listToolCalls(id)).map((r) => pick(r, PAYLOAD_FIELDS.tool_calls) as ToolCallRow);
    fileEvents[id] = (await store.listFileEvents(id)).map((r) => pick(r, PAYLOAD_FIELDS.file_events) as FileEventRow);
    riskEvents[id] = (await store.listRiskEvents(id)).map((r) => pick(r, PAYLOAD_FIELDS.risk_events) as RiskEventRow);
    // Only sessions that have any, to keep blobs from older sessions as they were.
    const sessionPrompts = await store.listPrompts(id);
    if (sessionPrompts.length) prompts[id] = sessionPrompts.map((r) => pick(r, PAYLOAD_FIELDS.prompts) as PromptRow);
    const sessionSubagents = await store.listSubagents(id);
    if (sessionSubagents.length) subagents[id] = sessionSubagents.map((r) => pick(r, PAYLOAD_FIELDS.subagents) as SubagentRow);
  }

  return {
    serialized_at: new Date().toISOString(),
    payload_version: SYNC_PAYLOAD_VERSION,
    session_ids: ids,
    sessions: sessions.map((r) => pick(r, PAYLOAD_FIELDS.sessions) as SessionRow),
    tool_calls: toolCalls,
    file_events: fileEvents,
    risk_events: riskEvents,
    prompts,
    subagents,
    ...(pauses?.length ? { capture_pauses: pauses } : {}),
    ...(monitoringChanges?.length ? { monitoring_changes: monitoringChanges } : {}),
  };
}

/** Encode a SyncPayload to UTF-8 bytes. */
export function encodePayload(payload: SyncPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload));
}
