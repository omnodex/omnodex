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

import type {
  ReadModelStore,
  SessionRow,
  ToolCallRow,
  FileEventRow,
  RiskEventRow,
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
 */
export const PAYLOAD_FIELDS = {
  sessions: [
    "session_id", "user", "project_path", "mcp_servers", "interceptor",
    "started_at", "ended_at", "duration_ms", "status",
    "tool_call_count", "file_read_count", "file_write_count", "risk_score",
    "last_event_at", "source_root", "platform", "mcp_client_name",
  ],
  tool_calls: [
    "tool_call_id", "session_id", "tool_name", "mcp_server", "interceptor",
    "correlation_id", "parameters_json", "started_at", "ended_at",
    "duration_ms", "status", "response_bytes", "error_message",
  ],
  file_events: ["event_id", "session_id", "direction", "path", "bytes", "at"],
  risk_events: [
    "event_id", "session_id", "related_event_id", "severity", "category",
    "description", "rule_id", "detected_at", "correlation_id",
  ],
} as const satisfies {
  sessions: readonly (keyof SessionRow)[];
  tool_calls: readonly (keyof ToolCallRow)[];
  file_events: readonly (keyof FileEventRow)[];
  risk_events: readonly (keyof RiskEventRow)[];
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
}

/**
 * Serialize the read model into a SyncPayload.
 *
 * When sessionIds is provided, only those sessions are included.
 * When omitted, all sessions are serialized (full sync).
 */
export async function serializeReadModel(
  store: ReadModelStore,
  sessionIds?: string[],
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

  for (const id of ids) {
    toolCalls[id] = (await store.listToolCalls(id)).map((r) => pick(r, PAYLOAD_FIELDS.tool_calls) as ToolCallRow);
    fileEvents[id] = (await store.listFileEvents(id)).map((r) => pick(r, PAYLOAD_FIELDS.file_events) as FileEventRow);
    riskEvents[id] = (await store.listRiskEvents(id)).map((r) => pick(r, PAYLOAD_FIELDS.risk_events) as RiskEventRow);
  }

  return {
    serialized_at: new Date().toISOString(),
    payload_version: SYNC_PAYLOAD_VERSION,
    session_ids: ids,
    sessions: sessions.map((r) => pick(r, PAYLOAD_FIELDS.sessions) as SessionRow),
    tool_calls: toolCalls,
    file_events: fileEvents,
    risk_events: riskEvents,
  };
}

/** Encode a SyncPayload to UTF-8 bytes. */
export function encodePayload(payload: SyncPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload));
}
