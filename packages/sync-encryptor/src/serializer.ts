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
 * payload suitable for encryption and upload. The output shape mirrors
 * the local dashboard's data source so the hosted dashboard can render
 * identically after decryption.
 */

import type {
  ReadModelStore,
  SessionRow,
  ToolCallRow,
  FileEventRow,
  RiskEventRow,
} from "@omnodex/projection";

/** The shape of the serialized sync payload (pre-encryption). */
export interface SyncPayload {
  /** ISO 8601 timestamp when this payload was produced. */
  serialized_at: string;
  /** Schema version for forward-compat of the payload format. */
  payload_version: 1;
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
    toolCalls[id] = await store.listToolCalls(id);
    fileEvents[id] = await store.listFileEvents(id);
    riskEvents[id] = await store.listRiskEvents(id);
  }

  return {
    serialized_at: new Date().toISOString(),
    payload_version: 1,
    session_ids: ids,
    sessions,
    tool_calls: toolCalls,
    file_events: fileEvents,
    risk_events: riskEvents,
  };
}

/** Encode a SyncPayload to UTF-8 bytes. */
export function encodePayload(payload: SyncPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload));
}
