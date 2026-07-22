// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * SQLite-backed ReadModelStore using Node 22's built-in node:sqlite module.
 * The projector replays the event log into this store; nothing else writes
 * here. Deleting the database file and replaying the log is a supported
 * operation.
 *
 * We deliberately use node:sqlite instead of better-sqlite3 so that the
 * project has zero native build steps. If we outgrow
 * what node:sqlite can do, swapping to better-sqlite3 is a drop-in change
 * behind the ReadModelStore interface.
 */

import { DatabaseSync } from "node:sqlite";
import * as path from "node:path";
import { promises as fs } from "node:fs";
import type {
  FileEventRow,
  ReadModelStore,
  RiskEventRow,
  SessionRow,
  ToolCallRow,
} from "./read-model.js";
import type { RiskSeverity } from "@omnodex/shared";

export interface SqliteReadModelStoreOptions {
  /** Absolute path to the SQLite database file. */
  dbPath: string;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  user TEXT NOT NULL,
  project_path TEXT NOT NULL,
  mcp_servers_json TEXT NOT NULL,
  interceptor TEXT NOT NULL DEFAULT 'unknown',
  started_at TEXT NOT NULL,
  ended_at TEXT,
  duration_ms INTEGER,
  status TEXT NOT NULL,
  tool_call_count INTEGER NOT NULL DEFAULT 0,
  file_read_count INTEGER NOT NULL DEFAULT 0,
  file_write_count INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 0,
  last_event_at TEXT NOT NULL DEFAULT '',
  source_root TEXT
);

CREATE TABLE IF NOT EXISTS tool_calls (
  tool_call_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(session_id),
  tool_name TEXT NOT NULL,
  mcp_server TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  duration_ms INTEGER,
  status TEXT NOT NULL,
  response_bytes INTEGER,
  error_message TEXT
);

CREATE TABLE IF NOT EXISTS file_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(session_id),
  direction TEXT NOT NULL,
  path TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(session_id),
  related_event_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  detected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_session ON tool_calls(session_id);
CREATE INDEX IF NOT EXISTS idx_file_events_session ON file_events(session_id);
CREATE INDEX IF NOT EXISTS idx_risk_events_session ON risk_events(session_id);

CREATE INDEX IF NOT EXISTS idx_sessions_last_event ON sessions(last_event_at);
CREATE INDEX IF NOT EXISTS idx_sessions_interceptor ON sessions(interceptor, last_event_at);
`;

export class SqliteReadModelStore implements ReadModelStore {
  private readonly dbPath: string;
  private db: DatabaseSync | null = null;

  constructor(options: SqliteReadModelStoreOptions) {
    this.dbPath = options.dbPath;
  }

  async init(): Promise<void> {
    await fs.mkdir(path.dirname(this.dbPath), { recursive: true });
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA_SQL);
    this.migrate();
  }

  /**
   * Forward-only migrations for existing databases. Each migration checks
   * whether the change has already been applied before running. New databases
   * get the full schema from SCHEMA_SQL and these are no-ops.
   */
  private migrate(): void {
    const db = this.requireDb();

    // Migration 1: add source_root column (2026-06-04).
    // SCHEMA_SQL includes the column for new DBs. Existing DBs need ALTER TABLE.
    const cols = db.prepare("PRAGMA table_info(sessions)").all() as Array<{ name: string }>;
    const hasSourceRoot = cols.some((c) => c.name === "source_root");
    if (!hasSourceRoot) {
      db.exec("ALTER TABLE sessions ADD COLUMN source_root TEXT");
    }
    // Index depends on source_root existing, so always create after migration.
    db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_source_root ON sessions(source_root, last_event_at)");
  }

  async reset(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    await fs.rm(this.dbPath, { force: true });
    await fs.rm(`${this.dbPath}-wal`, { force: true });
    await fs.rm(`${this.dbPath}-shm`, { force: true });
    await this.init();
  }

  async upsertSession(row: SessionRow): Promise<void> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `INSERT INTO sessions
        (session_id, user, project_path, mcp_servers_json, interceptor, started_at, ended_at, duration_ms, status, tool_call_count, file_read_count, file_write_count, risk_score, last_event_at, source_root)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET
        user = excluded.user,
        project_path = excluded.project_path,
        mcp_servers_json = excluded.mcp_servers_json,
        interceptor = excluded.interceptor,
        started_at = excluded.started_at,
        ended_at = excluded.ended_at,
        duration_ms = excluded.duration_ms,
        status = excluded.status,
        last_event_at = excluded.last_event_at,
        source_root = excluded.source_root`,
    );
    stmt.run(
      row.session_id,
      row.user,
      row.project_path,
      JSON.stringify(row.mcp_servers),
      row.interceptor,
      row.started_at,
      row.ended_at,
      row.duration_ms,
      row.status,
      row.tool_call_count,
      row.file_read_count,
      row.file_write_count,
      row.risk_score,
      row.last_event_at,
      row.source_root,
    );
  }

  async patchSession(
    sessionId: string,
    patch: Partial<Omit<SessionRow, "session_id">>,
  ): Promise<void> {
    const db = this.requireDb();
    const entries = Object.entries(patch).filter(([, v]) => v !== undefined);
    if (entries.length === 0) return;
    const setClauses: string[] = [];
    const values: unknown[] = [];
    for (const [key, value] of entries) {
      if (key === "mcp_servers") {
        setClauses.push(`mcp_servers_json = ?`);
        values.push(JSON.stringify(value));
      } else {
        setClauses.push(`${key} = ?`);
        values.push(value as unknown);
      }
    }
    values.push(sessionId);
    const stmt = db.prepare(
      `UPDATE sessions SET ${setClauses.join(", ")} WHERE session_id = ?`,
    );
    stmt.run(...(values as never[]));
  }

  async incrementSessionCounter(
    sessionId: string,
    field: "tool_call_count" | "file_read_count" | "file_write_count",
    delta: number,
  ): Promise<void> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `UPDATE sessions SET ${field} = ${field} + ? WHERE session_id = ?`,
    );
    stmt.run(delta, sessionId);
  }

  async addToRiskScore(sessionId: string, delta: number): Promise<void> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `UPDATE sessions SET risk_score = risk_score + ? WHERE session_id = ?`,
    );
    stmt.run(delta, sessionId);
  }

  async insertToolCall(row: ToolCallRow): Promise<void> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `INSERT INTO tool_calls
        (tool_call_id, session_id, tool_name, mcp_server, parameters_json, started_at, ended_at, duration_ms, status, response_bytes, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(tool_call_id) DO NOTHING`,
    );
    stmt.run(
      row.tool_call_id,
      row.session_id,
      row.tool_name,
      row.mcp_server,
      row.parameters_json,
      row.started_at,
      row.ended_at,
      row.duration_ms,
      row.status,
      row.response_bytes,
      row.error_message,
    );
  }

  async patchToolCall(
    toolCallId: string,
    patch: Partial<Omit<ToolCallRow, "tool_call_id" | "session_id">>,
  ): Promise<void> {
    const db = this.requireDb();
    const entries = Object.entries(patch).filter(([, v]) => v !== undefined);
    if (entries.length === 0) return;
    const setClauses = entries.map(([k]) => `${k} = ?`).join(", ");
    const values = entries.map(([, v]) => v as unknown);
    values.push(toolCallId);
    const stmt = db.prepare(
      `UPDATE tool_calls SET ${setClauses} WHERE tool_call_id = ?`,
    );
    stmt.run(...(values as never[]));
  }

  async addMcpServer(sessionId: string, mcpServer: string): Promise<void> {
    const db = this.requireDb();
    const select = db.prepare(
      `SELECT mcp_servers_json FROM sessions WHERE session_id = ?`,
    );
    const row = select.get(sessionId) as { mcp_servers_json: string } | undefined;
    if (!row) return;
    const current: string[] = JSON.parse(row.mcp_servers_json);
    if (current.includes(mcpServer)) return;
    current.push(mcpServer);
    const update = db.prepare(
      `UPDATE sessions SET mcp_servers_json = ? WHERE session_id = ?`,
    );
    update.run(JSON.stringify(current), sessionId);
  }

  async insertFileEvent(row: FileEventRow): Promise<void> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `INSERT INTO file_events (session_id, direction, path, bytes, at) VALUES (?, ?, ?, ?, ?)`,
    );
    stmt.run(row.session_id, row.direction, row.path, row.bytes, row.at);
  }

  async insertRiskEvent(row: RiskEventRow): Promise<void> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `INSERT INTO risk_events (session_id, related_event_id, severity, category, description, rule_id, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    stmt.run(
      row.session_id,
      row.related_event_id,
      row.severity,
      row.category,
      row.description,
      row.rule_id,
      row.detected_at,
    );
  }

  async getSession(sessionId: string): Promise<SessionRow | null> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `SELECT * FROM sessions WHERE session_id = ?`,
    );
    const raw = stmt.get(sessionId) as unknown as SessionRowRaw | undefined;
    return raw ? toSessionRow(raw) : null;
  }

  async listSessions(): Promise<SessionRow[]> {
    const db = this.requireDb();
    const stmt = db.prepare(`SELECT * FROM sessions ORDER BY last_event_at DESC, started_at DESC`);
    return (stmt.all() as unknown as SessionRowRaw[]).map(toSessionRow);
  }

  async listToolCalls(sessionId: string): Promise<ToolCallRow[]> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `SELECT * FROM tool_calls WHERE session_id = ? ORDER BY started_at`,
    );
    return (stmt.all(sessionId) as unknown as ToolCallRowRaw[]).map(toToolCallRow);
  }

  async listFileEvents(sessionId: string): Promise<FileEventRow[]> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `SELECT session_id, direction, path, bytes, at FROM file_events WHERE session_id = ? ORDER BY at`,
    );
    return stmt.all(sessionId) as unknown as FileEventRow[];
  }

  async listRiskEvents(sessionId: string): Promise<RiskEventRow[]> {
    const db = this.requireDb();
    const stmt = db.prepare(
      `SELECT session_id, related_event_id, severity, category, description, rule_id, detected_at FROM risk_events WHERE session_id = ? ORDER BY detected_at`,
    );
    return (stmt.all(sessionId) as unknown as RiskEventRowRaw[]).map((r) => ({
      ...r,
      severity: r.severity as RiskSeverity,
    }));
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  private requireDb(): DatabaseSync {
    if (!this.db) {
      throw new Error("SqliteReadModelStore.init() must be awaited before use");
    }
    return this.db;
  }
}

interface SessionRowRaw {
  session_id: string;
  user: string;
  project_path: string;
  mcp_servers_json: string;
  interceptor: string;
  started_at: string;
  ended_at: string | null;
  duration_ms: number | null;
  status: string;
  tool_call_count: number;
  file_read_count: number;
  file_write_count: number;
  risk_score: number;
  last_event_at: string;
  source_root: string | null;
}

interface ToolCallRowRaw {
  tool_call_id: string;
  session_id: string;
  tool_name: string;
  mcp_server: string;
  parameters_json: string;
  started_at: string;
  ended_at: string | null;
  duration_ms: number | null;
  status: string;
  response_bytes: number | null;
  error_message: string | null;
}

interface RiskEventRowRaw {
  session_id: string;
  related_event_id: string;
  severity: string;
  category: string;
  description: string;
  rule_id: string;
  detected_at: string;
}

function toSessionRow(raw: SessionRowRaw): SessionRow {
  return {
    session_id: raw.session_id,
    user: raw.user,
    project_path: raw.project_path,
    mcp_servers: JSON.parse(raw.mcp_servers_json) as string[],
    interceptor: raw.interceptor as SessionRow["interceptor"],
    started_at: raw.started_at,
    ended_at: raw.ended_at,
    duration_ms: raw.duration_ms,
    status: raw.status as SessionRow["status"],
    tool_call_count: raw.tool_call_count,
    file_read_count: raw.file_read_count,
    file_write_count: raw.file_write_count,
    risk_score: raw.risk_score,
    last_event_at: raw.last_event_at,
    source_root: raw.source_root,
  };
}

function toToolCallRow(raw: ToolCallRowRaw): ToolCallRow {
  return {
    tool_call_id: raw.tool_call_id,
    session_id: raw.session_id,
    tool_name: raw.tool_name,
    mcp_server: raw.mcp_server,
    parameters_json: raw.parameters_json,
    started_at: raw.started_at,
    ended_at: raw.ended_at,
    duration_ms: raw.duration_ms,
        status: raw.status as ToolCallRow["status"],
    response_bytes: raw.response_bytes,
    error_message: raw.error_message,
  };
}
