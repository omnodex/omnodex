// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/event-log
 *
 * Append-only JSONL event log. This is the source of truth for the
 * system. All interceptors write
 * events here; the projector reads them to rebuild the SQLite read model
 * on demand.
 *
 * Layout on disk:
 *
 *   <root>/
 *     index.jsonl                 list of session_id + path pairs
 *     sessions/
 *       <session_id>.jsonl        one file per session, append-only
 *
 * The one-file-per-session layout maps cleanly onto future object storage
 * (one object per session) without a writer rewrite.
 */

import { promises as fs } from "node:fs";
import * as fsSync from "node:fs";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import type { TraceEvent } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

export interface EventLogOptions {
  /** Absolute path to the event log root directory. */
  root: string;
}

/**
 * Append-only event log. Thread-safe across processes via O_APPEND
 * semantics for the per-session files. Reads are non-locking and may see
 * a tail that is mid-write; callers should tolerate trailing partial
 * lines and discard them.
 */
export class EventLog {
  private readonly root: string;
  private readonly sessionsDir: string;
  private readonly indexPath: string;
  private readonly openHandles = new Map<string, fsSync.WriteStream>();
  private readonly knownSessions = new Set<string>();

  constructor(options: EventLogOptions) {
    this.root = options.root;
    this.sessionsDir = path.join(this.root, "sessions");
    this.indexPath = path.join(this.root, "index.jsonl");
  }

  /** Ensure the event log directory layout exists. */
  async init(): Promise<void> {
    await fs.mkdir(this.sessionsDir, { recursive: true });
    // Touch the index so readers can tail an empty log safely.
    try {
      await fs.access(this.indexPath);
    } catch {
      await fs.writeFile(this.indexPath, "", { flag: "a" });
    }
    // Populate knownSessions from the existing index so we do not
    // re-register sessions on restart.
    const indexRaw = await fs.readFile(this.indexPath, "utf8").catch(() => "");
    for (const line of indexRaw.split("\n")) {
      if (!line.trim()) continue;
      try {
        const { session_id } = JSON.parse(line) as { session_id?: string };
        if (session_id) this.knownSessions.add(session_id);
      } catch {
        // Skip malformed trailing writes.
      }
    }
  }

  /**
   * Append a single event to the session's log file. Writes to the index
   * on the first event for a given session_id.
   */
  async append(event: TraceEvent): Promise<void> {
    this.assertValid(event);
    if (!this.knownSessions.has(event.session_id)) {
      await this.registerSession(event.session_id);
    }
    const stream = this.openStreamFor(event.session_id);
    const line = JSON.stringify(event) + "\n";
    await new Promise<void>((resolve, reject) => {
      stream.write(line, (err) => (err ? reject(err) : resolve()));
    });
  }

  /** Append many events in order. */
  async appendMany(events: Iterable<TraceEvent>): Promise<void> {
    for (const event of events) {
      await this.append(event);
    }
  }

  /**
   * Read all events for a given session. Malformed trailing lines (i.e.
   * a write that was observed mid-flush) are skipped rather than failing.
   */
  async readSession(sessionId: string): Promise<TraceEvent[]> {
    const filePath = this.sessionFilePath(sessionId);
    const raw = await fs.readFile(filePath, "utf8").catch((err: unknown) => {
      if (isNoEnt(err)) return "";
      throw err;
    });
    return parseJsonl(raw);
  }

  /** Stream all events across all sessions in session-discovery order. */
  async *readAll(): AsyncGenerator<TraceEvent> {
    const sessions = await this.listSessions();
    for (const sessionId of sessions) {
      for (const event of await this.readSession(sessionId)) {
        yield event;
      }
    }
  }

  /** Return the list of session ids currently in the index. */
  async listSessions(): Promise<string[]> {
    const raw = await fs.readFile(this.indexPath, "utf8").catch(() => "");
    const out: string[] = [];
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      try {
        const { session_id } = JSON.parse(line) as { session_id?: string };
        if (session_id) out.push(session_id);
      } catch {
        // Skip malformed lines.
      }
    }
    return out;
  }

  /** Close any open file handles. Safe to call multiple times. */
  async close(): Promise<void> {
    const handles = [...this.openHandles.values()];
    this.openHandles.clear();
    await Promise.all(
      handles.map(
        (h) =>
          new Promise<void>((resolve) => {
            h.end(() => resolve());
          }),
      ),
    );
  }

  /**
   * Tail a session file, yielding new events as they are appended.
   *
   * Polls the file every `pollMs` milliseconds (default 200 ms). If the
   * file does not yet exist, keeps polling until it appears. Stops cleanly
   * when `signal` is aborted.
   *
   * Events that were already in the file at the time of the first poll are
   * yielded first (offset starts at 0), so callers should pre-seed their
   * own deduplication state from the existing log before calling tail() if
   * they want to skip historical events.
   */
  async *tail(
    sessionId: string,
    signal?: AbortSignal,
    pollMs = 200,
  ): AsyncGenerator<TraceEvent> {
    const filePath = this.sessionFilePath(sessionId);
    let offset = 0;
    let partial = "";

    while (!signal?.aborted) {
      let newBytes: string | null = null;
      try {
        const stat = await fs.stat(filePath);
        if (stat.size > offset) {
          const buf = Buffer.alloc(stat.size - offset);
          const fh = await fs.open(filePath, "r");
          await fh.read(buf, 0, buf.length, offset);
          await fh.close();
          offset = stat.size;
          newBytes = buf.toString("utf8");
        }
      } catch {
        // File not yet created or a transient read error -- keep waiting.
      }

      if (newBytes) {
        partial += newBytes;
        const lines = partial.split("\n");
        partial = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            yield JSON.parse(line) as TraceEvent;
          } catch {
            // Skip malformed lines (e.g. a partial write from a concurrent
            // producer on the last line of the file).
          }
        }
      } else {
        await sleep(pollMs);
      }
    }
  }

  /** Absolute path to the per-session JSONL file. */
  sessionFilePath(sessionId: string): string {
    return path.join(this.sessionsDir, `${sanitize(sessionId)}.jsonl`);
  }

  private openStreamFor(sessionId: string): fsSync.WriteStream {
    let stream = this.openHandles.get(sessionId);
    if (stream) return stream;
    stream = fsSync.createWriteStream(this.sessionFilePath(sessionId), {
      flags: "a",
      encoding: "utf8",
    });
    this.openHandles.set(sessionId, stream);
    return stream;
  }

  private async registerSession(sessionId: string): Promise<void> {
    this.knownSessions.add(sessionId);
    const entry = JSON.stringify({
      session_id: sessionId,
      registered_at: new Date().toISOString(),
      file: path.relative(this.root, this.sessionFilePath(sessionId)),
    }) + "\n";
    await fs.appendFile(this.indexPath, entry, { encoding: "utf8" });
  }

  private assertValid(event: TraceEvent): void {
    if (event.schema_version !== SCHEMA_VERSION) {
      throw new Error(
        `event-log: refusing write for schema_version=${event.schema_version}, expected ${SCHEMA_VERSION}`,
      );
    }
    if (!event.session_id) {
      throw new Error("event-log: event missing session_id");
    }
    if (!event.event_id) {
      throw new Error("event-log: event missing event_id");
    }
  }
}

function parseJsonl(raw: string): TraceEvent[] {
  const out: TraceEvent[] = [];
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || !line.trim()) continue;
    try {
      out.push(JSON.parse(line) as TraceEvent);
    } catch {
      // A partial trailing write from a concurrent producer is expected
      // on the last line only. Anywhere else is a real problem, but we
      // prefer resilience over strictness.
      if (i !== lines.length - 1) {
        // Non-trailing parse failures are still swallowed in v0; we log
        // them in a future version.
      }
    }
  }
  return out;
}

function sanitize(sessionId: string): string {
  return sessionId.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isNoEnt(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { code?: string }).code === "ENOENT"
  );
}

/** Tiny helper exported for tests that want a freshly stamped event id. */
export function newEventId(): string {
  // Keep dependency-free. Uses 16 random bytes.
  const buf = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) buf[i] = Math.floor(Math.random() * 256);
  return buf.toString("hex");
}
