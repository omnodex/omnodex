// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Session titles for hook shims.
 *
 * Agent runtimes keep a session's title in their own files (a transcript, an
 * index), not in hook payloads. A shim reads the tail of that file on a few
 * lifecycle hooks and emits `session.renamed` only when the title differs
 * from the last one it recorded for the session, so the event log gains one
 * event per rename rather than one per turn.
 *
 * The last recorded title lives in <home>/session-titles/<session>.json.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import type { InterceptorKind, SessionRenamedEvent } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

/**
 * "user" for a title the user set (a rename), "auto" for one the runtime
 * generated. A user title is never replaced by an auto one, because a
 * runtime can keep writing its generated title after the user renames.
 */
export type TitleSource = "user" | "auto";

export interface FoundTitle {
  title: string;
  source: TitleSource;
}

/** How much of a file's end a hook reads, to stay inside its time budget. */
export const TITLE_TAIL_BYTES = 256 * 1024;

/** Titles longer than this are cut, so one record cannot bloat every row. */
const MAX_TITLE_LENGTH = 200;

/**
 * Parsed records from the last `maxBytes` of a JSONL file, oldest first.
 * When the read starts mid-file the first, partial line is dropped, and a
 * line that does not parse (a write still in progress) is skipped. Empty
 * when the file is missing or unreadable.
 */
export async function readJsonlTail(file: string, maxBytes = TITLE_TAIL_BYTES): Promise<unknown[]> {
  let raw: string;
  try {
    const fh = await fs.open(file, "r");
    try {
      const { size } = await fh.stat();
      const start = Math.max(0, size - maxBytes);
      const buf = Buffer.alloc(size - start);
      await fh.read(buf, 0, buf.length, start);
      raw = buf.toString("utf8");
      if (start > 0) raw = raw.slice(raw.indexOf("\n") + 1);
    } finally {
      await fh.close();
    }
  } catch {
    return [];
  }
  const out: unknown[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      // Partial or corrupt line.
    }
  }
  return out;
}

/** Trimmed and length-capped, or null when nothing is left. */
export function cleanTitle(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const title = value.replace(/\s+/g, " ").trim();
  if (!title) return null;
  return title.length > MAX_TITLE_LENGTH ? title.slice(0, MAX_TITLE_LENGTH) : title;
}

function statePath(home: string, sessionId: string): string {
  return path.join(home, "session-titles", `${sessionId.replace(/[^a-zA-Z0-9_.-]/g, "_")}.json`);
}

/**
 * Whether `found` is news for the session, recording it when it is. False
 * when it matches the last recorded title, or when it is an auto title and
 * the user already set one.
 */
export async function claimTitleChange(home: string, sessionId: string, found: FoundTitle): Promise<boolean> {
  const file = statePath(home, sessionId);
  let last: Partial<FoundTitle> = {};
  try {
    last = JSON.parse(await fs.readFile(file, "utf8")) as Partial<FoundTitle>;
  } catch {
    // No title recorded yet.
  }
  if (last.title === found.title) return false;
  if (last.source === "user" && found.source === "auto") return false;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(found), "utf8");
  return true;
}

export interface SessionRenamedOptions {
  home: string;
  sessionId: string;
  interceptor: InterceptorKind;
  newEventId: () => string;
  nowIso?: () => string;
}

/**
 * A `session.renamed` event for `found` when it is a new title for the
 * session, otherwise null. Never throws: a title is not worth failing a hook.
 */
export async function sessionRenamedIfChanged(
  found: FoundTitle | null,
  options: SessionRenamedOptions,
): Promise<SessionRenamedEvent | null> {
  if (!found || !options.sessionId) return null;
  try {
    if (!(await claimTitleChange(options.home, options.sessionId, found))) return null;
  } catch {
    return null;
  }
  const now = (options.nowIso ?? (() => new Date().toISOString()))();
  return {
    schema_version: SCHEMA_VERSION,
    event_id: options.newEventId(),
    event_type: "session.renamed",
    session_id: options.sessionId,
    occurred_at: now,
    recorded_at: now,
    interceptor: options.interceptor,
    title: found.title,
  };
}
