// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Codex thread names, read from Codex's session index.
 *
 * Codex appends a record to <codex home>/session_index.jsonl whenever a
 * thread is named, by Codex or by the user:
 *
 *   {"id":"<session id>","thread_name":"...","updated_at":"..."}
 *
 * The id is the hook payload's session_id, a thread can have several
 * records, and the last one is its current name. Codex does not say who
 * chose the name, so every name counts as the user's.
 */

import * as os from "node:os";
import * as path from "node:path";
import type { FoundTitle } from "@omnodex/event-log";
import { cleanTitle, readJsonlTail } from "@omnodex/event-log";
import type { CodexHookEventName } from "./codex-payload.js";

/**
 * Hooks that check for a new name. Codex names a thread after its first
 * turn, so Stop picks that up; UserPromptSubmit and SessionStart catch
 * renames and resumed threads.
 */
export const TITLE_HOOKS: ReadonlySet<CodexHookEventName> = new Set([
  "SessionStart",
  "UserPromptSubmit",
  "Stop",
]);

/** The thread's current name from session index records, oldest first. */
export function titleFromSessionIndex(records: readonly unknown[], sessionId: string): FoundTitle | null {
  let name: string | null = null;
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const r = record as { id?: unknown; thread_name?: unknown };
    if (r.id !== sessionId) continue;
    name = cleanTitle(r.thread_name) ?? name;
  }
  return name ? { title: name, source: "user" } : null;
}

/**
 * Codex's home directory: CODEX_HOME when set, else the directory that holds
 * the transcript's sessions/ tree (transcripts live at
 * <home>/sessions/YYYY/MM/DD/rollout-*.jsonl), else ~/.codex.
 */
export function codexHome(
  transcriptPath: string | null | undefined,
  env: NodeJS.ProcessEnv = process.env,
  homedir: string = os.homedir(),
): string {
  if (env.CODEX_HOME) return env.CODEX_HOME;
  if (transcriptPath) {
    const parts = transcriptPath.split(/[\\/]/);
    const i = parts.lastIndexOf("sessions");
    if (i > 0) return parts.slice(0, i).join(transcriptPath.includes("\\") ? "\\" : "/");
  }
  return path.join(homedir, ".codex");
}

/** The thread's current name from the tail of Codex's session index. */
export async function readCodexThreadName(
  sessionId: string,
  transcriptPath: string | null | undefined,
): Promise<FoundTitle | null> {
  const index = path.join(codexHome(transcriptPath), "session_index.jsonl");
  return titleFromSessionIndex(await readJsonlTail(index), sessionId);
}
