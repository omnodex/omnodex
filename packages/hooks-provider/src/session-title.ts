// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Claude Code session titles, read from the session transcript.
 *
 * Claude Code writes the title into the transcript, not into hook payloads:
 *
 *   {"type":"custom-title","customTitle":"...","sessionId":"..."}  after /rename
 *   {"type":"ai-title","aiTitle":"...","sessionId":"..."}          its own title
 *
 * Both are re-appended every few records, so the tail of the transcript
 * holds the current ones. A custom title always wins over an AI title.
 */

import type { FoundTitle } from "@omnodex/event-log";
import { cleanTitle, readJsonlTail } from "@omnodex/event-log";
import type { ClaudeCodeHookEventName } from "./claude-code-payload.js";

/**
 * Hooks that check for a new title. UserPromptSubmit runs once per turn,
 * so a rename shows up on the next prompt; SessionStart catches a resumed
 * session's title and SessionEnd a rename just before exit.
 */
export const TITLE_HOOKS: ReadonlySet<ClaudeCodeHookEventName> = new Set([
  "SessionStart",
  "UserPromptSubmit",
  "SessionEnd",
]);

/** The session's current title from transcript records, oldest first. */
export function titleFromTranscript(records: readonly unknown[]): FoundTitle | null {
  let custom: string | null = null;
  let ai: string | null = null;
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const r = record as { type?: unknown; customTitle?: unknown; aiTitle?: unknown };
    if (r.type === "custom-title") custom = cleanTitle(r.customTitle) ?? custom;
    else if (r.type === "ai-title") ai = cleanTitle(r.aiTitle) ?? ai;
  }
  if (custom) return { title: custom, source: "user" };
  if (ai) return { title: ai, source: "auto" };
  return null;
}

/** The current title from the tail of a transcript file. */
export async function readTranscriptTitle(transcriptPath: string | undefined): Promise<FoundTitle | null> {
  if (!transcriptPath) return null;
  return titleFromTranscript(await readJsonlTail(transcriptPath));
}
