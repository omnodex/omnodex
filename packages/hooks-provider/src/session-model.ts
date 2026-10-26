// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Claude Code session models, read from the session transcript.
 *
 * Claude Code's hook payloads do not name the model. Its transcript does,
 * on every assistant message, as the API reported it:
 *
 *   {"type":"assistant","isSidechain":false,"message":{"model":"...",...},...}
 *
 * The model of the last main-thread assistant message is the session's
 * current model. Subagent (sidechain) messages and the ones Claude Code
 * makes up itself (model "<synthetic>") are skipped. Only the model name is
 * read; message content is never kept.
 */

import { cleanModel } from "@omnodex/event-log";
import type { ClaudeCodeHookEventName } from "./claude-code-payload.js";

/**
 * Hooks that check for a new model, the same ones that check the title.
 * UserPromptSubmit runs once per turn, so a model used in one turn is
 * recorded when the next prompt arrives; SessionStart catches the model a
 * resumed session last used, and SessionEnd one used in the final turn.
 */
export const MODEL_HOOKS: ReadonlySet<ClaudeCodeHookEventName> = new Set<ClaudeCodeHookEventName>([
  "SessionStart",
  "UserPromptSubmit",
  "SessionEnd",
]);

/** The session's current model from transcript records, oldest first. */
export function modelFromTranscript(records: readonly unknown[]): string | null {
  for (let i = records.length - 1; i >= 0; i--) {
    const r = records[i] as { type?: unknown; isSidechain?: unknown; message?: { model?: unknown } } | null;
    if (!r || typeof r !== "object" || r.type !== "assistant" || r.isSidechain === true) continue;
    const model = cleanModel(r.message?.model);
    if (model && model !== "<synthetic>") return model;
  }
  return null;
}
