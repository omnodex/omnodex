// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Telling a Copilot run apart from a Claude Code run.
 *
 * Copilot also runs the hooks in a project's `.claude/settings.json`, with
 * Claude Code's event names and tool names, so a project that has Omnodex
 * installed for Claude Code fires the Claude Code launcher from Copilot
 * sessions. Where Omnodex also records Copilot directly, the Copilot hooks
 * already capture that run and label it correctly, so the Claude Code shim
 * steps aside rather than record the same call twice as Claude Code.
 *
 * No variable or field names the caller, so this reads the payload: Claude
 * Code always sends `transcript_path` (and `permission_mode`), and sends
 * `tool_use_id` on every tool event; Copilot's VS Code compatible payload
 * sends none of them on session, prompt and tool events. A payload with any
 * of those fields is treated as Claude Code's.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

/** Whether a payload that reached the Claude Code shim was sent by Copilot. */
export function looksLikeCopilotRun(input: unknown): boolean {
  if (!input || typeof input !== "object" || Array.isArray(input)) return false;
  const raw = input as Record<string, unknown>;
  if (raw.permission_mode !== undefined) return false;
  if (str(raw.transcript_path)) return false;
  const name = str(raw.hook_event_name);
  if (name === "PreToolUse" || name === "PostToolUse" || name === "PostToolUseFailure") {
    return str(raw.tool_use_id) === undefined;
  }
  return name === "SessionStart" || name === "SessionEnd" || name === "UserPromptSubmit";
}

/**
 * Whether Omnodex records Copilot on this machine: a Copilot hook install in
 * the registry, or Copilot set to record every project. Reads two small
 * files and never throws.
 */
export async function copilotCaptureInstalled(omnodexHome: string): Promise<boolean> {
  try {
    const registry = JSON.parse(await fs.readFile(path.join(omnodexHome, "installations.json"), "utf8")) as {
      installations?: { target?: unknown; component?: unknown }[];
    };
    if ((registry.installations ?? []).some((e) => e.target === "copilot" && (e.component === "hooks" || e.component === undefined))) return true;
  } catch {
    // no registry
  }
  try {
    const scope = JSON.parse(await fs.readFile(path.join(omnodexHome, "hook-scope.json"), "utf8")) as { everywhere?: unknown };
    return Array.isArray(scope.everywhere) && scope.everywhere.includes("copilot");
  } catch {
    return false;
  }
}
