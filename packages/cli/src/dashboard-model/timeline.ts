// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * The event timeline: tool calls interleaved with the prompts that asked
 * for them and the subagents that made some of them.
 */

import type { CollapsedToolCallRow, PromptRow, SessionView, SubagentRow } from "./view.js";

export type TimelineEntry =
  | { kind: "prompt"; at: string; prompt: PromptRow }
  | { kind: "subagent-start"; at: string; subagent: SubagentRow }
  | { kind: "call"; at: string; call: CollapsedToolCallRow; subagent?: SubagentRow }
  | { kind: "subagent-stop"; at: string; subagent: SubagentRow };

/** At the same instant: the prompt, then the subagent starting, its calls, its finish. */
const RANK: Record<TimelineEntry["kind"], number> = { prompt: 0, "subagent-start": 1, call: 2, "subagent-stop": 3 };

/** A subagent's key; ids are unique per session. */
export function subagentKey(row: Pick<SubagentRow, "session_id" | "agent_id">): string {
  return `${row.session_id}::${row.agent_id}`;
}

/**
 * Every entry for a view, oldest first, or newest first for the all-sessions
 * view, matching the order its tool calls already use. A call made inside a
 * subagent carries that subagent, so it can be labelled with its type.
 */
export function timelineEntries(view: SessionView, newestFirst: boolean): TimelineEntry[] {
  const subagents = new Map(view.subagents.map((a) => [subagentKey(a), a]));
  const entries: TimelineEntry[] = [];
  for (const prompt of view.prompts) entries.push({ kind: "prompt", at: prompt.at, prompt });
  for (const subagent of view.subagents) {
    if (subagent.started_at) entries.push({ kind: "subagent-start", at: subagent.started_at, subagent });
    if (subagent.ended_at) entries.push({ kind: "subagent-stop", at: subagent.ended_at, subagent });
  }
  for (const call of view.toolCalls) {
    const subagent = call.agent_id ? subagents.get(subagentKey({ session_id: call.session_id, agent_id: call.agent_id })) : undefined;
    entries.push({ kind: "call", at: call.started_at, call, ...(subagent ? { subagent } : {}) });
  }
  entries.sort((a, b) => (a.at || "").localeCompare(b.at || "") || RANK[a.kind] - RANK[b.kind]);
  return newestFirst ? entries.reverse() : entries;
}

/** What a subagent is called: its type, or a short form of its id. */
export function subagentLabel(row: Pick<SubagentRow, "agent_type" | "agent_id">): string {
  return row.agent_type || `subagent ${row.agent_id.slice(0, 8)}`;
}

/** A prompt shortened to one line for the timeline. */
export function promptPreview(text: string, max = 140): string {
  const line = text.replace(/\s+/g, " ").trim();
  return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}
