// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Call ids for Copilot tool calls.
 *
 * Copilot's hook payloads carry no id that ties a postToolUse to its
 * preToolUse. When the payload has none, the shim makes one on the pre-hook
 * and hands it to the matching post-hook: calls are matched on session, tool
 * and a hash of the input, oldest first, so two identical calls in flight
 * still pair up in order. The start time is kept alongside so the post-hook
 * can measure the call's duration.
 *
 * State is one small file per key under a directory the shim owns. A call
 * whose post-hook never arrives leaves an entry that is dropped after a day.
 */

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

const STALE_MS = 24 * 60 * 60 * 1000;

interface Entry {
  id: string;
  startedAt: number;
}

/** The id Copilot sent for this call, if it sent one. */
export function payloadCallId(payload: Record<string, unknown>): string | undefined {
  for (const key of ["tool_use_id", "toolUseId", "tool_call_id", "toolCallId"]) {
    const value = payload[key];
    if (typeof value === "string" && value) return value;
  }
  return undefined;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/** The file that queues the open calls for one session, tool and input. */
export function callKeyFile(dir: string, sessionId: string, toolName: string, toolInput: unknown): string {
  const hash = createHash("sha256").update(`${sessionId}\n${toolName}\n${stable(toolInput)}`).digest("hex").slice(0, 32);
  return path.join(dir, `${hash}.q`);
}

async function readQueue(file: string, now: number): Promise<Entry[]> {
  try {
    return (await fs.readFile(file, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [id, at] = line.split(" ");
        return { id: id ?? "", startedAt: Number(at) };
      })
      .filter((e) => e.id && Number.isFinite(e.startedAt) && now - e.startedAt < STALE_MS);
  } catch {
    return [];
  }
}

async function writeQueue(file: string, entries: Entry[]): Promise<void> {
  if (entries.length === 0) {
    await fs.rm(file, { force: true });
    return;
  }
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, entries.map((e) => `${e.id} ${e.startedAt}`).join("\n") + "\n", "utf8");
}

/** Record a new open call and return its id. */
export async function openCall(file: string, id: string, now: number = Date.now()): Promise<string> {
  const queue = await readQueue(file, now);
  queue.push({ id, startedAt: now });
  await writeQueue(file, queue);
  return id;
}

/** Close the oldest open call for this key: its id and how long it ran, or null when none is open. */
export async function closeCall(file: string, now: number = Date.now()): Promise<{ id: string; durationMs: number } | null> {
  const queue = await readQueue(file, now);
  const first = queue.shift();
  await writeQueue(file, queue);
  return first ? { id: first.id, durationMs: Math.max(0, now - first.startedAt) } : null;
}
