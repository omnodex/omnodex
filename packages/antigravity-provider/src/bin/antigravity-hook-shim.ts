#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * antigravity-hook-shim
 *
 * The process Antigravity spawns for every hook event we subscribe to. Reads
 * the hook payload JSON from stdin, maps it into TraceEvents via
 * mapAntigravityPayload, and appends each event to the Omnodex event log.
 *
 * Contract (matching Antigravity 2.0 hook spec):
 *
 *   - argv[2]:  event name ("PreToolUse" | "PostToolUse" | "Stop")
 *   - stdin:    JSON payload (one object per invocation)
 *   - stdout:   JSON response (PreToolUse: decision, PostToolUse/Stop: {})
 *   - stderr:   diagnostics only
 *   - exit 0:   success; Antigravity continues normally.
 *   - exit 2:   signals Antigravity to block the current tool call
 *               (PreToolUse only). We never exit 2 -- we observe, not block.
 *
 * Environment:
 *
 *   OMNODEX_HOME   location of the event log (defaults to ~/.omnodex)
 *   OMNODEX_DEBUG  set to "1" for verbose stderr logging
 *
 * Antigravity payload differences from Codex:
 *   - Uses camelCase fields (conversationId, toolCall.name, etc.)
 *   - PostToolUse only receives stepIdx + error (no tool name/response)
 *   - No hook_event_name field; event name passed via CLI argument
 *   - No session_id; uses conversationId
 *   - No tool_use_id; uses stepIdx for Pre/Post correlation
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import { EventLog, newEventId } from "@omnodex/event-log";
import type {
  AntigravityHookEventName,
  AntigravityHookPayload,
  AntigravityPreToolUsePayload,
  PostToolUseCorrelation,
} from "../antigravity-payload.js";
import { mapAntigravityPayload } from "../antigravity-payload.js";

/** State saved during PreToolUse to correlate with the matching PostToolUse. */
interface PreToolUseState {
  toolName: string;
  toolCallId: string;
  invokedAt: number;
}

async function main(): Promise<number> {
  const debug = process.env.OMNODEX_DEBUG === "1";
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  const eventLogRoot = path.join(home, "event-log");
  const stateDir = path.join(home, "antigravity-state");
  await fs.mkdir(stateDir, { recursive: true });

  // Event name from CLI argument (set by the interceptor per-event command).
  const eventName = process.argv[2] as AntigravityHookEventName | undefined;
  if (!eventName || !["PreToolUse", "PostToolUse", "Stop"].includes(eventName)) {
    console.error(
      `[omnodex-antigravity] unknown or missing event name: ${eventName}`,
    );
    outputResponse(eventName);
    return 0;
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    if (debug) console.error("[omnodex-antigravity] empty stdin, nothing to do");
    outputResponse(eventName);
    return 0;
  }

  let payload: AntigravityHookPayload;
  try {
    payload = JSON.parse(raw) as AntigravityHookPayload;
  } catch (err) {
    console.error(
      `[omnodex-antigravity] could not parse stdin as JSON: ${(err as Error).message}`,
    );
    outputResponse(eventName);
    return 0;
  }

  if (!payload || typeof payload !== "object") {
    if (debug)
      console.error("[omnodex-antigravity] payload not an object, discarding");
    outputResponse(eventName);
    return 0;
  }

  try {
    const conversationId =
      "conversationId" in payload
        ? String((payload as { conversationId: string }).conversationId)
        : "unknown";
    let correlation: PostToolUseCorrelation | undefined;

    if (eventName === "PreToolUse") {
      const p = payload as AntigravityPreToolUsePayload;
      const toolCallId = `step-${p.stepIdx}`;
      const state: PreToolUseState = {
        toolName: p.toolCall?.name ?? "unknown",
        toolCallId,
        invokedAt: Date.now(),
      };
      await saveState(stateDir, conversationId, p.stepIdx, state);
    } else if (eventName === "PostToolUse") {
      const stepIdx = "stepIdx" in payload
        ? (payload as { stepIdx: number }).stepIdx
        : -1;
      const restored = await consumeState(stateDir, conversationId, stepIdx);
      if (restored) {
        correlation = {
          toolName: restored.toolName,
          toolCallId: restored.toolCallId,
          durationMs: Math.max(0, Date.now() - restored.invokedAt),
        };
      } else {
        correlation = {
          toolName: null,
          toolCallId: null,
          durationMs: 0,
        };
      }
    }

    const events = mapAntigravityPayload(eventName, payload, { newEventId }, correlation);
    if (events.length === 0) {
      if (debug)
        console.error(
          `[omnodex-antigravity] mapper produced zero events for ${eventName}`,
        );
      outputResponse(eventName);
      return 0;
    }

    const log = new EventLog({ root: eventLogRoot });
    await log.init();
    for (const event of events) {
      await log.append(event);
    }
    await log.close();

    if (debug) {
      console.error(
        `[omnodex-antigravity] wrote ${events.length} event(s) for ${eventName}`,
      );
    }

    outputResponse(eventName);
    return 0;
  } catch (err) {
    console.error(
      `[omnodex-antigravity] failed to write event: ${(err as Error).message}`,
    );
    outputResponse(eventName);
    return 0;
  }
}

// ---------------------------------------------------------------------------
// State persistence (Pre/Post correlation by stepIdx)
// ---------------------------------------------------------------------------

function stateKey(conversationId: string, stepIdx: number): string {
  // Sanitise conversationId for use as filename (UUID is safe, but be defensive).
  const safe = conversationId.replace(/[^a-zA-Z0-9_-]/g, "_");
  return `${safe}-${stepIdx}.json`;
}

async function saveState(
  dir: string,
  conversationId: string,
  stepIdx: number,
  state: PreToolUseState,
): Promise<void> {
  await fs.writeFile(
    path.join(dir, stateKey(conversationId, stepIdx)),
    JSON.stringify(state),
    "utf8",
  );
}

async function consumeState(
  dir: string,
  conversationId: string,
  stepIdx: number,
): Promise<PreToolUseState | null> {
  const p = path.join(dir, stateKey(conversationId, stepIdx));
  try {
    const raw = await fs.readFile(p, "utf8");
    await fs.unlink(p).catch(() => undefined);
    return JSON.parse(raw) as PreToolUseState;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// stdout response (Antigravity expects JSON on stdout)
// ---------------------------------------------------------------------------

function outputResponse(eventName?: string): void {
  if (eventName === "PreToolUse") {
    // We observe only; always allow the tool call.
    process.stdout.write(JSON.stringify({ decision: "allow" }));
  } else {
    // PostToolUse and Stop expect empty JSON.
    process.stdout.write("{}");
  }
}

// ---------------------------------------------------------------------------
// stdin
// ---------------------------------------------------------------------------

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`[omnodex-antigravity] unhandled: ${err}`);
    process.stdout.write("{}");
    process.exit(0);
  });
