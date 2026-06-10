#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * claude-hook-shim
 *
 * The process Claude Code spawns for every hook event we subscribe to.
 * Reads the hook payload JSON from stdin, maps it into TraceEvents via
 * the pure mapper in `../claude-code-payload.ts`, and appends each event
 * to the Omnodex event log.
 *
 * Contract (enforced by Claude Code):
 *
 *   - stdin: JSON payload (one object, one invocation)
 *   - stdout: must stay empty, otherwise Claude Code tries to interpret
 *             it as a hook decision. Use stderr for diagnostics.
 *   - exit code 0: success. Any other code is a non-blocking error
 *             except 2, which blocks the tool call. We never want to
 *             block so we always exit 0 unless we are about to crash.
 *
 * Environment:
 *
 *   - OMNODEX_HOME      location of the event log, defaults to ~/.omnodex
 *   - OMNODEX_DEBUG     set to "1" to get verbose stderr logging
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import { EventLog, newEventId } from "@omnodex/event-log";
import type { ClaudeCodeHookPayload } from "../claude-code-payload.js";
import { mapClaudeCodePayload } from "../claude-code-payload.js";

async function main(): Promise<number> {
  const debug = process.env.OMNODEX_DEBUG === "1";
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  const eventLogRoot = path.join(home, "event-log");

  const timingDir = path.join(home, "timing");
  await fs.mkdir(timingDir, { recursive: true });

  /**
   * Persist the invoke timestamp for a tool call so PostToolUse can
   * compute a real duration_ms. Claude Code does not send duration_ms
   * on PostToolUse, so we measure it ourselves from wall-clock deltas.
   */
  async function saveInvokeTime(toolUseId: string): Promise<void> {
    const p = path.join(timingDir, `${toolUseId}.ts`);
    await fs.writeFile(p, String(Date.now()), "utf8");
  }

  /**
   * Read the saved invoke timestamp, compute elapsed ms, then delete the
   * timing file. Returns null if the file is missing (e.g. shim restarted).
   */
  async function consumeInvokeTime(toolUseId: string): Promise<number | null> {
    const p = path.join(timingDir, `${toolUseId}.ts`);
    try {
      const raw = await fs.readFile(p, "utf8");
      await fs.unlink(p).catch(() => undefined);
      const invokedAt = parseInt(raw, 10);
      if (isNaN(invokedAt)) return null;
      return Math.max(0, Date.now() - invokedAt);
    } catch {
      return null;
    }
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    if (debug) console.error("[omnodex-hook] empty stdin, nothing to do");
    return 0;
  }

  let payload: ClaudeCodeHookPayload;
  try {
    payload = JSON.parse(raw) as ClaudeCodeHookPayload;
  } catch (err) {
    console.error(
      `[omnodex-hook] could not parse stdin as JSON: ${(err as Error).message}`,
    );
    // Exit 0 so we never block Claude, even on malformed input.
    return 0;
  }

  if (!payload || typeof payload !== "object" || !payload.hook_event_name) {
    if (debug)
      console.error(
        `[omnodex-hook] payload missing hook_event_name, discarding`,
      );
    return 0;
  }

  try {
    // --- duration_ms tracking ---
    // On PreToolUse: record the wall-clock invoke time.
    // On PostToolUse: compute elapsed time and inject it so the mapper
    // produces a real duration_ms instead of always emitting 0.
    if (payload.hook_event_name === "PreToolUse") {
      await saveInvokeTime(payload.tool_use_id);
    } else if (
      payload.hook_event_name === "PostToolUse" ||
      payload.hook_event_name === "PostToolUseFailure"
    ) {
      if (!payload.duration_ms) {
        const computed = await consumeInvokeTime(payload.tool_use_id);
        if (computed !== null) {
          payload.duration_ms = computed;
        }
      }
    }
    // ----------------------------

    const events = mapClaudeCodePayload(payload, { newEventId });
    if (events.length === 0) {
      if (debug)
        console.error(
          `[omnodex-hook] mapper produced zero events for ${payload.hook_event_name}`,
        );
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
        `[omnodex-hook] wrote ${events.length} event(s) for ${payload.hook_event_name}`,
      );
    }
    return 0;
  } catch (err) {
    console.error(
      `[omnodex-hook] failed to write event: ${(err as Error).message}`,
    );
    // Never block Claude.
    return 0;
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

main()
  .then((code) => {
    process.exit(code);
  })
  .catch((err) => {
    console.error(`[omnodex-hook] unhandled: ${err}`);
  });
