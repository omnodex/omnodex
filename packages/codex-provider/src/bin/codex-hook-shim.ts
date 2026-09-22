#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * codex-hook-shim
 *
 * The process Codex spawns for every hook event we subscribe to. Reads the
 * hook payload JSON from stdin, maps it into TraceEvents via mapCodexPayload,
 * and appends each event to the Omnodex event log.
 *
 * Contract (enforced by Codex):
 *
 *   - stdin:    JSON payload (one object per invocation)
 *   - stdout:   must stay empty for PreToolUse unless returning a decision.
 *               Codex may interpret JSON on stdout as a hook decision.
 *               Use stderr for diagnostics.
 *   - exit 0:   success; Codex continues normally.
 *   - exit 2:   signals Codex to block the current tool call (PreToolUse only).
 *               We never exit 2 — we observe, we do not block.
 *
 * Environment:
 *
 *   OMNODEX_HOME   location of the event log (defaults to ~/.omnodex)
 *   OMNODEX_DEBUG  set to "1" for verbose stderr logging
 *   OMNODEX_CAPTURE_DETECT  set to "0" to skip judging tool calls here
 *                           (the background pass still judges them)
 *
 * Codex supports asynchronous command hooks, but may run them out of order or
 * cancel them when a session ends. Omnodex keeps its hooks synchronous so
 * tool invocation/completion ordering and lifecycle capture remain reliable.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import { EventLog, newEventId } from "@omnodex/event-log";
import { captureDetectEnabled, judgeCaptured } from "@omnodex/analyzer/capture";
import type { CodexHookPayload } from "../codex-payload.js";
import { mapCodexPayload } from "../codex-payload.js";
import {
  AUTO_SYNC_CHILD_ENV,
  backgroundPassDue,
  includesSessionEnd,
  pushEventsToCloud,
  runAutoSync,
  startBackgroundSync,
} from "@omnodex/sync-encryptor";

async function main(): Promise<number> {
  const debug = process.env.OMNODEX_DEBUG === "1";
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  const eventLogRoot = path.join(home, "event-log");

  // Detached background sync started by a SessionEnd hook, not a hook call.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    await runAutoSync(home, {
      // The analyzer loads here only, never on the per-event hook path.
      detect: async () => (await import("@omnodex/analyzer")).runBackgroundDetect(home),
    });
    return 0;
  }

  const timingDir = path.join(home, "timing");
  await fs.mkdir(timingDir, { recursive: true });

  async function saveInvokeTime(toolUseId: string): Promise<void> {
    await fs.writeFile(
      path.join(timingDir, `${toolUseId}.ts`),
      String(Date.now()),
      "utf8",
    );
  }

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
    if (debug) console.error("[omnodex-codex] empty stdin, nothing to do");
    return 0;
  }

  let payload: CodexHookPayload;
  try {
    payload = JSON.parse(raw) as CodexHookPayload;
  } catch (err) {
    console.error(
      `[omnodex-codex] could not parse stdin as JSON: ${(err as Error).message}`,
    );
    return 0;
  }

  if (!payload || typeof payload !== "object" || !payload.hook_event_name) {
    if (debug)
      console.error("[omnodex-codex] payload missing hook_event_name, discarding");
    return 0;
  }

  try {
    // Wall-clock duration tracking: save on PreToolUse, compute on PostToolUse.
    // Codex does not send duration_ms, so we measure it ourselves.
    if (payload.hook_event_name === "PreToolUse") {
      await saveInvokeTime(payload.tool_use_id);
    } else if (payload.hook_event_name === "PostToolUse") {
      if (!payload.duration_ms) {
        const computed = await consumeInvokeTime(payload.tool_use_id);
        if (computed !== null) {
          payload.duration_ms = computed;
        }
      }
    }

    const events = mapCodexPayload(payload, { newEventId });
    if (events.length === 0) {
      if (debug)
        console.error(
          `[omnodex-codex] mapper produced zero events for ${payload.hook_event_name}`,
        );
      return 0;
    }

    const log = new EventLog({ root: eventLogRoot });
    await log.init();
    for (const event of events) {
      await log.append(event);
    }
    // Judge the call against the per-event rules here, so its findings are
    // written and pushed with it. Capped in time; on a timeout or error
    // the background pass judges it instead.
    const findings = captureDetectEnabled()
      ? await judgeCaptured(events, {
          newEventId,
          onError: (err) => {
            if (debug) console.error(`[omnodex-codex] rule evaluation skipped: ${(err as Error).message}`);
          },
        })
      : [];
    for (const finding of findings) {
      await log.append(finding);
    }
    await log.close();

    if (debug) {
      console.error(
        `[omnodex-codex] wrote ${events.length} event(s) for ${payload.hook_event_name}`,
      );
    }

    // Push to cloud in real time (never throws; ~50-100ms on cache hit).
    // Codex hooks are synchronous so keep the timeout short.
    await pushEventsToCloud([...events, ...findings], home, 2000);

    // Refresh the hosted dashboard's sync blob in the background. The sync
    // runs detached, so Codex's short SessionEnd timeout does not cut it off.
    // The same detached child runs detection first, so it also starts
    // mid-session once the last pass is older than the timer period.
    if (includesSessionEnd(events) || (await backgroundPassDue(home))) {
      const decision = await startBackgroundSync({
        home,
        scriptPath: process.argv[1] ?? "",
        detect: true,
      });
      if (debug) console.error(`[omnodex-codex] background pass: ${decision}`);
    }

    return 0;
  } catch (err) {
    console.error(
      `[omnodex-codex] failed to write event: ${(err as Error).message}`,
    );
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
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`[omnodex-codex] unhandled: ${err}`);
    process.exit(0);
  });
