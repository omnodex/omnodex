#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * cursor-hook-shim
 *
 * The process Cursor spawns for every hook event Omnodex subscribes to.
 * Reads the payload JSON from stdin, maps it to TraceEvents, appends them to
 * the Omnodex event log and, for the events that can stop a call, answers
 * with the guardrails decision.
 *
 * Contract (shared/shim-contract): the shim always exits 0 and always prints
 * one valid JSON document. Cursor blocks on a permission hook that prints
 * invalid JSON, so an Omnodex bug must never reach it; on any internal error
 * the answer is `{}`, which means no decision.
 *
 * The permission hooks (shell, MCP, file read) only judge: the call itself is
 * recorded from preToolUse, which fires for every tool, so nothing is
 * recorded twice and no event is written from a permission hook.
 *
 * The signed-in user's email, which Cursor puts in every payload, is never
 * read.
 *
 * Environment:
 *
 *   OMNODEX_HOME   location of the event log (defaults to ~/.omnodex)
 *   OMNODEX_DEBUG  set to "1" for verbose stderr logging
 *   OMNODEX_CAPTURE_DETECT  set to "0" to skip judging tool calls here
 */

import * as os from "node:os";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import { applyCapturePause, EventLog, isPauseMarker, newEventId, sessionModelChangedIfChanged, withProjectRemote } from "@omnodex/event-log";
import { CaptureTimeoutError, captureDetectEnabled, judgeCaptured, maskCaptured } from "@omnodex/analyzer/capture";
import { enforceCapturedCall, stampCaptured } from "@omnodex/analyzer/stamp";
import { runShim } from "@omnodex/shared/shim-contract";
import type { TraceEvent } from "@omnodex/shared";
import { hasPermissionHook, mapCursorPayload, normalizeCursorPayload, PERMISSION_EVENTS } from "../cursor-payload.js";
import { cursorDecision, type CursorDecisionEvent } from "../decision.js";
import {
  AUTO_SYNC_CHILD_ENV,
  backgroundPassDue,
  includesSessionEnd,
  deferLivePush,
  pushEventsToCloud,
  runAutoSync,
  startBackgroundSync,
} from "@omnodex/sync-encryptor";

const debug = process.env.OMNODEX_DEBUG === "1";
const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
const note = (msg: string): void => {
  if (debug) console.error(`[omnodex-cursor] ${msg}`);
};

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

/** Handle one hook call. Resolves to the decision to print, or nothing. */
async function handle(): Promise<Record<string, unknown> | undefined> {
  const raw = await readStdin();
  if (!raw.trim()) {
    note("empty stdin, nothing to do");
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.error(`[omnodex-cursor] could not parse stdin as JSON: ${(err as Error).message}`);
    return undefined;
  }
  const payload = normalizeCursorPayload(parsed);
  if (!payload) {
    note("payload is not a recorded Cursor hook event, discarding");
    return undefined;
  }

  const permissionOnly = PERMISSION_EVENTS.has(payload.event);
  const events = await withProjectRemote(mapCursorPayload(payload, { newEventId, callId: newEventId() }));
  if (events.length === 0) {
    note(`mapper produced zero events for ${payload.event}`);
    return undefined;
  }

  const failures: { value?: "timeout" | "error" } = {};
  const judge = (): Promise<ReturnType<typeof judgeCaptured> extends Promise<infer R> ? R : never> =>
    captureDetectEnabled()
      ? judgeCaptured(events.filter((e) => !isPauseMarker(e)), {
          newEventId,
          onError: (err) => {
            failures.value = err instanceof CaptureTimeoutError ? "timeout" : "error";
            note(`rule evaluation skipped: ${(err as Error).message}`);
          },
        })
      : Promise.resolve([]);
  const onEnforcementError = (err: unknown) => note(`enforcement skipped: ${(err as Error).message}`);

  if (permissionOnly) {
    // Judge only: nothing is written, and the answer is the permission shape.
    const findings = await judge();
    const result = await enforceCapturedCall(findings, events, {
      host: "cursor", home, newEventId, failure: failures.value, onError: onEnforcementError,
    });
    return cursorDecision(payload.event as CursorDecisionEvent, result.output);
  }

  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();

  // Cursor names the model in every payload; a change is recorded at the
  // start of a session and of a turn.
  const all: TraceEvent[] = [...events];
  if (payload.event === "sessionStart" || payload.event === "beforeSubmitPrompt") {
    const changed = await sessionModelChangedIfChanged(payload.model, {
      home, sessionId: payload.sessionId, interceptor: "cursor-hook", source: "hook", newEventId,
      announced: events.some((e) => e.event_type === "session.started" && (e as { model?: string }).model !== undefined),
    });
    if (changed) all.push({ ...changed, platform: "cursor" } as TraceEvent);
  }

  // A capture pause drops the events (record) or keeps them on this machine
  // only (sync); pause markers are always written. Masked as written: the
  // rules below still judge the call as captured.
  const written = await maskCaptured(await applyCapturePause(all, home), home);
  for (const event of written) await log.append(event);

  const findings = await judge();
  let deferPush = false;
  let stamped = findings;
  let extra: TraceEvent[] = [];
  let decision: Record<string, unknown> | undefined;
  if (payload.event === "preToolUse") {
    const result = await enforceCapturedCall(findings, events, {
      host: "cursor", home, newEventId, failure: failures.value, onError: onEnforcementError,
    });
    decision = cursorDecision("preToolUse", result.output, { hasPermissionHook: hasPermissionHook(payload.toolName) });
    ({ findings: stamped, extra } = result);
    deferPush = result.mode === "guardrails";
  } else {
    stamped = await stampCaptured(findings, events, { home, onError: onEnforcementError });
  }
  const keptFindings = await applyCapturePause([...stamped, ...extra], home);
  for (const finding of keptFindings) await log.append(finding);
  await log.close();
  note(`wrote ${written.length} event(s) for ${payload.event}`);

  // The agent waits on a guardrails preToolUse, so its events go out with the
  // next push instead of making it wait on the network now.
  if (deferPush) await deferLivePush([...written, ...keptFindings], home);
  else await pushEventsToCloud([...written, ...keptFindings], home, 2000);

  // Refresh the hosted dashboard's sync blob in a detached child, so a short
  // sessionEnd timeout does not cut it off.
  if (includesSessionEnd(events) || (await backgroundPassDue(home))) {
    note(`background pass: ${await startBackgroundSync({ home, scriptPath: process.argv[1] ?? "", detect: true })}`);
  }
  return decision;
}

async function main(): Promise<void> {
  // Detached background sync started by a sessionEnd hook, not a hook call.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    await runAutoSync(home, {
      // The analyzer loads here only, never on the per-event hook path.
      detect: async () => (await import("@omnodex/analyzer")).runBackgroundDetect(home),
    });
    return;
  }
  // Cursor waits on a permission hook; past this the answer is "no decision"
  // rather than a hung hook (its own timeout is 30 seconds by default).
  const limit = Number(process.env.OMNODEX_SHIM_TIMEOUT_MS);
  await runShim({
    run: handle,
    timeoutMs: Number.isFinite(limit) && limit > 0 ? limit : 20_000,
    onError: (err) => console.error(`[omnodex-cursor] failed: ${(err as Error)?.message ?? String(err)}`),
  });
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[omnodex-cursor] unhandled: ${err}`);
    // Even here the agent gets valid JSON and exit 0.
    try {
      process.stdout.write("{}");
    } catch {
      // nothing left to do
    }
    process.exit(0);
  });
