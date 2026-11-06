#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * copilot-hook-shim
 *
 * The process GitHub Copilot spawns for every hook event Omnodex subscribes
 * to. Reads the payload JSON from stdin, maps it to TraceEvents, appends them
 * to the Omnodex event log and, on PreToolUse in guardrails mode, answers
 * with the decision.
 *
 * Contract (shared/shim-contract): the shim always exits 0 and always prints
 * one valid JSON document. Copilot denies a tool call when a preToolUse hook
 * crashes or exits non-zero, so an Omnodex bug must never reach it; on any
 * internal error the answer is `{}`, which means no decision.
 *
 * Environment:
 *
 *   OMNODEX_HOME   location of the event log (defaults to ~/.omnodex)
 *   OMNODEX_DEBUG  set to "1" for verbose stderr logging
 *   OMNODEX_CAPTURE_DETECT  set to "0" to skip judging tool calls here
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import { applyCapturePause, EventLog, isPauseMarker, newEventId, withProjectRemote } from "@omnodex/event-log";
import { CaptureTimeoutError, captureDetectEnabled, judgeCaptured, maskCaptured } from "@omnodex/analyzer/capture";
import { enforceCapturedCall, stampCaptured } from "@omnodex/analyzer/stamp";
import { runShim } from "@omnodex/shared/shim-contract";
import type { TraceEvent } from "@omnodex/shared";
import { mapCopilotPayload, normalizeCopilotPayload } from "../copilot-payload.js";
import { copilotDecision } from "../decision.js";
import { callKeyFile, closeCall, openCall } from "../tool-ids.js";
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
  if (debug) console.error(`[omnodex-copilot] ${msg}`);
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
    console.error(`[omnodex-copilot] could not parse stdin as JSON: ${(err as Error).message}`);
    return undefined;
  }
  const payload = normalizeCopilotPayload(parsed);
  if (!payload) {
    note("payload is not a recorded Copilot hook event, discarding");
    return undefined;
  }

  // Copilot sends no id that pairs a postToolUse with its preToolUse, so the
  // pre-hook makes one and the post-hook takes it back.
  let callId = payload.callId;
  let durationMs: number | undefined;
  if (payload.toolName) {
    const keyFile = callKeyFile(path.join(home, "timing", "copilot"), payload.sessionId, payload.toolName, payload.toolInput);
    if (payload.event === "PreToolUse") {
      callId = await openCall(keyFile, callId ?? newEventId());
    } else if (payload.event === "PostToolUse" || payload.event === "PostToolUseFailure") {
      const closed = await closeCall(keyFile);
      if (closed) {
        callId = callId ?? closed.id;
        durationMs = closed.durationMs;
      }
      callId = callId ?? newEventId();
    }
  }

  const events = await withProjectRemote(mapCopilotPayload(payload, { newEventId, callId, durationMs }));
  if (events.length === 0) {
    note(`mapper produced zero events for ${payload.event}`);
    return undefined;
  }

  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  // A capture pause drops the events (record) or keeps them on this machine
  // only (sync); pause markers are always written. Masked as written: the
  // rules below still judge the call as captured.
  const written = await maskCaptured(await applyCapturePause(events, home), home);
  for (const event of written) await log.append(event);

  // Judge the call against the per-event rules here, so its findings are
  // written and pushed with it. Capped in time; on a timeout or error the
  // background pass judges it instead. Judged even while recording is
  // paused, so a pause never switches guardrails off.
  let failure: "timeout" | "error" | undefined;
  const findings = captureDetectEnabled()
    ? await judgeCaptured(events.filter((e) => !isPauseMarker(e)), {
        newEventId,
        onError: (err) => {
          failure = err instanceof CaptureTimeoutError ? "timeout" : "error";
          note(`rule evaluation skipped: ${(err as Error).message}`);
        },
      })
    : [];
  const onEnforcementError = (err: unknown) => note(`enforcement skipped: ${(err as Error).message}`);

  let deferPush = false;
  let stamped = findings;
  let extra: TraceEvent[] = [];
  let decision: Record<string, unknown> | undefined;
  if (payload.event === "PreToolUse") {
    // The module answers in the shape a PascalCase registration reads, the
    // same as for Claude Code.
    const result = await enforceCapturedCall(findings, events, {
      host: "claude-code", home, newEventId, failure, onError: onEnforcementError,
    });
    decision = copilotDecision(result.output);
    ({ findings: stamped, extra } = result);
    deferPush = result.mode === "guardrails";
  } else {
    stamped = await stampCaptured(findings, events, { home, onError: onEnforcementError });
  }
  const keptFindings = await applyCapturePause([...stamped, ...extra], home);
  for (const finding of keptFindings) await log.append(finding);
  await log.close();
  note(`wrote ${events.length} event(s) for ${payload.event}`);

  // The agent waits on a guardrails preToolUse, so its events go out with the
  // next push instead of making it wait on the network now.
  if (deferPush) await deferLivePush([...written, ...keptFindings], home);
  else await pushEventsToCloud([...written, ...keptFindings], home, 2000);

  // Refresh the hosted dashboard's sync blob in a detached child, so a short
  // SessionEnd timeout does not cut it off.
  if (includesSessionEnd(events) || (await backgroundPassDue(home))) {
    note(`background pass: ${await startBackgroundSync({ home, scriptPath: process.argv[1] ?? "", detect: true })}`);
  }
  return decision;
}

async function main(): Promise<void> {
  // Detached background sync started by a SessionEnd hook, not a hook call.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    await runAutoSync(home, {
      // The analyzer loads here only, never on the per-event hook path.
      detect: async () => (await import("@omnodex/analyzer")).runBackgroundDetect(home),
    });
    return;
  }
  await fs.mkdir(path.join(home, "timing", "copilot"), { recursive: true }).catch(() => undefined);
  // Copilot waits on a preToolUse hook; past this the answer is "no decision"
  // rather than a hung hook (its own timeout is 30 seconds by default).
  const limit = Number(process.env.OMNODEX_SHIM_TIMEOUT_MS);
  await runShim({
    run: handle,
    timeoutMs: Number.isFinite(limit) && limit > 0 ? limit : 20_000,
    onError: (err) => console.error(`[omnodex-copilot] failed: ${(err as Error)?.message ?? String(err)}`),
  });
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[omnodex-copilot] unhandled: ${err}`);
    // Even here the agent gets valid JSON and exit 0.
    try {
      process.stdout.write("{}");
    } catch {
      // nothing left to do
    }
    process.exit(0);
  });
