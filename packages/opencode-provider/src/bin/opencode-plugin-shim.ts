#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * opencode-plugin-shim
 *
 * The process the Omnodex OpenCode plugin starts (through the launcher) for
 * every event it sends. Reads the envelope JSON from stdin, maps it to
 * TraceEvents, appends them to the Omnodex event log and, for a tool call
 * about to run in guardrails mode, answers with the decision.
 *
 * Contract (shared/shim-contract): the shim always exits 0 and always prints
 * one valid JSON document; on any internal error the answer is `{}`, which
 * means no decision. The plugin treats anything but a deny as "run the call".
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
import { mapOpenCodePayload, normalizeOpenCodePayload } from "../opencode-payload.js";
import { opencodeDecision } from "../decision.js";
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
  if (debug) console.error(`[omnodex-opencode] ${msg}`);
};

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

/** Handle one envelope. Resolves to the decision to print, or nothing. */
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
    console.error(`[omnodex-opencode] could not parse stdin as JSON: ${(err as Error).message}`);
    return undefined;
  }
  const payload = normalizeOpenCodePayload(parsed);
  if (!payload) {
    note("payload is not a recorded OpenCode event, discarding");
    return undefined;
  }

  const events = await withProjectRemote(mapOpenCodePayload(payload, { newEventId, callId: newEventId() }));
  if (events.length === 0) {
    note(`mapper produced zero events for ${payload.event}`);
    return undefined;
  }

  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();

  // OpenCode names the model with each prompt; a change is recorded.
  const all: TraceEvent[] = [...events];
  if (payload.event === "prompt") {
    const changed = await sessionModelChangedIfChanged(payload.model, {
      home, sessionId: payload.sessionId, interceptor: "opencode-plugin", source: "hook", newEventId,
    });
    if (changed) all.push({ ...changed, platform: "opencode" } as TraceEvent);
  }

  // A capture pause drops the events (record) or keeps them on this machine
  // only (sync); pause markers are always written. Masked as written: the
  // rules below still judge the call as captured.
  const written = await maskCaptured(await applyCapturePause(all, home), home);
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
  if (payload.event === "tool.before") {
    const result = await enforceCapturedCall(findings, events, {
      host: "opencode", home, newEventId, failure, onError: onEnforcementError,
    });
    decision = opencodeDecision(result.output);
    ({ findings: stamped, extra } = result);
    deferPush = result.mode === "guardrails";
  } else {
    stamped = await stampCaptured(findings, events, { home, onError: onEnforcementError });
  }
  const keptFindings = await applyCapturePause([...stamped, ...extra], home);
  for (const finding of keptFindings) await log.append(finding);
  await log.close();
  note(`wrote ${written.length} event(s) for ${payload.event}`);

  // The agent waits on a guardrails tool.before, so its events go out with
  // the next push instead of making it wait on the network now.
  if (deferPush) await deferLivePush([...written, ...keptFindings], home);
  else await pushEventsToCloud([...written, ...keptFindings], home, 2000);

  // Refresh the hosted dashboard's sync blob in a detached child.
  if (includesSessionEnd(events) || (await backgroundPassDue(home))) {
    note(`background pass: ${await startBackgroundSync({ home, scriptPath: process.argv[1] ?? "", detect: true })}`);
  }
  return decision;
}

async function main(): Promise<void> {
  // Detached background sync started after a session ended, not an event.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    await runAutoSync(home, {
      // The analyzer loads here only, never on the per-event path.
      detect: async () => (await import("@omnodex/analyzer")).runBackgroundDetect(home),
    });
    return;
  }
  // The plugin waits on a tool.before; past this the answer is "no decision"
  // rather than a hung tool call (the plugin has its own, longer cap).
  const limit = Number(process.env.OMNODEX_SHIM_TIMEOUT_MS);
  await runShim({
    run: handle,
    timeoutMs: Number.isFinite(limit) && limit > 0 ? limit : 15_000,
    onError: (err) => console.error(`[omnodex-opencode] failed: ${(err as Error)?.message ?? String(err)}`),
  });
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[omnodex-opencode] unhandled: ${err}`);
    // Even here the plugin gets valid JSON and exit 0.
    try {
      process.stdout.write("{}");
    } catch {
      // nothing left to do
    }
    process.exit(0);
  });
