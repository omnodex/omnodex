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
 *   - argv[2]:  event name ("PreInvocation" | "PostInvocation" | "PreToolUse" | "PostToolUse" | "Stop")
 *   - stdin:    JSON payload (one object per invocation)
 *   - stdout:   JSON response (PreToolUse: the guardrails decision, or allow,
 *               which defers to Antigravity's own policy; Stop: allow; others: {})
 *   - stderr:   diagnostics only
 *   - exit 0:   success; Antigravity continues normally.
 *   - Installed hooks subscribe to PreToolUse only in guardrails mode, and
 *     never approve a call.
 *
 * Environment:
 *
 *   OMNODEX_HOME   location of the event log (defaults to ~/.omnodex)
 *   OMNODEX_DEBUG  set to "1" for verbose stderr logging
 *   OMNODEX_CAPTURE_DETECT  set to "0" to skip judging tool calls here
 *                           (the background pass still judges them)
 *
 * Antigravity payload differences from Codex:
 *   - Uses camelCase fields (conversationId, toolCall.name, etc.)
 *   - PostToolUse includes toolCall, stepIdx and error, but no response
 *   - No hook_event_name field; event name passed via CLI argument
 *   - No session_id; uses conversationId
 *   - No tool_use_id; uses stepIdx for Pre/Post correlation
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { applyCapturePause, EventLog, isPauseMarker, newEventId, sessionModelChangedIfChanged, withProjectRemote } from "@omnodex/event-log";
import { CaptureTimeoutError, captureDetectEnabled, judgeCaptured } from "@omnodex/analyzer/capture";
import { enforceCapturedCall, stampCaptured } from "@omnodex/analyzer/stamp";
import type { TraceEvent } from "@omnodex/shared";
import type {
  AntigravityCommonFields,
  AntigravityHookEventName,
  AntigravityHookPayload,
  AntigravityPreToolUsePayload,
  AntigravityStopPayload,
  PostToolUseCorrelation,
} from "../antigravity-payload.js";
import { antigravityToolCallId, mapAntigravityPayload } from "../antigravity-payload.js";
import {
  AUTO_SYNC_CHILD_ENV,
  backgroundPassDue,
  includesSessionEnd,
  deferLivePush,
  pushEventsToCloud,
  runAutoSync,
  startBackgroundSync,
} from "@omnodex/sync-encryptor";

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

  // Detached background sync started by a session-ending hook, not a hook
  // call. It has no event name and must not write a hook response.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    await runAutoSync(home, {
      // The analyzer loads here only, never on the per-event hook path.
      detect: async () => (await import("@omnodex/analyzer")).runBackgroundDetect(home),
    });
    return 0;
  }

  const stateDir = path.join(home, "antigravity-state");
  await fs.mkdir(stateDir, { recursive: true });

  // Event name from CLI argument (set by the interceptor per-event command).
  const eventName = process.argv[2] as AntigravityHookEventName | undefined;
  if (!eventName || !["PreInvocation", "PostInvocation", "PreToolUse", "PostToolUse", "Stop"].includes(eventName)) {
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

  let uncommittedSessionFile: string | undefined;
  let uncommittedStopFile: string | undefined;
  try {
    const conversationId =
      "conversationId" in payload
        ? String((payload as { conversationId: string }).conversationId)
        : "unknown";
    if (conversationId === "unknown" || !conversationId.trim() || eventName === "PostInvocation") {
      outputResponse(eventName);
      return 0;
    }
    const sessionKey = createHash("sha256").update(conversationId).digest("hex");
    const sessionFile = path.join(stateDir, `${sessionKey}-session.json`);
    let session: { startedAt: string } | undefined;
    try {
      session = JSON.parse(await fs.readFile(sessionFile, "utf8"));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    let firstActivity = false;
    if (!session && eventName !== "Stop") {
      session = { startedAt: new Date().toISOString() };
      try {
        await fs.writeFile(sessionFile, JSON.stringify(session), { flag: "wx" });
        uncommittedSessionFile = sessionFile;
        firstActivity = true;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        session = JSON.parse(await fs.readFile(sessionFile, "utf8"));
      }
    }
    let stopFile: string | undefined;
    if (eventName === "Stop") {
      const p = payload as AntigravityStopPayload;
      // A Stop is an execution-loop signal. Background work must finish first.
      if (!session || p.fullyIdle !== true || !Number.isInteger(p.executionNum)) {
        outputResponse(eventName);
        return 0;
      }
      stopFile = path.join(stateDir, `${sessionKey}-stop-${p.executionNum}.json`);
      try {
        await fs.writeFile(stopFile, "{}", { flag: "wx" });
        uncommittedStopFile = stopFile;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        outputResponse(eventName);
        return 0;
      }
    }
    let correlation: PostToolUseCorrelation | undefined;

    if (eventName === "PreToolUse") {
      const p = payload as AntigravityPreToolUsePayload;
      const toolCallId = antigravityToolCallId(conversationId, p.stepIdx);
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

    const options = { newEventId, emitSessionStart: firstActivity, sessionStartedAt: session?.startedAt };
    let events = mapAntigravityPayload(eventName, payload, options, correlation);
    if (firstActivity && eventName !== "PreInvocation") {
      events.unshift(...mapAntigravityPayload("PreInvocation", payload, options));
    }
    events = await withProjectRemote(events);
    // Every payload names the model; check it once per turn (and when the
    // session starts) and record a change.
    if (eventName === "PreInvocation" || firstActivity) {
      const changed = await sessionModelChangedIfChanged((payload as AntigravityCommonFields).modelName, {
        home,
        sessionId: conversationId,
        interceptor: "antigravity-hook",
        source: "hook",
        newEventId,
        announced: events.some((e) => e.event_type === "session.started" && e.model !== undefined),
      });
      if (changed) events.push({ ...changed, platform: "antigravity" });
    }
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
    // A capture pause drops the events (record) or keeps them on this
    // machine only (sync); pause markers are always written.
    const written = await applyCapturePause(events, home);
    for (const event of written) {
      await log.append(event);
    }
    // Judge the call against the per-event rules here, so its findings are
    // written and pushed with it. Capped in time; on a timeout or error
    // the background pass judges it instead.
    let failure: "timeout" | "error" | undefined;
    // Judged even while recording is paused, so a pause never switches
    // guardrails off; what a pause keeps out of the log is dropped below.
    const findings = captureDetectEnabled()
      ? await judgeCaptured(events.filter((e) => !isPauseMarker(e)), {
          newEventId,
          onError: (err) => {
            failure = err instanceof CaptureTimeoutError ? "timeout" : "error";
            if (debug) console.error(`[omnodex-antigravity] rule evaluation skipped: ${(err as Error).message}`);
          },
        })
      : [];
    const onEnforcementError = (err: unknown) => {
      if (debug) console.error(`[omnodex-antigravity] enforcement skipped: ${(err as Error).message}`);
    };
    // PreToolUse can still act on the call: in guardrails mode, decide it.
    // Elsewhere, record on each finding what enforcement would have done.
    let deferPush = false;
    let stamped = findings;
    let extra: TraceEvent[] = [];
    if (eventName === "PreToolUse") {
      const result = await enforceCapturedCall(findings, events, {
        host: "antigravity", home, newEventId, failure, onError: onEnforcementError,
      });
      // Written by outputResponse when the hook ends.
      preToolUseDecision = result.output;
      ({ findings: stamped, extra } = result);
      deferPush = result.mode === "guardrails";
    } else {
      stamped = await stampCaptured(findings, events, { home, onError: onEnforcementError });
    }
    const keptFindings = await applyCapturePause([...stamped, ...extra], home);
    for (const finding of keptFindings) {
      await log.append(finding);
    }
    await log.close();
    uncommittedSessionFile = undefined;
    uncommittedStopFile = undefined;

    if (debug) {
      console.error(
        `[omnodex-antigravity] wrote ${events.length} event(s) for ${eventName}`,
      );
    }

    // Push to cloud in real time (never throws; ~50-100ms on cache hit).
    // The agent waits on a guardrails PreToolUse, so its events go out with
    // the next push instead of making it wait on the network now.
    if (deferPush) await deferLivePush([...written, ...keptFindings], home);
    else await pushEventsToCloud([...written, ...keptFindings], home);

    // Refresh the hosted dashboard's sync blob in the background.
    // The same detached child runs detection first, so it also starts
    // mid-session once the last pass is older than the timer period.
    if (includesSessionEnd(events) || (await backgroundPassDue(home))) {
      const decision = await startBackgroundSync({
        home,
        scriptPath: process.argv[1] ?? "",
        detect: true,
      });
      if (debug) console.error(`[omnodex-antigravity] background pass: ${decision}`);
    }

    outputResponse(eventName);
    return 0;
  } catch (err) {
    // A failed append must not suppress a later successful retry.
    await Promise.allSettled(
      [uncommittedSessionFile, uncommittedStopFile]
        .filter((file): file is string => file !== undefined)
        .map((file) => fs.unlink(file)),
    );
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

/** The guardrails decision for this PreToolUse call, once made. */
let preToolUseDecision: Record<string, unknown> | null = null;

function outputResponse(eventName?: string): void {
  if (eventName === "PreToolUse") {
    // A guardrails decision, or "allow", which defers to the next hook and
    // to Antigravity's own permission policy: it never approves anything.
    // Installs subscribe to PreToolUse only in guardrails mode.
    process.stdout.write(JSON.stringify(preToolUseDecision ?? { decision: "allow" }));
  } else if (eventName === "Stop") {
    // A decision is required. Anything other than continue permits stopping.
    process.stdout.write(JSON.stringify({ decision: "allow" }));
  } else {
    // Tool completion and model invocation hooks require no intervention.
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
    outputResponse(process.argv[2]);
    process.exit(0);
  });
