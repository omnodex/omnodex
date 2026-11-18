// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * One adapter per agent: turns that agent's hook payload into TraceEvents the
 * same way its own hook shim does, minus everything that needs a local
 * install (event log, rules, guardrails, background sync). Sealed capture
 * only records; it never decides.
 *
 * Pairing a call's start with its end keeps one small file per open call
 * under the spool directory, as the shims do under their own.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { maskCaptured } from "@omnodex/analyzer/capture";
import { newEventId } from "@omnodex/event-log";
import type { TraceEvent } from "@omnodex/shared";
import { claudeCodeAdapter, ingestDir, type PayloadAdapter } from "@omnodex/hooks-provider";
import { callKeyFile, closeCall, mapCopilotPayload, normalizeCopilotPayload, openCall } from "@omnodex/copilot-provider";
import { PERMISSION_EVENTS, mapCursorPayload, normalizeCursorPayload } from "@omnodex/cursor-provider";
import { mapCodexPayload, type CodexHookPayload } from "@omnodex/codex-provider";
import {
  antigravityToolCallId,
  mapAntigravityPayload,
  type AntigravityHookEventName,
  type AntigravityHookPayload,
  type PostToolUseCorrelation,
} from "@omnodex/antigravity-provider";
import type { PlatformKind } from "@omnodex/shared";
import type { SealedProvider } from "./config.js";

/** Hook names, in any agent's spelling, that end a turn or a session. */
const FLUSH_NAMES = new Set(["stop", "sessionend", "agentstop"]);

function flushes(payload: unknown): boolean {
  const name = (payload as { hook_event_name?: unknown } | null)?.hook_event_name;
  return typeof name === "string" && FLUSH_NAMES.has(name.toLowerCase());
}

/** Ties tool calls and sessions together across the short-lived hook processes. */
function stateDir(home: string, name: string): string {
  return path.join(ingestDir(home), name);
}

function safeName(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 32);
}

function claim(file: string): boolean {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "{}", { flag: "wx" });
    return true;
  } catch {
    return false;
  }
}

async function masked(events: TraceEvent[], home: string): Promise<TraceEvent[]> {
  return maskCaptured(events, home);
}

// ---------------------------------------------------------------------------

const copilotAdapter: PayloadAdapter = async (payload, home) => {
  const normalized = normalizeCopilotPayload(payload);
  if (!normalized) return flushes(payload) ? { events: [], flush: true } : null;
  let callId = normalized.callId;
  let durationMs: number | undefined;
  if (normalized.toolName) {
    const keyFile = callKeyFile(stateDir(home, "timing-copilot"), normalized.sessionId, normalized.toolName, normalized.toolInput);
    if (normalized.event === "PreToolUse") {
      callId = await openCall(keyFile, callId ?? newEventId());
    } else if (normalized.event === "PostToolUse" || normalized.event === "PostToolUseFailure") {
      const closed = await closeCall(keyFile);
      if (closed) {
        callId = callId ?? closed.id;
        durationMs = closed.durationMs;
      }
      callId = callId ?? newEventId();
    }
  }
  const events = mapCopilotPayload(normalized, { newEventId, callId, durationMs });
  return { events: await masked(events, home), flush: normalized.event === "Stop" || normalized.event === "SessionEnd" };
};

const cursorAdapter: PayloadAdapter = async (payload, home) => {
  const normalized = normalizeCursorPayload(payload);
  if (!normalized) return flushes(payload) ? { events: [], flush: true } : null;
  // The permission hooks only judge a call Cursor is about to ask about; the
  // call itself is recorded by the tool hooks.
  if (PERMISSION_EVENTS.has(normalized.event)) return null;
  const events = mapCursorPayload(normalized, { newEventId, callId: newEventId() });
  return { events: await masked(events, home), flush: normalized.event === "sessionEnd" };
};

const codexAdapter: PayloadAdapter = async (payload, home, now) => {
  const p = payload as CodexHookPayload | null;
  if (!p || typeof p !== "object" || typeof p.hook_event_name !== "string" || typeof p.session_id !== "string") return null;
  if ("tool_use_id" in p && typeof p.tool_use_id === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(p.tool_use_id)) {
    const file = path.join(stateDir(home, "timing-codex"), `${p.tool_use_id}.ts`);
    try {
      if (p.hook_event_name === "PreToolUse") {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, String(now));
      } else if (p.hook_event_name === "PostToolUse") {
        const started = Number(fs.readFileSync(file, "utf8"));
        fs.unlinkSync(file);
        if (!p.duration_ms && Number.isFinite(started)) p.duration_ms = Math.max(0, now - started);
      }
    } catch {
      // No matching PreToolUse: the duration stays unknown.
    }
  }
  const events = mapCodexPayload(p, { newEventId });
  return { events: await masked(events, home), flush: flushes(p) };
};

function antigravityAdapterFor(eventName: AntigravityHookEventName): PayloadAdapter {
  return async (payload, home, now) => {
    if (!payload || typeof payload !== "object") return null;
    const p = payload as AntigravityHookPayload;
    const conversationId = String((p as { conversationId?: unknown }).conversationId ?? "").trim();
    if (!conversationId || eventName === "PostInvocation") return null;
    const key = safeName(conversationId);
    const dir = stateDir(home, "antigravity");

    if (eventName === "Stop") {
      const stop = p as { fullyIdle?: unknown; executionNum?: unknown };
      if (stop.fullyIdle !== true || !Number.isInteger(stop.executionNum)) return null;
      if (!claim(path.join(dir, `${key}-stop-${String(stop.executionNum)}`))) return null;
    }

    const startedAt = new Date(now).toISOString();
    const firstActivity = eventName !== "Stop" && claim(path.join(dir, `${key}-session`));
    const options = { newEventId, emitSessionStart: firstActivity, sessionStartedAt: startedAt };

    let correlation: PostToolUseCorrelation | undefined;
    const stepIdx = (p as { stepIdx?: unknown }).stepIdx;
    if (typeof stepIdx === "number" && Number.isInteger(stepIdx)) {
      const file = path.join(dir, `${key}-step-${stepIdx}.json`);
      if (eventName === "PreToolUse") {
        const toolName = (p as { toolCall?: { name?: string } }).toolCall?.name ?? "unknown";
        try {
          fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(file, JSON.stringify({ toolName, toolCallId: antigravityToolCallId(conversationId, stepIdx), invokedAt: now }));
        } catch {
          // Without the saved start, the end reports no duration.
        }
      } else if (eventName === "PostToolUse") {
        try {
          const saved = JSON.parse(fs.readFileSync(file, "utf8")) as { toolName: string; toolCallId: string; invokedAt: number };
          fs.unlinkSync(file);
          correlation = { toolName: saved.toolName, toolCallId: saved.toolCallId, durationMs: Math.max(0, now - saved.invokedAt) };
        } catch {
          correlation = { toolName: null, toolCallId: null, durationMs: 0 };
        }
      }
    }

    let events = mapAntigravityPayload(eventName, p, options, correlation);
    if (firstActivity && eventName !== "PreInvocation") {
      events = [...mapAntigravityPayload("PreInvocation", p, options), ...events];
    }
    return { events: await masked(events, home), flush: eventName === "Stop" };
  };
}

// ---------------------------------------------------------------------------

export interface ProviderSetup {
  adapter: PayloadAdapter;
  /** Platform label for every event; null keeps the mapper's own. */
  platform: PlatformKind | null;
  /** What the agent expects on stdout when there is nothing to decide. */
  stdout: (eventName?: string) => string;
}

const EMPTY_OBJECT = (): string => "{}";
const NOTHING = (): string => "";

/**
 * The adapter, platform label and neutral answer for one agent. `eventName`
 * is the event argument Antigravity's hooks pass on the command line.
 */
export function providerSetup(provider: SealedProvider, eventName?: string): ProviderSetup | null {
  switch (provider) {
    case "claude-code":
      return { adapter: claudeCodeAdapter, platform: "claude-code", stdout: NOTHING };
    case "codex":
      return { adapter: codexAdapter, platform: "codex", stdout: NOTHING };
    case "copilot":
      return { adapter: copilotAdapter, platform: null, stdout: EMPTY_OBJECT };
    case "cursor":
      return { adapter: cursorAdapter, platform: null, stdout: EMPTY_OBJECT };
    case "antigravity": {
      const names: readonly string[] = ["PreInvocation", "PostInvocation", "PreToolUse", "PostToolUse", "Stop"];
      if (!eventName || !names.includes(eventName)) return null;
      return {
        adapter: antigravityAdapterFor(eventName as AntigravityHookEventName),
        platform: null,
        // Antigravity needs an answer: "allow" defers to its own permission policy.
        stdout: () => (eventName === "PreToolUse" || eventName === "Stop" ? '{"decision":"allow"}' : "{}"),
      };
    }
  }
}
