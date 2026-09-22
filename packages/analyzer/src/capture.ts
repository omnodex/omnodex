// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Capture-time evaluation: judging events in the process that captured them.
 *
 * A hook shim is a fresh process per hook event. It runs the event-class
 * rules on the tool.invoked events it has just written, under a hard time
 * cap, and never fails the hook: on a timeout or an error it returns no
 * findings and the background pass judges the event later. Its
 * deduplication is seeded from the log, so nothing is written twice.
 *
 * This module is imported statically by the shims, so it loads nothing
 * itself. The evaluator is imported only when a batch holds a tool.invoked
 * and capture evaluation is on, so session and completion hooks pay
 * nothing, and the time cap covers the import as well as the evaluation.
 *
 * CAPTURE_HOSTS records which capture paths evaluate what, so a host that
 * sees their events later (the local dashboard's live loop) runs only the
 * rule classes they did not.
 *
 * Environment:
 *
 *   OMNODEX_CAPTURE_DETECT=0                 turns capture evaluation off
 *   OMNODEX_CAPTURE_DETECT_TIMEOUT_MS=<ms>   the time cap (default 1000)
 */

import type { RiskDetectedEvent, TraceEvent } from "@omnodex/shared";
import type { EvaluatorHost, EvaluatorOptions, Evaluator } from "./evaluator.js";

export const CAPTURE_DETECT_ENV = "OMNODEX_CAPTURE_DETECT";
export const CAPTURE_TIMEOUT_ENV = "OMNODEX_CAPTURE_DETECT_TIMEOUT_MS";

/**
 * Comfortably above the measured cost of loading and running the evaluator
 * on the slowest layout we support (an unbundled checkout on a Windows
 * drive under WSL, about 300 ms), and short enough that a stuck load never
 * holds a synchronous hook for long.
 */
export const DEFAULT_CAPTURE_TIMEOUT_MS = 1000;

/**
 * The evaluator host each capture path runs as, by interceptor. Findings
 * for these interceptors' events of the host's classes are written at
 * capture time.
 */
export const CAPTURE_HOSTS: Readonly<Record<string, EvaluatorHost>> = {
  "claude-code-hook": "hook",
  "codex-hook": "hook",
  "antigravity-hook": "hook",
  "mcp-proxy": "proxy",
};

/** Whether capture evaluation is on. */
export function captureDetectEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[CAPTURE_DETECT_ENV] !== "0";
}

/** The time cap from the environment, or the default. */
export function captureTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env[CAPTURE_TIMEOUT_ENV];
  const ms = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(ms) && ms > 0 ? ms : DEFAULT_CAPTURE_TIMEOUT_MS;
}

export interface JudgeCapturedOptions {
  newEventId: () => string;
  /** Defaults to captureTimeoutMs(). */
  timeoutMs?: number;
  /** Error and timeout reporting. Defaults to silence. */
  onError?: (err: unknown) => void;
  /** Loads the evaluator factory. Defaults to importing the evaluator module. */
  load?: () => Promise<{ createEvaluator: (opts: EvaluatorOptions) => Evaluator }>;
}

export class CaptureTimeoutError extends Error {
  constructor(ms: number) {
    super(`capture evaluation exceeded ${ms} ms`);
    this.name = "CaptureTimeoutError";
  }
}

/**
 * Judge the events a hook has just written with the event-class rules.
 * Resolves to the findings, or to none on a timeout or error. Never rejects.
 */
export async function judgeCaptured(
  events: readonly TraceEvent[],
  opts: JudgeCapturedOptions,
): Promise<RiskDetectedEvent[]> {
  if (!events.some((e) => e.event_type === "tool.invoked")) return [];
  const timeoutMs = opts.timeoutMs ?? captureTimeoutMs();
  const onError = opts.onError ?? (() => undefined);

  let timedOut = false;
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<RiskDetectedEvent[]>((resolve) => {
    timer = setTimeout(() => {
      timedOut = true;
      onError(new CaptureTimeoutError(timeoutMs));
      resolve([]);
    }, timeoutMs);
  });

  const work = (async (): Promise<RiskDetectedEvent[]> => {
    const { createEvaluator } = await (opts.load ?? (() => import("./evaluator.js")))();
    if (timedOut) return [];
    const evaluator = createEvaluator({ host: "hook", newEventId: opts.newEventId });
    const findings: RiskDetectedEvent[] = [];
    for (const event of events) findings.push(...evaluator.evaluate(event));
    return findings;
  })().catch((err: unknown) => {
    if (!timedOut) onError(err);
    return [];
  });

  try {
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
  }
}
