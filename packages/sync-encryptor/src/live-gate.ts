// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- live push gate
 *
 * Live pushes only matter while a hosted dashboard is watching the stream.
 * Everything they carry also reaches the cloud through blob sync, which a
 * dashboard loads when it opens. So when the relay answers a push with
 * `live: false` (no one watching), clients stop pushing for a back-off
 * window, then send one batch as a probe. The window doubles while no one
 * watches, from LIVE_BACKOFF_MIN_MS up to LIVE_BACKOFF_MAX_MS, and resets
 * as soon as a push reports a viewer. A failed push (network error, non-2xx)
 * backs off the same way, so an offline machine or a revoked token does not
 * cost a request per event either.
 *
 * Cost this bounds: every live push is a Worker request and, unless the
 * gateway already knows the room is empty, a Durable Object request, both
 * counted against account-wide daily limits. With the gate, an unwatched
 * machine sends about one push per LIVE_BACKOFF_MAX_MS however many events
 * it records. The price is latency: a dashboard opened mid-session starts
 * receiving live events at the next probe, at most LIVE_BACKOFF_MAX_MS later.
 *
 * Hook shims are one process per event, so the state lives in a small file
 * under OMNODEX_HOME that every pusher on the machine shares
 * (live-push-state.json). It is written only when the state changes: when a
 * pause starts, and when a viewer ends it. Concurrent processes can race on
 * it; the worst outcome is one extra probe.
 *
 * Servers that predate the `live` field never send `live: false`, so
 * clients keep pushing every event, as before.
 */

import { readFile, writeFile, unlink, mkdir } from "node:fs/promises";
import { join } from "node:path";

export const LIVE_BACKOFF_MIN_MS = 60_000;
export const LIVE_BACKOFF_MAX_MS = 300_000;

const STATE_FILE = "live-push-state.json";

/** How a live push went, as far as the gate cares. */
export type LivePushOutcome = "watched" | "unwatched" | "failed";

export interface LiveGateState {
  /** Unix ms; no live pushes before this. */
  paused_until: number;
  /** The window that produced paused_until; the next one doubles it. */
  backoff_ms: number;
}

/** Whether a push may go out now. */
export function liveGateOpen(state: LiveGateState | null, now: number): boolean {
  return !state || now >= state.paused_until;
}

/**
 * The gate after a push with the given outcome. null means open with no
 * back-off history.
 */
export function nextLiveGate(
  state: LiveGateState | null,
  outcome: LivePushOutcome,
  now: number,
): LiveGateState | null {
  if (outcome === "watched") return null;
  const backoff = state
    ? Math.min(state.backoff_ms * 2, LIVE_BACKOFF_MAX_MS)
    : LIVE_BACKOFF_MIN_MS;
  return { paused_until: now + backoff, backoff_ms: backoff };
}

/**
 * Reads a push response into an outcome. `live: false` is the relay saying
 * no dashboard is connected; anything else that succeeded counts as watched.
 */
export async function livePushOutcome(res: Response): Promise<LivePushOutcome> {
  if (!res.ok) {
    await res.text().catch(() => "");
    return "failed";
  }
  const body = (await res.json().catch(() => null)) as { live?: unknown } | null;
  return body?.live === false ? "unwatched" : "watched";
}

/** A gate held in memory, for a long-lived process that pushes on its own. */
export class LiveGate {
  private state: LiveGateState | null = null;

  open(now = Date.now()): boolean {
    return liveGateOpen(this.state, now);
  }

  record(outcome: LivePushOutcome, now = Date.now()): void {
    this.state = nextLiveGate(this.state, outcome, now);
  }
}

// ---------------------------------------------------------------------------
// Shared, file-backed gate (hook shims, proxy, background sync)
// ---------------------------------------------------------------------------

export async function readLiveGate(home: string): Promise<LiveGateState | null> {
  try {
    const parsed = JSON.parse(await readFile(join(home, STATE_FILE), "utf-8")) as LiveGateState;
    if (typeof parsed.paused_until !== "number" || typeof parsed.backoff_ms !== "number") return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Whether a push may go out now, per the machine's shared gate. */
export async function livePushAllowed(home: string, now = Date.now()): Promise<boolean> {
  return liveGateOpen(await readLiveGate(home), now);
}

/** Records a push outcome in the shared gate. Never throws. */
export async function recordLivePush(
  home: string,
  outcome: LivePushOutcome,
  now = Date.now(),
): Promise<void> {
  try {
    const prev = await readLiveGate(home);
    const next = nextLiveGate(prev, outcome, now);
    if (!next) {
      if (prev) await unlink(join(home, STATE_FILE));
      return;
    }
    await mkdir(home, { recursive: true });
    await writeFile(join(home, STATE_FILE), JSON.stringify(next) + "\n");
  } catch {
    // Best effort: a lost update costs at most an extra probe.
  }
}
