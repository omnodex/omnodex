// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Evidence bundles: a file an auditor can check without Omnodex. See
 * docs/evidence.md for the format. One JSON object per line:
 *
 *   {"type":"manifest", ...}   first line
 *   {"type":"key", ...}        the public key of each signing key used
 *   {"type":"seal", ...}       each seal, as signed
 *   {"type":"event", ...}      the events of each seal, in the seal's order
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { TraceEvent } from "@omnodex/shared";
import { eventHash } from "./canonical.js";
import { loadOrCreateKey, readSeals, sealPending, type SealRecord } from "./seal.js";

export const BUNDLE_FORMAT = "omnodex.bundle/1";

export interface BundleOptions {
  home: string;
  roots: string[];
  /** Epoch ms; seals with events at or after this are included. */
  since?: number;
  /** Epoch ms; seals with events before this are included. */
  until?: number;
  now?: () => number;
}

export interface BuiltBundle {
  text: string;
  seals: number;
  events: number;
  /** Events a seal lists that the log no longer holds. The verifier will report them as dropped. */
  missing: string[];
}

function ms(iso: string): number {
  const v = Date.parse(iso);
  return Number.isNaN(v) ? 0 : v;
}

/** Read the named events from every root. */
async function collect(roots: readonly string[], wanted: ReadonlySet<string>): Promise<Map<string, TraceEvent>> {
  const found = new Map<string, TraceEvent>();
  for (const root of roots) {
    const dir = path.join(root, "event-log", "sessions");
    for (const name of (await fs.readdir(dir).catch(() => [] as string[])).sort()) {
      if (!name.endsWith(".jsonl")) continue;
      const text = await fs.readFile(path.join(dir, name), "utf8").catch(() => "");
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line) as TraceEvent;
          if (wanted.has(event.event_id) && !found.has(event.event_id)) found.set(event.event_id, event);
        } catch {
          // Skipped, as in every other reader of the log.
        }
      }
    }
  }
  return found;
}

/**
 * Seal what is pending, then bundle every seal that has events in the range.
 * A seal is whole or absent, so the bundle can run slightly wider than the
 * range asked for. Throws when no seal falls in the range.
 */
export async function buildBundle(opts: BundleOptions): Promise<BuiltBundle> {
  await sealPending({ home: opts.home, roots: opts.roots, now: opts.now });
  const all = await readSeals(opts.home);
  const chosen = all.filter((s) =>
    (opts.since === undefined || ms(s.last_recorded_at) >= opts.since) &&
    (opts.until === undefined || ms(s.first_recorded_at) < opts.until));
  if (chosen.length === 0) throw new Error("no sealed events in that range");

  const wanted = new Set(chosen.flatMap((s) => s.event_ids));
  const events = await collect(opts.roots, wanted);
  const key = await loadOrCreateKey(opts.home);
  const usedKeys = new Set(chosen.map((s) => s.key_id));

  const lines: string[] = [];
  const missing: string[] = [];
  let eventCount = 0;
  const body: string[] = [];
  for (const seal of chosen) {
    const { local: _local, ...signed } = seal as SealRecord;
    body.push(JSON.stringify({ type: "seal", ...signed }));
    for (const id of seal.event_ids) {
      const event = events.get(id);
      if (!event) {
        missing.push(id);
        continue;
      }
      eventCount++;
      body.push(JSON.stringify({ type: "event", seal: seal.seq, event_hash: eventHash(event), event }));
    }
  }
  lines.push(JSON.stringify({
    type: "manifest",
    format: BUNDLE_FORMAT,
    created_at: new Date(opts.now?.() ?? Date.now()).toISOString(),
    range: {
      since: opts.since === undefined ? null : new Date(opts.since).toISOString(),
      until: opts.until === undefined ? null : new Date(opts.until).toISOString(),
    },
    first_seal: chosen[0].seq,
    last_seal: chosen[chosen.length - 1].seq,
    seals: chosen.length,
    events: eventCount,
  }));
  if (usedKeys.has(key.key_id)) {
    lines.push(JSON.stringify({ type: "key", key_id: key.key_id, alg: "Ed25519", public_key: key.public_key }));
  }
  return { text: [...lines, ...body].join("\n") + "\n", seals: chosen.length, events: eventCount, missing };
}
