// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Check an evidence bundle. This reads a bundle and nothing else, and uses
 * only canonical.ts for the arithmetic, so it is also a reference for anyone
 * writing their own verifier from docs/evidence.md.
 */

import { GENESIS_HEAD, eventHash, foldHead, verifyBody } from "./canonical.js";

export type ProblemCode =
  | "malformed"
  | "unknown_key"
  | "key_untrusted"
  | "bad_signature"
  | "count_mismatch"
  | "dropped"
  | "extra"
  | "reordered"
  | "edited"
  | "gap"
  | "chain_break";

export interface Problem {
  code: ProblemCode;
  seal?: number;
  event_id?: string;
  message: string;
}

export interface IntegrityEntry {
  seal: number;
  event_id: string;
  event_type: string;
  at: string;
  detail: string;
}

export interface VerifyReport {
  /** True when no problem was found. */
  ok: boolean;
  problems: Problem[];
  notes: string[];
  seals: number;
  events: number;
  keys: { key_id: string; public_key: string }[];
  /** Capture pauses and monitoring changes inside the bundle's events. */
  integrity: IntegrityEntry[];
}

export interface VerifyOptions {
  /** Public keys (hex) or key ids the caller trusts. When given, every seal must be signed by one. */
  trustedKeys?: string[];
}

export const INTEGRITY_TYPES = ["capture.paused", "capture.resumed", "monitoring.changed", "monitoring.unexplained_change"];

const BASE_FIELDS = new Set([
  "schema_version", "event_id", "session_id", "event_type", "occurred_at", "recorded_at", "interceptor", "platform", "agent_id", "local_only",
]);

interface SealLine {
  type: "seal";
  seq: number;
  prev_head: string;
  head: string;
  count: number;
  event_ids: string[];
  key_id: string;
  signature: string;
  [k: string]: unknown;
}

interface EventLine {
  type: "event";
  seal: number;
  event_hash: string;
  event: Record<string, unknown> & { event_id: string; event_type: string; occurred_at: string };
}

export function verifyBundle(text: string, options: VerifyOptions = {}): VerifyReport {
  const problems: Problem[] = [];
  const notes: string[] = [];
  const keys = new Map<string, string>();
  const seals: SealLine[] = [];
  const eventsBySeal = new Map<number, EventLine[]>();
  let manifest: { format?: string } | undefined;
  let eventCount = 0;

  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    let row: { type?: string };
    try {
      row = JSON.parse(lines[i]) as { type?: string };
    } catch {
      problems.push({ code: "malformed", message: "line " + (i + 1) + " is not JSON" });
      continue;
    }
    if (row.type === "manifest") manifest = row as { format?: string };
    else if (row.type === "key") {
      const k = row as unknown as { key_id: string; public_key: string };
      keys.set(k.key_id, k.public_key);
    } else if (row.type === "seal") seals.push(row as unknown as SealLine);
    else if (row.type === "event") {
      const e = row as unknown as EventLine;
      if (!e.event || typeof e.event.event_id !== "string") {
        problems.push({ code: "malformed", message: "line " + (i + 1) + " is an event line with no event" });
        continue;
      }
      eventCount++;
      const group = eventsBySeal.get(e.seal) ?? [];
      group.push(e);
      eventsBySeal.set(e.seal, group);
    }
  }
  if (!manifest || manifest.format !== "omnodex.bundle/1") {
    problems.push({ code: "malformed", message: "not an omnodex.bundle/1 file (no matching manifest line)" });
  }

  const trusted = options.trustedKeys?.map((k) => k.toLowerCase());
  const sealSeqs = new Set(seals.map((s) => s.seq));
  for (const seq of eventsBySeal.keys()) {
    if (!sealSeqs.has(seq)) {
      problems.push({ code: "extra", seal: seq, message: "events are filed under seal " + seq + ", which is not in the bundle" });
    }
  }

  let previous: SealLine | undefined;
  for (const seal of seals) {
    const publicKey = keys.get(seal.key_id);
    // The signed body is the seal without its type tag and signature.
    const { type: _type, signature, ...body } = seal;
    if (!publicKey) {
      problems.push({ code: "unknown_key", seal: seal.seq, message: "seal " + seal.seq + " names key " + seal.key_id + ", which the bundle does not carry" });
    } else {
      if (!verifyBody(publicKey, body, signature)) {
        problems.push({ code: "bad_signature", seal: seal.seq, message: "seal " + seal.seq + " does not carry a valid signature from key " + seal.key_id });
      }
      if (trusted && !trusted.includes(publicKey.toLowerCase()) && !trusted.includes(seal.key_id.toLowerCase())) {
        problems.push({ code: "key_untrusted", seal: seal.seq, message: "seal " + seal.seq + " is signed by key " + seal.key_id + ", which is not one of the keys you trust" });
      }
    }

    // Continuity with the seal before it.
    if (previous) {
      if (seal.seq !== previous.seq + 1) {
        problems.push({ code: "gap", seal: seal.seq, message: "seals " + (previous.seq + 1) + " to " + (seal.seq - 1) + " are missing between seal " + previous.seq + " and seal " + seal.seq });
      } else if (seal.prev_head !== previous.head) {
        problems.push({ code: "chain_break", seal: seal.seq, message: "seal " + seal.seq + " does not continue from the head of seal " + previous.seq });
      }
    } else if (seal.prev_head !== GENESIS_HEAD) {
      notes.push("The bundle starts at seal " + seal.seq + "; earlier seals are not included, so nothing here shows what came before it.");
    }
    previous = seal;

    // The events against the seal.
    const present = eventsBySeal.get(seal.seq) ?? [];
    if (seal.count !== seal.event_ids.length) {
      problems.push({ code: "count_mismatch", seal: seal.seq, message: "seal " + seal.seq + " says " + seal.count + " events but lists " + seal.event_ids.length });
    }
    const listed = new Set(seal.event_ids);
    const have = new Map<string, EventLine>();
    for (const e of present) {
      if (!listed.has(e.event.event_id) || have.has(e.event.event_id)) {
        problems.push({ code: "extra", seal: seal.seq, event_id: e.event.event_id, message: "event " + e.event.event_id + " is not one of the events seal " + seal.seq + " lists" });
      } else have.set(e.event.event_id, e);
    }
    const dropped = seal.event_ids.filter((id) => !have.has(id));
    for (const id of dropped) {
      problems.push({ code: "dropped", seal: seal.seq, event_id: id, message: "event " + id + " is listed by seal " + seal.seq + " but missing from the bundle" });
    }
    const bundleOrder = present.map((e) => e.event.event_id).filter((id) => have.has(id) && listed.has(id));
    const sealOrder = seal.event_ids.filter((id) => have.has(id));
    if (bundleOrder.length === sealOrder.length && bundleOrder.some((id, i) => id !== sealOrder[i])) {
      problems.push({ code: "reordered", seal: seal.seq, message: "the events of seal " + seal.seq + " are not in the order the seal signed" });
    }

    let edited = false;
    const hashes = new Map<string, string>();
    for (const [id, e] of have) {
      const h = eventHash(e.event);
      hashes.set(id, h);
      if (h !== e.event_hash) {
        edited = true;
        problems.push({ code: "edited", seal: seal.seq, event_id: id, message: "event " + id + " no longer matches the hash recorded for it" });
      }
    }
    if (dropped.length === 0) {
      let head = seal.prev_head;
      for (const id of seal.event_ids) head = foldHead(head, hashes.get(id) as string);
      if (head !== seal.head && !edited) {
        problems.push({ code: "edited", seal: seal.seq, message: "the events of seal " + seal.seq + " do not hash to the head it signed" });
      }
    }
  }

  const integrity: IntegrityEntry[] = [];
  for (const [seal, group] of eventsBySeal) {
    for (const e of group) {
      if (!INTEGRITY_TYPES.includes(e.event.event_type)) continue;
      const rest = Object.fromEntries(Object.entries(e.event).filter(([k]) => !BASE_FIELDS.has(k)));
      integrity.push({ seal, event_id: e.event.event_id, event_type: e.event.event_type, at: e.event.occurred_at, detail: JSON.stringify(rest).slice(0, 200) });
    }
  }
  integrity.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

  return {
    ok: problems.length === 0,
    problems,
    notes,
    seals: seals.length,
    events: eventCount,
    keys: [...keys].map(([key_id, public_key]) => ({ key_id, public_key })),
    integrity,
  };
}

/** Lines for a person: the verdict first, then what was found. */
export function formatReport(report: VerifyReport, trustedGiven: boolean): string[] {
  const out: string[] = [];
  out.push(report.ok
    ? "VALID: " + report.seals + " seal(s) and " + report.events + " event(s) check out."
    : "INVALID: " + report.problems.length + " problem(s) found in " + report.seals + " seal(s) and " + report.events + " event(s).");
  for (const p of report.problems) out.push("  [" + p.code + "] " + p.message);
  for (const n of report.notes) out.push("  note: " + n);
  if (report.ok && !trustedGiven) {
    out.push("  The signatures match the keys inside the bundle. Compare these key ids with the one you were given (or pass --key) before relying on it:");
    for (const k of report.keys) out.push("    " + k.key_id + "  " + k.public_key);
  }
  out.push(report.integrity.length === 0
    ? "Monitoring integrity events in range: none."
    : "Monitoring integrity events in range: " + report.integrity.length);
  for (const i of report.integrity) out.push("  " + i.at + "  " + i.event_type + "  " + i.detail);
  return out;
}
