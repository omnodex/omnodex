// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- finding notification rules
 *
 * The hosted dashboard saves notification rules in the sealed account policy
 * copy, beside the policy entries (`notifications`). A rule says which
 * findings to tell the owner about and where; this machine matches each new
 * finding against them and sends the gateway only a minimal request. The
 * gateway never sees a rule, a path or a host.
 *
 * A copy with no `notifications` field has never had a rule saved; the
 * default rule then applies: HIGH and CRITICAL findings, in the email digest
 * and the dashboard list. Hosted accounts get only that default, whatever
 * the copy holds.
 */

import { createHash } from "node:crypto";

export type NotifySeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
const SEVERITIES: readonly NotifySeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Destination IDs with a fixed meaning; any other ID is one of the account's channels. */
export const ACCOUNT_EMAIL = "account_email";
export const IN_APP = "in_app";

/** What a finding must be, all of the listed parts at once. */
export interface NotificationMatch {
  severities?: NotifySeverity[];
  rule_id?: string;
  category?: string;
  /** A file or folder the call touched, ~ allowed. */
  path?: string;
  /** A host (and its subdomains) the call reached. */
  destination?: string;
}

export interface NotificationRule {
  id: string;
  name: string;
  enabled: boolean;
  match: NotificationMatch;
  exclude: NotificationMatch[];
  channels: string[];
  mode: "now" | "digest";
  /** Local 24-hour times, "22:00" to "07:00"; a window may cross midnight. */
  quiet_hours?: { from: string; to: string };
}

const MAX_RULES = 50;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

const text = (v: unknown, max = 200): string | undefined =>
  typeof v === "string" && v.trim() && v.length <= max ? v.trim() : undefined;

function parseMatch(raw: unknown): NotificationMatch {
  const r = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const severities = Array.isArray(r.severities)
    ? [...new Set((r.severities as unknown[]).filter((s): s is NotifySeverity => SEVERITIES.includes(s as NotifySeverity)))]
    : [];
  const out: NotificationMatch = {};
  if (severities.length) out.severities = severities;
  for (const k of ["rule_id", "category", "path", "destination"] as const) {
    const v = text(r[k]);
    if (v) out[k] = v;
  }
  return out;
}

const isEmpty = (m: NotificationMatch): boolean => Object.keys(m).length === 0;

/** The valid rules in a copy's `notifications` list; anything malformed is dropped. */
export function parseNotificationRules(raw: unknown): NotificationRule[] {
  if (!Array.isArray(raw)) return [];
  const rules: NotificationRule[] = [];
  for (const r of (raw as unknown[]).slice(0, MAX_RULES)) {
    if (typeof r !== "object" || r === null) continue;
    const rec = r as Record<string, unknown>;
    const id = text(rec.id, 64);
    const channels = Array.isArray(rec.channels)
      ? [...new Set((rec.channels as unknown[]).filter((c): c is string => typeof c === "string" && c.length > 0 && c.length <= 64))]
      : [];
    const match = parseMatch(rec.match);
    if (!id || channels.length === 0 || isEmpty(match)) continue;
    const q = rec.quiet_hours as Record<string, unknown> | undefined;
    rules.push({
      id,
      name: text(rec.name, 80) ?? "Notification rule",
      enabled: rec.enabled !== false,
      match,
      exclude: (Array.isArray(rec.exclude) ? (rec.exclude as unknown[]) : []).map(parseMatch).filter((m) => !isEmpty(m)).slice(0, 20),
      channels: channels.slice(0, 10),
      mode: rec.mode === "now" ? "now" : "digest",
      ...(q && typeof q.from === "string" && typeof q.to === "string" && TIME_RE.test(q.from) && TIME_RE.test(q.to)
        ? { quiet_hours: { from: q.from, to: q.to } }
        : {}),
    });
  }
  return rules;
}

/** What applies before any rule is saved, and to every Hosted account. */
export const DEFAULT_RULE: NotificationRule = {
  id: "default",
  name: "HIGH and CRITICAL findings",
  enabled: true,
  match: { severities: ["HIGH", "CRITICAL"] },
  exclude: [],
  channels: [ACCOUNT_EMAIL, IN_APP],
  mode: "digest",
};

/**
 * The reference the gateway stores for a finding, and the dashboard uses to
 * find it again: the first 24 hex digits of SHA-256 of the session, the
 * related event and the rule, NUL-separated. Must match the dashboard.
 */
export function findingRef(f: { session_id: string; related_event_id: string; rule_id: string }): string {
  return createHash("sha256").update(`${f.session_id}\0${f.related_event_id}\0${f.rule_id}`).digest("hex").slice(0, 24);
}

/** The parts of a finding a rule can match, with the call it was raised on when known. */
export interface NotifiableFinding {
  severity: string;
  rule_id: string;
  category: string;
}

/** Whether a local time (minutes since midnight) is inside a quiet window. */
export function inQuietHours(q: { from: string; to: string } | undefined, minutes: number): boolean {
  if (!q) return false;
  const at = (t: string): number => Number(t.slice(0, 2)) * 60 + Number(t.slice(3, 5));
  const from = at(q.from);
  const to = at(q.to);
  if (from === to) return false;
  return from < to ? minutes >= from && minutes < to : minutes >= from || minutes < to;
}

/** Whether a rule needs the call the finding was raised on, to look at a path or host. */
export const needsCall = (m: NotificationMatch): boolean => m.path !== undefined || m.destination !== undefined;

/**
 * Whether one match holds for a finding. `touches` answers a path or host
 * question about the finding's call; without one such a part cannot hold.
 */
export function matchHolds(
  m: NotificationMatch,
  f: NotifiableFinding,
  touches: (kind: "path" | "destination", value: string) => boolean,
): boolean {
  if (m.severities && !m.severities.includes(f.severity as NotifySeverity)) return false;
  if (m.rule_id !== undefined && m.rule_id !== f.rule_id) return false;
  if (m.category !== undefined && m.category !== f.category) return false;
  if (m.path !== undefined && !touches("path", m.path)) return false;
  if (m.destination !== undefined && !touches("destination", m.destination)) return false;
  return true;
}

/** A finding's deliveries: destinations to post to now, and to hold for the digest. */
export interface Deliveries {
  now: string[];
  digest: string[];
}

/**
 * The deliveries the rules give a finding. A matching rule's channels are
 * added; a rule whose exclude matches contributes nothing. "now" applies to
 * chat channels only (email and the dashboard list are always held for the
 * digest or written at once by the gateway), and quiet hours turn "now"
 * into "digest".
 */
export function deliveriesFor(
  rules: readonly NotificationRule[],
  f: NotifiableFinding,
  touches: (kind: "path" | "destination", value: string) => boolean,
  minutes: number,
): Deliveries {
  const now = new Set<string>();
  const digest = new Set<string>();
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (!matchHolds(rule.match, f, touches)) continue;
    if (rule.exclude.some((e) => matchHolds(e, f, touches))) continue;
    const immediate = rule.mode === "now" && !inQuietHours(rule.quiet_hours, minutes);
    for (const c of rule.channels) {
      const fixed = c === ACCOUNT_EMAIL || c === IN_APP;
      (immediate && !fixed ? now : digest).add(c);
    }
  }
  // A destination asked for now wins over the same one asked for the digest.
  for (const c of now) digest.delete(c);
  return { now: [...now], digest: [...digest] };
}
