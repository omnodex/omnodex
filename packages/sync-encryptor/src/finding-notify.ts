// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- telling the owner about findings
 *
 * The background pass calls this after detection. It reads the findings
 * recorded since the last pass, matches them against the account's
 * notification rules (notification-rules.ts), and asks the gateway to
 * deliver each one with a minimal request:
 *
 *   POST /api/v1/notify/finding
 *     { rule_id, severity, occurred_at, finding_ref, mode, destination_ids }
 *
 * Nothing else about a finding is sent: no path, command, host, tool
 * argument or machine name. The gateway refuses a request with any other
 * field, and its message holds only these values and a link to the
 * dashboard, where the finding opens from the person's own decrypted data.
 *
 * What counts: the finding's effective severity (the user's, when a policy
 * entry changed it), never a muted finding, and only findings recorded in
 * the last few hours, so an old log never floods anyone. The first pass on
 * a machine only records where each session's log ends, so installing the
 * feature never notifies about history. Hosted accounts get the default
 * rule (HIGH and CRITICAL, in the digest and the dashboard list); Pro and
 * above follow their saved rules. A free account sends nothing.
 *
 * Failures never reach the agent. A request that could not be answered
 * leaves the session's position where it was, so the next pass tries
 * again; the gateway ignores a finding it already has.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { readPulledPolicy } from "./account-policy.js";
import {
  DEFAULT_RULE,
  deliveriesFor,
  findingRef,
  needsCall,
  type NotificationRule,
} from "./notification-rules.js";

export const FINDING_NOTIFY_STATE_FILE = "finding-notify-state.json";
/** Set to "0" to send no finding notifications. */
export const FINDING_NOTIFY_ENV = "OMNODEX_FINDING_NOTIFY";

const REQUEST_TIMEOUT_MS = 10_000;
/** Findings older than this at the time of the pass are not worth a message. */
const MAX_FINDING_AGE_MS = 6 * 3_600_000;
/** Requests one pass may make. */
const MAX_REQUESTS_PER_PASS = 40;
const FULL_TIERS = new Set(["pro", "enterprise"]);
const LICENSED_TIERS = new Set(["hosted", "pro", "enterprise"]);

export type NotifyOutcome = "disabled" | "no-credentials" | "not-entitled" | "seeded" | "done" | "stopped";

export interface NotifyResult {
  outcome: NotifyOutcome;
  /** Requests the gateway accepted. */
  sent: number;
}

export interface FindingNotifyOptions {
  fetchFn?: typeof fetch;
  now?: () => Date;
  /** Folder the machine's findings are read from. Defaults to the home's event log. */
  logRoot?: string;
  /** Answers whether a call touched a path or host. Defaults to the analyzer's matcher. */
  touches?: TouchesFactory;
}

type Touches = (kind: "path" | "destination", value: string) => boolean;
export type TouchesFactory = (call: Record<string, unknown> | undefined) => Touches;

interface State {
  v: 1;
  /** Bytes of each session log already looked at. */
  sessions: Record<string, number>;
}

async function readJson(file: string): Promise<Record<string, unknown> | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function readState(home: string): Promise<State | null> {
  const raw = await readJson(path.join(home, FINDING_NOTIFY_STATE_FILE));
  if (!raw || raw.v !== 1 || typeof raw.sessions !== "object" || raw.sessions === null) return null;
  return { v: 1, sessions: raw.sessions as Record<string, number> };
}

async function writeState(home: string, state: State): Promise<void> {
  const file = path.join(home, FINDING_NOTIFY_STATE_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state) + "\n", "utf8");
  await fs.rename(tmp, file);
}

/** The analyzer's matcher, loaded only when a rule asks about a path or host. */
async function analyzerTouches(): Promise<TouchesFactory | null> {
  try {
    const { targetMatches } = await import("@omnodex/analyzer");
    return (call) => (kind, value) =>
      call !== undefined &&
      targetMatches(kind === "path" ? { path: value } : { destination: value }, { call: call as never }, "any");
  } catch {
    return null;
  }
}

interface LogEvent {
  event_type?: string;
  session_id?: string;
  occurred_at?: string;
  recorded_at?: string;
  severity?: string;
  rule_id?: string;
  category?: string;
  related_event_id?: string;
  tool_call_id?: string;
  enforcement?: { muted?: boolean };
}

function parseLines(text: string): LogEvent[] {
  const out: LogEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const ev = JSON.parse(line) as LogEvent;
      if (ev && typeof ev === "object") out.push(ev);
    } catch {
      // A torn or foreign line is not ours to report.
    }
  }
  return out;
}

/** Complete lines appended to a file after `offset`, and the offset after them. */
async function readAppended(file: string, offset: number, size: number): Promise<{ text: string; next: number }> {
  const fh = await fs.open(file, "r");
  try {
    const buf = Buffer.alloc(size - offset);
    await fh.read(buf, 0, buf.length, offset);
    const cut = buf.lastIndexOf(0x0a);
    if (cut < 0) return { text: "", next: offset };
    return { text: buf.subarray(0, cut + 1).toString("utf8"), next: offset + cut + 1 };
  } finally {
    await fh.close();
  }
}

/** Looks at the findings recorded since the last pass and asks the gateway to deliver the ones the rules want. */
export async function sendFindingNotifications(home: string, opts: FindingNotifyOptions = {}): Promise<NotifyResult> {
  if (process.env[FINDING_NOTIFY_ENV] === "0") return { outcome: "disabled", sent: 0 };
  try {
    const config = await readJson(path.join(home, "stream-config.json"));
    const apiToken = typeof config?.api_token === "string" ? config.api_token : "";
    if (!apiToken) return { outcome: "no-credentials", sent: 0 };
    const license = (await readJson(path.join(home, "license-cache.json")))?.response as { tier?: unknown } | undefined;
    const tier = typeof license?.tier === "string" ? license.tier : "";
    if (!LICENSED_TIERS.has(tier)) return { outcome: "not-entitled", sent: 0 };
    const apiUrl = (typeof config?.api_url === "string" && config.api_url ? config.api_url : "https://api.omnodex.com").replace(/\/$/, "");

    // Hosted follows the default rule; Pro follows what the dashboard saved, or the default before any is.
    const pulled = FULL_TIERS.has(tier) ? await readPulledPolicy(home) : null;
    const rules: readonly NotificationRule[] = pulled?.notifications ?? [DEFAULT_RULE];
    if (rules.every((r) => !r.enabled)) return { outcome: "done", sent: 0 };

    const root = opts.logRoot ?? path.join(home, "event-log");
    const sessionsDir = path.join(root, "sessions");
    const files = (await fs.readdir(sessionsDir).catch(() => [] as string[])).filter((f) => f.endsWith(".jsonl"));
    const sizes = new Map<string, number>();
    for (const f of files) sizes.set(f, (await fs.stat(path.join(sessionsDir, f)).catch(() => null))?.size ?? 0);

    const held = await readState(home);
    if (!held) {
      // First pass on this machine: remember where every log ends, notify about nothing old.
      await writeState(home, { v: 1, sessions: Object.fromEntries(sizes) });
      return { outcome: "seeded", sent: 0 };
    }

    const now = (opts.now?.() ?? new Date());
    const minutes = now.getHours() * 60 + now.getMinutes();
    const wantsCall = rules.some((r) => r.enabled && (needsCall(r.match) || r.exclude.some(needsCall)));
    const touchesFactory: TouchesFactory | null = wantsCall ? (opts.touches ?? (await analyzerTouches())) : null;
    const none: Touches = () => false;
    const fetchFn = opts.fetchFn ?? fetch;

    const next: State = { v: 1, sessions: { ...held.sessions } };
    let requests = 0;
    let sent = 0;
    let stopped = false;

    for (const [file, size] of sizes) {
      const offset = held.sessions[file] ?? 0;
      if (size <= offset) { next.sessions[file] = size; continue; }
      const appended = await readAppended(path.join(sessionsDir, file), offset, size);
      const findings = parseLines(appended.text).filter(
        (e) => e.event_type === "risk.detected" && !e.enforcement?.muted && e.rule_id && e.severity && e.related_event_id,
      );
      let calls: Map<string, Record<string, unknown>> | null = null;
      let sessionDone = true;

      for (const f of findings) {
        const at = Date.parse(f.occurred_at ?? f.recorded_at ?? "");
        if (!Number.isFinite(at) || now.getTime() - at > MAX_FINDING_AGE_MS) continue;
        let touches: Touches = none;
        if (touchesFactory) {
          if (!calls) {
            calls = new Map();
            const whole = parseLines((await fs.readFile(path.join(sessionsDir, file), "utf8").catch(() => "")));
            for (const e of whole) if (e.event_type === "tool.invoked" && e.tool_call_id) calls.set(e.tool_call_id, e as Record<string, unknown>);
          }
          touches = touchesFactory(calls.get(f.related_event_id!));
        }
        const deliveries = deliveriesFor(rules, { severity: f.severity!, rule_id: f.rule_id!, category: f.category ?? "" }, touches, minutes);
        const ref = findingRef({ session_id: f.session_id ?? file.replace(/\.jsonl$/, ""), related_event_id: f.related_event_id!, rule_id: f.rule_id! });
        const asks: { mode: "now" | "digest"; ids: string[] }[] = [];
        if (deliveries.now.length) asks.push({ mode: "now", ids: deliveries.now });
        if (deliveries.digest.length) asks.push({ mode: "digest", ids: deliveries.digest });

        for (const ask of asks) {
          if (requests >= MAX_REQUESTS_PER_PASS) { sessionDone = false; stopped = true; break; }
          requests++;
          let res: Response;
          try {
            res = await fetchFn(`${apiUrl}/api/v1/notify/finding`, {
              method: "POST",
              headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
              body: JSON.stringify({
                rule_id: f.rule_id,
                severity: f.severity,
                occurred_at: new Date(at).toISOString(),
                finding_ref: ref,
                mode: ask.mode,
                destination_ids: ask.ids,
              }),
              signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
            });
          } catch {
            sessionDone = false; stopped = true; break;
          }
          if (res.ok) { sent++; continue; }
          // The gateway said no. A limit or an outage is retried next pass; a refusal of this request is not.
          if (res.status === 429 || res.status >= 500) { sessionDone = false; stopped = true; break; }
          if (res.status === 403 || res.status === 401) { stopped = true; break; }
        }
        if (stopped) break;
      }
      if (sessionDone) next.sessions[file] = appended.next;
      if (stopped) break;
    }
    await writeState(home, next);
    return { outcome: stopped ? "stopped" : "done", sent };
  } catch {
    return { outcome: "stopped", sent: 0 };
  }
}
