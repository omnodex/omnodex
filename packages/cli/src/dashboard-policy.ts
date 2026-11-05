// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Actions on a finding from the local dashboard: the targets a finding's call
 * offers, the policy entry an action makes, a preview over past findings, and
 * saving.
 *
 * The page never builds an entry. It sends which finding and what the person
 * chose, and this module builds the entry, so what is previewed, shown as a
 * command and saved are the same thing.
 *
 * Who may save what:
 *   - An entry that tightens (block, hold, a higher severity, showing again)
 *     for this machine is saved here, through the same code as
 *     `omnodex policy add`, with the same Pro check for block and hold.
 *   - An entry that loosens (allow, mute, a lower severity) is never saved
 *     here. The page shows the `omnodex policy add` command instead, because
 *     the typed confirmation in a terminal is what keeps an agent from
 *     turning protection down.
 *   - An entry for the whole account is never saved here. The page opens the
 *     hosted dashboard with the entry in the URL fragment, which a browser
 *     does not send to any server.
 */

import * as os from "node:os";
import { randomUUID } from "node:crypto";
import { evaluatePolicy, normalizeAction, normalizePath } from "@omnodex/analyzer";
import type { ReadModelSnapshot } from "@omnodex/projection";
import type { PolicyEntry, PolicyTarget, RiskSeverity, ToolInvokedEvent } from "@omnodex/shared";
import type { Draft, DraftRequest, PolicyAction, Preview, SaveBlock, TargetChoice, TargetKind } from "./dashboard-model/policy.js";
export type { Draft, DraftRequest, PolicyAction, PolicyScope, Preview, SaveBlock, TargetChoice, TargetKind } from "./dashboard-model/policy.js";
import { appendPolicyEntry, commandForEntry, describeEntry, loosens, tightens } from "./policy-command.js";

const ACTIONS: readonly PolicyAction[] = ["block", "hold", "allow", "mute", "severity"];
const KINDS: readonly TargetKind[] = ["rule", "path", "destination", "command", "tool"];
const SEVERITIES: readonly RiskSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const RANK: Readonly<Record<RiskSeverity, number>> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const PREVIEW_DAYS = 30;
/** Where the whole-account entry is made: the hosted dashboard's Policies page. */
export const HOSTED_POLICIES_URL = "https://dashboard.omnodex.com/policies";

const EFFECT: Record<Exclude<PolicyAction, "severity">, PolicyEntry["effect"]> = {
  block: { verdict: "deny" },
  hold: { verdict: "confirm" },
  allow: { verdict: "allow" },
  mute: { mute: true },
};

/** What the dashboard process lends this module. */
export interface DashboardPolicyHooks {
  /** This machine's Omnodex home, where the policy is kept. */
  home: () => string;
  /** Whether this machine's plan includes guardrails, which block and hold need. */
  guardrailsEntitled: () => Promise<boolean>;
  /** A rule's own severity, when the rule is known. */
  ruleSeverity: (ruleId: string) => RiskSeverity | undefined;
  /** This machine's entries. */
  machineEntries: () => PolicyEntry[];
  /** The account's entries as last pulled. */
  accountEntries: () => PolicyEntry[];
  /** For tests. */
  now?: () => Date;
  newId?: () => string;
}

type Call = ToolInvokedEvent;

/** The start of a command worth matching on: a word or two, before any flag or URL. */
export function commandPrefix(exec: string): string {
  const out: string[] = [];
  for (const w of exec.trim().split(/\s+/).slice(0, 2)) {
    if (w.startsWith("-") || w.includes("://") || w.includes("=")) break;
    out.push(w);
  }
  return out.join(" ");
}

/** The targets a call offers, pre-filled from what it did. */
export function targetChoices(call: Call | undefined): TargetChoice[] {
  const out: TargetChoice[] = [{ kind: "rule", value: "" }];
  if (!call) return out;
  const action = normalizeAction(call);
  for (const p of [...new Set([...action.writes, ...action.paths])].slice(0, 5)) {
    out.push({ kind: "path", value: normalizePath(p, call.cwd, os.homedir()) });
  }
  for (const host of [...new Set(action.destinations.map((d) => d.host))].slice(0, 5)) {
    out.push({ kind: "destination", value: host });
  }
  const prefix = action.exec ? commandPrefix(action.exec) : "";
  if (prefix) out.push({ kind: "command", value: prefix });
  out.push({
    kind: "tool",
    value: call.tool_name,
    ...(call.mcp_server && call.mcp_server !== "builtin" ? { server: call.mcp_server } : {}),
  });
  return out;
}

function targetOf(c: TargetChoice): PolicyTarget | undefined {
  const value = c.value.trim();
  if (c.kind === "rule" || !value) return undefined;
  if (c.kind === "path") return { path: value };
  if (c.kind === "destination") return { destination: value.toLowerCase() };
  if (c.kind === "command") return { command_prefix: value };
  return { tool: value, ...(c.server ? { server: c.server } : {}) };
}

/** The call a finding is about, as the evaluator reads it. */
function callOf(snapshot: ReadModelSnapshot, sessionId: string, relatedEventId: string): Call | undefined {
  const row = (snapshot.tool_calls[sessionId] ?? []).find((t) => t.tool_call_id === relatedEventId);
  if (!row) return undefined;
  try {
    const parameters = JSON.parse(row.parameters_json) as Record<string, unknown>;
    const cwd = snapshot.sessions.find((s) => s.session_id === sessionId)?.project_path;
    return {
      tool_call_id: row.tool_call_id,
      tool_name: row.tool_name,
      mcp_server: row.mcp_server,
      parameters,
      ...(cwd ? { cwd } : {}),
    } as unknown as Call;
  } catch {
    return undefined;
  }
}

type FindingRow = ReadModelSnapshot["risk_events"][string][number];

/** The rule's own severity: what was recorded before an entry changed it. */
const ruleSeverityOf = (e: Pick<FindingRow, "severity" | "recommended_severity">): RiskSeverity =>
  e.recommended_severity ?? e.severity;

interface Layers {
  machine: readonly PolicyEntry[];
  account: readonly PolicyEntry[];
}

function view(snapshot: ReadModelSnapshot, e: FindingRow, layers: Layers) {
  const r = evaluatePolicy({
    finding: { rule_id: e.rule_id, category: e.category, severity: ruleSeverityOf(e) },
    call: callOf(snapshot, e.session_id, e.related_event_id),
    machine: layers.machine,
    account: layers.account,
    home: os.homedir(),
  });
  return { severity: r.decided.severity ? r.severity : e.severity, muted: r.muted, decided: r.decided };
}

/** How `next` changes the findings of the last days against `current`. */
function previewOf(snapshot: ReadModelSnapshot, entry: PolicyEntry, current: Layers, next: Layers, now: Date): Preview {
  const since = new Date(now.getTime() - PREVIEW_DAYS * 86_400_000).toISOString();
  const p: Preview = { days: PREVIEW_DAYS, reach: 0, muted: 0, unmuted: 0, raised: 0, lowered: 0 };
  for (const rows of Object.values(snapshot.risk_events)) {
    for (const e of rows) {
      if (e.detected_at < since) continue;
      const alone = evaluatePolicy({
        finding: { rule_id: e.rule_id, category: e.category, severity: ruleSeverityOf(e) },
        call: callOf(snapshot, e.session_id, e.related_event_id),
        machine: [entry],
        home: os.homedir(),
      });
      if (alone.decided.verdict || alone.decided.severity || alone.decided.mute) p.reach++;
      const a = view(snapshot, e, current);
      const b = view(snapshot, e, next);
      if (!a.muted && b.muted) p.muted++;
      else if (a.muted && !b.muted) p.unmuted++;
      if (!b.muted) {
        if (RANK[b.severity] > RANK[a.severity]) p.raised++;
        else if (RANK[b.severity] < RANK[a.severity]) p.lowered++;
      }
    }
  }
  return p;
}

/** The entry in the form the hosted Policies page reads from its URL fragment. */
export function hostedUrl(entry: PolicyEntry): string {
  const { match, effect, note } = entry;
  const payload = Buffer.from(JSON.stringify({ v: 1, entry: { match, effect, ...(note ? { note } : {}) } }), "utf8").toString("base64url");
  return `${HOSTED_POLICIES_URL}#add=${payload}`;
}

/** Whether `body` is a request this module can read. */
export function parseDraftRequest(body: unknown): DraftRequest | string {
  if (typeof body !== "object" || body === null) return "the request is not an object";
  const b = body as Record<string, unknown>;
  const str = (k: string): string | undefined => (typeof b[k] === "string" && (b[k] as string).length > 0 ? (b[k] as string) : undefined);
  const session_id = str("session_id");
  const rule_id = str("rule_id");
  const related_event_id = str("related_event_id");
  if (!session_id || !rule_id || !related_event_id) return "name the finding: session_id, rule_id and related_event_id";
  if (!ACTIONS.includes(b.action as PolicyAction)) return "action must be block, hold, allow, mute or severity";
  const scope = b.scope === "account" ? "account" : b.scope === "machine" || b.scope === undefined ? "machine" : null;
  if (!scope) return "scope must be machine or account";
  const req: DraftRequest = { session_id, rule_id, related_event_id, action: b.action as PolicyAction, scope };
  if (b.severity !== undefined) {
    if (!SEVERITIES.includes(b.severity as RiskSeverity)) return "severity must be LOW, MEDIUM, HIGH or CRITICAL";
    req.severity = b.severity as RiskSeverity;
  }
  if (b.target !== undefined && b.target !== null) {
    const t = b.target as Record<string, unknown>;
    if (typeof t !== "object" || !KINDS.includes(t.kind as TargetKind) || typeof t.value !== "string") return "target needs a kind and a value";
    req.target = { kind: t.kind as TargetKind, value: t.value, ...(typeof t.server === "string" && t.server ? { server: t.server } : {}) };
  }
  if (b.here === true) req.here = true;
  return req;
}

/** Everything the page needs to show an action on a finding, or why it cannot. */
export async function draftPolicy(snapshot: ReadModelSnapshot, req: DraftRequest, hooks: DashboardPolicyHooks): Promise<Draft | null> {
  const finding = (snapshot.risk_events[req.session_id] ?? []).find(
    (e) => e.rule_id === req.rule_id && e.related_event_id === req.related_event_id,
  );
  if (!finding) return null;
  const now = hooks.now?.() ?? new Date();
  const call = callOf(snapshot, req.session_id, req.related_event_id);
  const project = snapshot.sessions.find((s) => s.session_id === req.session_id)?.project_path || undefined;
  const own = ruleSeverityOf(finding);
  const guardrails = await hooks.guardrailsEntitled();
  const draft: Draft = { choices: targetChoices(call), ...(project ? { project } : {}), own_severity: own, guardrails };

  if (req.action === "severity" && !req.severity) return { ...draft, error: "choose a severity" };
  if (req.action === "severity" && req.severity === own) return { ...draft, error: `the rule already has severity ${own}` };
  if (req.here && !project) return { ...draft, error: "this finding has no project folder" };

  const t = targetOf(req.target ?? { kind: "rule", value: "" });
  const entry: PolicyEntry = {
    id: hooks.newId?.() ?? `p-${randomUUID().slice(0, 8)}`,
    match: { rule_id: req.rule_id, ...(t ? { target: t } : {}), ...(req.here && project ? { project } : {}) },
    effect: req.action === "severity" ? { severity: req.severity! } : EFFECT[req.action],
    created_at: now.toISOString(),
    created_by: req.scope === "account" ? "dashboard" : "cli",
  };
  draft.entry = entry;
  draft.summary = describeEntry(entry);
  draft.command = commandForEntry(entry);

  const machine = hooks.machineEntries();
  const account = hooks.accountEntries();
  const current = { machine, account };
  const next = req.scope === "account" ? { machine, account: [...account, entry] } : { machine: [...machine, entry], account };
  draft.preview = previewOf(snapshot, entry, current, next, now);

  if (req.scope === "account") {
    draft.hosted_url = hostedUrl(entry);
    draft.save_blocked = "account";
  } else if (loosens(entry, hooks.ruleSeverity)) {
    draft.save_blocked = "loosens";
  } else if (!tightens(entry, hooks.ruleSeverity)) {
    draft.save_blocked = "no-change";
  } else if ((entry.effect.verdict === "deny" || entry.effect.verdict === "confirm") && !guardrails) {
    draft.save_blocked = "pro";
  }
  return draft;
}

/**
 * Save the entry a request describes to this machine's policy. Only an entry
 * that tightens, for this machine, and that this plan includes; anything else
 * comes back with the reason and writes nothing.
 */
export async function savePolicy(
  snapshot: ReadModelSnapshot,
  req: DraftRequest,
  hooks: DashboardPolicyHooks,
): Promise<{ saved: PolicyEntry } | { blocked: SaveBlock | "not-found" | "invalid"; error?: string }> {
  const draft = await draftPolicy(snapshot, req, hooks);
  if (!draft) return { blocked: "not-found" };
  if (!draft.entry) return { blocked: "invalid", error: draft.error };
  if (draft.save_blocked) return { blocked: draft.save_blocked };
  await appendPolicyEntry(hooks.home(), draft.entry);
  return { saved: draft.entry };
}
