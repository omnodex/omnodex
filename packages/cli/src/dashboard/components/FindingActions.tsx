// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import React, { useEffect, useRef, useState } from "react";
import type { Draft, PolicyAction, PolicyScope, TargetChoice } from "../../dashboard-model/policy.js";
import type { RiskEventRow } from "../../dashboard-model/view.js";

/**
 * Actions on a finding: Block, Hold, Allow, Mute and Change severity, each
 * with a scope chooser and a preview over the last 30 days.
 *
 * The server builds every entry. What this page does with the answer depends
 * on the entry: one that tightens this machine's policy is saved here; one
 * that loosens it is shown as an `omnodex policy add` command to run in a
 * terminal, where a typed confirmation keeps an agent from turning protection
 * down; one for the whole account opens the hosted dashboard with the entry in
 * the URL fragment.
 */

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const LABEL: Record<PolicyAction, string> = {
  block: "Block like this", hold: "Hold like this", allow: "Allow like this", mute: "Mute", severity: "Change severity",
};
const TARGET_LABEL: Record<TargetChoice["kind"], string> = {
  rule: "Every finding from this rule", path: "This path", destination: "This host", command: "This command", tool: "This tool",
};
const plural = (n: number, one: string): string => `${n} ${one}${n === 1 ? "" : "s"}`;

interface Form {
  action: PolicyAction;
  severity: string;
  choiceAt: number;
  value: string | null;
  here: boolean;
  scope: PolicyScope;
}

async function post(path: string, body: unknown): Promise<{ ok: boolean; status: number; json: Record<string, unknown> }> {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { ok: res.ok, status: res.status, json };
}

function previewText(d: Draft): string {
  const p = d.preview;
  if (!p) return "";
  const parts = [
    p.muted && `${p.muted} hidden`,
    p.lowered && `${p.lowered} lowered`,
    p.raised && `${p.raised} raised`,
    p.unmuted && `${p.unmuted} shown again`,
  ].filter(Boolean);
  const lead = `Matches ${plural(p.reach, "finding")} in the last ${p.days} days`;
  const verdict = d.entry?.effect.verdict;
  if (verdict === "deny" || verdict === "confirm") {
    const did = verdict === "deny" ? "stopped" : "held";
    return `${lead}, whose calls this would have ${did}. It applies to new calls only; a machine in shadow mode records what it would have ${did} instead.`;
  }
  return parts.length > 0
    ? `${lead}: ${parts.join(", ")}.`
    : `${lead}. This page does not change what it shows for past findings; this machine applies the entry to new calls.`;
}

export function FindingActions({ event }: { event: RiskEventRow }): React.JSX.Element | null {
  const [available, setAvailable] = useState(false);
  const [form, setForm] = useState<Form | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const seq = useRef(0);

  useEffect(() => {
    let live = true;
    fetch("/api/info").then((r) => r.json()).then((i: { policy?: boolean }) => { if (live) setAvailable(i.policy === true); }).catch(() => {});
    return () => { live = false; };
  }, []);

  // A different finding starts clean.
  const key = `${event.session_id}:${event.rule_id}:${event.related_event_id}`;
  useEffect(() => { setForm(null); setDraft(null); setError(null); setMessage(null); }, [key]);

  const request = (f: Form, choices: TargetChoice[] | undefined) => {
    const base = choices?.[Math.min(f.choiceAt, (choices?.length ?? 1) - 1)];
    return {
      session_id: event.session_id,
      rule_id: event.rule_id,
      related_event_id: event.related_event_id,
      action: f.action,
      scope: f.scope,
      here: f.here,
      ...(f.action === "severity" ? { severity: f.severity } : {}),
      ...(base ? { target: { ...base, value: f.value ?? base.value } } : {}),
    };
  };

  // Ask the server what the current choices make, each time they change.
  useEffect(() => {
    if (!form) return;
    const mine = ++seq.current;
    const t = setTimeout(() => {
      post("/api/policy/draft", request(form, draft?.choices)).then((r) => {
        if (mine !== seq.current) return;
        if (!r.ok) { setError(String(r.json.error ?? "could not preview")); return; }
        const d = r.json as unknown as Draft;
        setDraft(d);
        setError(form.action === "severity" && form.severity === "" ? null : d.error ?? null);
        // First answer for an action: start on a severity other than the rule's own.
        if (form.action === "severity" && form.severity === "") {
          setForm({ ...form, severity: SEVERITIES.find((s) => s !== d.own_severity) ?? "LOW" });
        }
      }).catch(() => { if (mine === seq.current) setError("could not reach the dashboard server"); });
    }, 120);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form]);

  if (!available) return null;

  const open = (action: PolicyAction): void => {
    setMessage(null);
    setCopied(false);
    setDraft(null);
    setError(null);
    setForm({ action, severity: action === "severity" ? "" : "LOW", choiceAt: 0, value: null, here: false, scope: "machine" });
  };
  const set = (patch: Partial<Form>): void => {
    if (form) setForm({ ...form, ...patch });
  };

  const save = async (): Promise<void> => {
    if (!form || !draft?.entry) return;
    setBusy(true);
    const r = await post("/api/policy/save", request(form, draft.choices)).catch(() => null);
    setBusy(false);
    if (r?.ok) {
      setMessage("Saved to this machine's policy. It applies to new calls; the findings already listed here do not change.");
      setForm(null);
      setDraft(null);
    } else {
      setError(String(r?.json.error ?? "could not save"));
    }
  };

  const copy = async (): Promise<void> => {
    if (!draft?.command) return;
    try {
      await navigator.clipboard.writeText(draft.command);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const choices = draft?.choices ?? [];
  const chosen = choices[Math.min(form?.choiceAt ?? 0, Math.max(choices.length - 1, 0))];
  const blocked = draft?.save_blocked;

  return (
    <div className="fa" style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--navy-border)" }}>
      <h4 className="fa-title">Actions</h4>
      <div className="fa-buttons">
        {(Object.keys(LABEL) as PolicyAction[]).map((a) => (
          <button key={a} type="button" className={form?.action === a ? "fa-btn active" : "fa-btn"} onClick={() => open(a)}>
            {LABEL[a]}{a === "block" || a === "hold" ? <span className="fa-pro">Pro</span> : null}
          </button>
        ))}
      </div>

      {form && (
        <div className="fa-form">
          {form.action === "severity" && (
            <label className="fa-row">
              <span>New severity</span>
              <select value={form.severity} onChange={(e) => set({ severity: e.target.value })}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}{draft && s === draft.own_severity ? " (the rule's own)" : ""}</option>)}
              </select>
            </label>
          )}
          <label className="fa-row">
            <span>Applies to</span>
            <select value={form.choiceAt} onChange={(e) => set({ choiceAt: Number(e.target.value), value: null })}>
              {(choices.length ? choices : [{ kind: "rule", value: "" } as TargetChoice]).map((c, i) => (
                <option key={`${c.kind}-${i}`} value={i}>{TARGET_LABEL[c.kind]}{c.value ? `: ${c.value}` : ""}</option>
              ))}
            </select>
          </label>
          {chosen && chosen.kind !== "rule" && (
            <input
              aria-label="Target"
              className="fa-input"
              value={form.value ?? chosen.value}
              onChange={(e) => set({ value: e.target.value })}
            />
          )}
          <div className="fa-row">
            <span>Where</span>
            <label><input type="radio" checked={!form.here} onChange={() => set({ here: false })} /> Everywhere</label>
            {draft?.project && (
              <label><input type="radio" checked={form.here} onChange={() => set({ here: true })} /> Only in {draft.project}</label>
            )}
          </div>
          <div className="fa-row">
            <span>For</span>
            <label><input type="radio" checked={form.scope === "machine"} onChange={() => set({ scope: "machine" })} /> This machine</label>
            <label><input type="radio" checked={form.scope === "account"} onChange={() => set({ scope: "account" })} /> The whole account</label>
          </div>

          {error && <p role="alert" className="fa-error">{error}</p>}
          {draft?.entry && !error && (
            <>
              <p role="status" className="fa-note">{previewText(draft)}</p>

              {blocked === "account" && draft.hosted_url && (
                <p className="fa-note">
                  Entries for the whole account are made in the hosted dashboard, which is where the account's sign-in is. The entry
                  travels in the link's fragment, so it is not sent to any server.{" "}
                  <a href={draft.hosted_url} target="_blank" rel="noopener noreferrer" className="fa-link">Open the hosted Policies page</a>
                </p>
              )}
              {blocked === "loosens" && (
                <div className="fa-note">
                  <p>
                    Turning protection down is done in a terminal on this machine, where you type a confirmation. That keeps an agent from
                    doing it for you. Run:
                  </p>
                  <pre className="fa-command">{draft.command}</pre>
                  <button type="button" className="fa-btn" onClick={() => void copy()}>{copied ? "Copied" : "Copy command"}</button>
                </div>
              )}
              {blocked === "pro" && (
                <p className="fa-note">
                  Blocking and holding calls come with Omnodex Pro. Until then, shadow mode shows what they would have stopped. The same
                  command works once your plan includes it: <code>{draft.command}</code>
                </p>
              )}
              {blocked === "no-change" && <p className="fa-note">That would not change anything for this rule.</p>}
              {!blocked && (
                <button type="button" className="fa-btn primary" disabled={busy} onClick={() => void save()}>Save to this machine</button>
              )}{" "}
              <button type="button" className="fa-btn" onClick={() => { setForm(null); setDraft(null); }}>Cancel</button>
            </>
          )}
        </div>
      )}
      {message && <p role="status" className="fa-note">{message}</p>}
    </div>
  );
}
