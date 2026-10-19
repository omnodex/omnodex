// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * sequence condition evaluator.
 *
 * Two forms. With `prior`, it matches when an earlier tool.invoked event in
 * the same session, within the condition's bounds, satisfied every one of
 * the prior conditions: "this event, after that one". It yields one context
 * citing the most recent qualifying earlier event as the chain's source.
 *
 * With `steps`, it matches an ordered chain: each step by a later event
 * than the one before, the last step by the current event. A step can bind
 * values (the file it read, the file it staged, the credentials it named)
 * and a later step can require that it carries one of them, used in a given
 * way. Of the chains that match, the one whose steps are most recent wins.
 *
 * The window of earlier events is kept by the engine and supplied here.
 * Step conditions must be stateless (checked when rules are classified),
 * because they are re-evaluated against events that have already passed.
 */

import type { EvidenceCredential, ToolInvokedEvent } from "@omnodex/shared";
import { credentialRole, isCredentialProvider, normalizeAction, type CredentialRole } from "../action.js";
import { evidenceDestination } from "../evidence.js";
import type {
  Condition,
  MatchContext,
  SequenceBinding,
  SequenceCondition,
  SequenceStep,
  SequenceStepMatch,
} from "../types.js";

/** Evaluates one stateless condition against one event. */
export type StatelessConditionFn = (
  condition: Condition,
  event: ToolInvokedEvent,
) => Partial<MatchContext>[];

/** Chains tried per event and rule before giving up; bounds a pathological window. */
const MAX_CHAINS = 2000;

export function evaluateSequence(
  condition: SequenceCondition,
  event: ToolInvokedEvent,
  window: readonly ToolInvokedEvent[],
  evaluate: StatelessConditionFn,
  home?: string,
): Partial<MatchContext>[] {
  const start = windowStart(condition, event, window);
  if (condition.steps) return evaluateSteps(condition.steps, event, window, start, evaluate, home);

  // Most recent first, so the finding cites the nearest earlier step.
  for (let i = window.length - 1; i >= start; i--) {
    const context = matchAll(condition.prior ?? [], window[i]!, evaluate);
    if (context) return [{ sequence_steps: [{ event: window[i]!, role: "source", context }] }];
  }
  return [];
}

/** The first window index inside the condition's event and time bounds. */
function windowStart(condition: SequenceCondition, event: ToolInvokedEvent, window: readonly ToolInvokedEvent[]): number {
  const limit = condition.within_events ?? window.length;
  let start = Math.max(0, window.length - limit);
  if (condition.within_seconds !== undefined) {
    const now = Date.parse(event.occurred_at);
    for (let i = window.length - 1; i >= start; i--) {
      const age = (now - Date.parse(window[i]!.occurred_at)) / 1000;
      if (!(age <= condition.within_seconds)) return i + 1;
    }
  }
  return start;
}

/**
 * The first context of each condition merged, when every condition matches
 * the event; null otherwise. Kept so the evidence can say what matched on
 * the earlier call (the sensitive path's label, say).
 */
function matchAll(
  conditions: readonly Condition[],
  event: ToolInvokedEvent,
  evaluate: StatelessConditionFn,
): Partial<MatchContext> | null {
  let merged: Partial<MatchContext> = {};
  for (const c of conditions) {
    const hit = evaluate(c, event);
    if (hit.length === 0) return null;
    merged = { ...merged, ...hit[0] };
  }
  return merged;
}

// ---------------------------------------------------------------------------
// The steps form
// ---------------------------------------------------------------------------

/** Values bound so far in a chain, by key, with what each came from. */
interface Bound {
  values: Map<SequenceBinding, Set<string>>;
  /** Credential types bound, and whether each came from a file read. */
  credentialTypes: Map<string, "file-read" | "param-pattern">;
}

interface Carried {
  key: SequenceBinding;
  role?: CredentialRole;
}

function evaluateSteps(
  steps: readonly SequenceStep[],
  event: ToolInvokedEvent,
  window: readonly ToolInvokedEvent[],
  start: number,
  evaluate: StatelessConditionFn,
  home: string | undefined,
): Partial<MatchContext>[] {
  const last = steps[steps.length - 1];
  if (!last) return [];
  const lastContext = matchAll(last.match, event, evaluate);
  if (!lastContext) return [];
  const earlier = steps.slice(0, -1);
  if (earlier.length === 0) return [];

  // Which window events match each earlier step, computed once per event.
  const cache = new Map<string, Partial<MatchContext> | null>();
  const matchStep = (k: number, i: number): Partial<MatchContext> | null => {
    const key = `${k}:${i}`;
    if (!cache.has(key)) cache.set(key, matchAll(earlier[k]!.match, window[i]!, evaluate));
    return cache.get(key)!;
  };

  // Assign window indices to steps from the last earlier step back, newest
  // first, so the first complete chain is the most recent one. Bindings run
  // forward, so a chain is checked once every step has an event.
  const chosen: (number | null)[] = new Array(earlier.length).fill(null);
  let tried = 0;
  let result: Partial<MatchContext> | null = null;

  const check = (): Partial<MatchContext> | null => {
    const bound: Bound = { values: new Map(), credentialTypes: new Map() };
    const matched: SequenceStepMatch[] = [];
    for (let k = 0; k < earlier.length; k++) {
      const i = chosen[k];
      if (i === null || i === undefined) continue;
      const step = earlier[k]!;
      const e = window[i]!;
      const context = matchStep(k, i)!;
      if (!satisfies(step, e, bound, home)) return null;
      bind(step, e, context, bound);
      matched.push({ event: e, role: step.as, context });
    }
    if (matched.length === 0) return null;
    const carried = satisfies(last, event, bound, home);
    if (!carried) return null;
    const credential = chainCredential(bound, carried);
    return {
      ...lastContext,
      sequence_steps: matched,
      sequence_role: last.as,
      ...(credential ? { sequence_credential: credential } : {}),
    };
  };

  const assign = (k: number, before: number): boolean => {
    if (++tried > MAX_CHAINS) return true;
    if (k < 0) {
      result = check();
      return result !== null;
    }
    for (let i = before - 1; i >= start; i--) {
      if (!matchStep(k, i)) continue;
      chosen[k] = i;
      if (assign(k - 1, i)) return true;
    }
    if (earlier[k]!.optional) {
      chosen[k] = null;
      if (assign(k - 1, before)) return true;
    }
    chosen[k] = null;
    return false;
  };

  assign(earlier.length - 1, window.length);
  return result ? [result] : [];
}

/** Record the values a step binds for later steps. */
function bind(step: SequenceStep, event: ToolInvokedEvent, context: Partial<MatchContext>, bound: Bound): void {
  const action = normalizeAction(event);
  const add = (key: SequenceBinding, values: Iterable<string>): void => {
    const set = bound.values.get(key) ?? new Set<string>();
    for (const v of values) if (v) set.add(v);
    bound.values.set(key, set);
  };
  for (const key of step.bind ?? []) {
    if (key === "path") add(key, context.matched_path ? [context.matched_path] : action.paths);
    if (key === "output") {
      add(key, context.staging_output
        ? [context.staging_output]
        : [...action.staging.map((s) => s.output ?? ""), ...action.writes]);
    }
    if (key === "credential") {
      add(key, (context.credential_sightings ?? []).map((c) => c.value));
      for (const c of context.credential_sightings ?? []) {
        if (!bound.credentialTypes.has(c.type)) bound.credentialTypes.set(c.type, "param-pattern");
      }
      if (context.path_credential_type) bound.credentialTypes.set(context.path_credential_type, "file-read");
    }
  }
}

/**
 * Whether a step's call meets its carries and provider requirements, given
 * what earlier steps bound. Returns what it carried (an empty list when it
 * has nothing to carry), or null when it fails.
 */
function satisfies(step: SequenceStep, event: ToolInvokedEvent, bound: Bound, home: string | undefined): Carried[] | null {
  if (step.exclude_credential_provider && bound.credentialTypes.size > 0) {
    const host = evidenceDestination(event)?.host;
    if (host && [...bound.credentialTypes.keys()].some((t) => isCredentialProvider(t, host))) return null;
  }
  if (!step.carries?.length) return [];

  const action = normalizeAction(event);
  const text = action.command ?? JSON.stringify(event.parameters ?? {});
  const carried: Carried[] = [];
  for (const key of step.carries) {
    for (const value of bound.values.get(key) ?? []) {
      const form = spellings(value, home).find((v) => text.includes(v));
      if (!form) continue;
      const role = credentialRole(event, form);
      if (step.carried_as && !(role && step.carried_as.includes(role))) continue;
      carried.push({ key, ...(role ? { role } : {}) });
    }
  }
  return carried.length > 0 ? carried : null;
}

/** The ways a path can be written in a later command: as given, and with ~ for home. */
function spellings(value: string, home: string | undefined): string[] {
  const out = [value];
  if (home) {
    const h = home.replace(/[\\/]+$/, "");
    if (value.startsWith(`${h}/`) || value.startsWith(`${h}\\`)) out.push(`~${value.slice(h.length)}`);
    if (value.startsWith("~/") || value.startsWith("~\\")) out.push(`${h}${value.slice(1)}`);
  }
  return out;
}

/** The credential the chain is about, by kind, and how the sink used what it carried. */
function chainCredential(bound: Bound, carried: Carried[]): EvidenceCredential | undefined {
  const [type, source] = [...bound.credentialTypes.entries()][0] ?? [];
  if (!type || !source) return undefined;
  const role = (carried.find((c) => c.key === "credential") ?? carried[0])?.role;
  return { class: type, source, ...(role ? { role } : {}) };
}
