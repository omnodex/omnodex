// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Policy entries applied to one finding: which verdict, severity and mute
 * the user's entries give it.
 *
 * Pure code over a finding, its call and the entries, with no file or
 * platform access, so a dashboard can apply the same entries to findings it
 * shows as a capture path applies them to a call it is about to let run.
 *
 * Each effect (verdict, severity, mute) is decided on its own, by the most
 * specific entry that sets it. Most specific means, in order:
 *
 *   1. An entry with a target beats one without.
 *   2. A rule beats a category, which beats a severity.
 *   3. An entry for a project beats one for everywhere, and a deeper project
 *      root beats the one containing it.
 *   4. The machine's own entries beat the account's.
 *
 * Between entries equally specific, the stricter verdict wins, the most
 * recent severity wins, and not muting wins.
 *
 * Entries from a repository's own policy file only tighten: their verdict
 * applies when it is stricter than the result, unless the user's own entry
 * allowed the call, and their severity when it is higher.
 *
 * Whether a target matches depends on which way the effect goes. An effect
 * that loosens (allow, mute, a lower severity) needs everything of the
 * target's kind on the call covered: allowing one path never allows a call
 * that also touches another, and allowing `npm test` never allows
 * `npm test && curl ...`. An effect that tightens (deny, confirm, a higher
 * severity) needs only one: blocking writes to a file blocks a call that
 * writes it and others too.
 */

import {
  blockingVerdict,
  type BlockingVerdict,
  type PolicyEntry,
  type PolicyTarget,
  type RiskSeverity,
  type ToolInvokedEvent,
} from "@omnodex/shared";
import { normalizeAction, shellSegments, shellWords } from "./action.js";

/** Where an entry came from. */
export type PolicyLayer = "machine" | "account" | "repo";

/** The parts of a finding the entries match on. */
export interface PolicyFinding {
  rule_id: string;
  category?: string;
  /** The rule's own severity, before any entry changes it. */
  severity: RiskSeverity;
  credential_fingerprints?: readonly string[];
}

export interface PolicyInput {
  finding: PolicyFinding;
  /** The call the finding is about. Without it, only entries without a target, or with a credential target, can match. */
  call?: ToolInvokedEvent;
  /** Entries kept on this machine. */
  machine?: readonly PolicyEntry[];
  /** Entries for the whole account, as last pulled. */
  account?: readonly PolicyEntry[];
  /** Entries from the repository's own policy file: tighten only. */
  repo?: readonly PolicyEntry[];
  /** Project roots the call is known to be in, beside its working directory. */
  projectRoots?: readonly string[];
  /** The user's home folder, for ~ in paths. */
  home?: string;
  /** The verdict when no entry sets one, usually from the rule's own hint. */
  defaultVerdict?: BlockingVerdict;
}

/** The entry that decided an effect, and its layer. */
export interface PolicyDecision {
  entry: PolicyEntry;
  layer: PolicyLayer;
  /** "<layer or scope>-<kind>", for status output and the finding's record. */
  source: string;
}

export interface PolicyResult {
  /** What enforcement does to the call. */
  verdict: BlockingVerdict;
  /** The finding's effective severity. */
  severity: RiskSeverity;
  muted: boolean;
  /** The entries that decided each effect. Absent when no entry did. */
  decided: {
    verdict?: PolicyDecision;
    severity?: PolicyDecision;
    mute?: PolicyDecision;
  };
}

const STRENGTH: Readonly<Record<BlockingVerdict, number>> = { alert_only: 0, confirm: 1, deny: 2 };
const SEVERITY_RANK: Readonly<Record<RiskSeverity, number>> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

type Mode = "all" | "any";
type Effect = "verdict" | "severity" | "mute";

interface Candidate {
  entry: PolicyEntry;
  layer: PolicyLayer;
  index: number;
  key: number[];
}

export function evaluatePolicy(input: PolicyInput): PolicyResult {
  const { finding } = input;
  const roots = projectRoots(input);
  const layers: [PolicyLayer, readonly PolicyEntry[] | undefined][] = [
    ["machine", input.machine],
    ["account", input.account],
  ];

  const result: PolicyResult = {
    verdict: input.defaultVerdict ?? "alert_only",
    severity: finding.severity,
    muted: false,
    decided: {},
  };

  for (const effect of ["verdict", "severity", "mute"] as const) {
    const candidates: Candidate[] = [];
    let index = 0;
    for (const [layer, entries] of layers) {
      for (const entry of entries ?? []) {
        index++;
        if (entry.effect[effect] === undefined) continue;
        if (!entryMatches(entry, input, roots, modeFor(entry, effect, finding.severity))) continue;
        candidates.push({ entry, layer, index, key: specificity(entry, layer, input.home) });
      }
    }
    const best = pickBest(candidates, effect);
    if (!best) continue;
    const mode = modeFor(best.entry, effect, finding.severity);
    const decision = { entry: best.entry, layer: best.layer, source: sourceOf(best.entry, best.layer, mode) };
    if (effect === "verdict") result.verdict = blockingVerdict(best.entry.effect.verdict!);
    if (effect === "severity") result.severity = best.entry.effect.severity!;
    if (effect === "mute") result.muted = best.entry.effect.mute!;
    result.decided[effect] = decision;
  }

  // The repository's entries, only where they tighten, and never over the
  // user's own decision to let calls like this through.
  const userAllowed = result.decided.verdict?.entry.effect.verdict === "allow";
  for (const entry of input.repo ?? []) {
    const v = entry.effect.verdict;
    if ((v === "deny" || v === "confirm") && !userAllowed) {
      if (STRENGTH[v] > STRENGTH[result.verdict] && entryMatches(entry, input, roots, "any")) {
        result.verdict = v;
        result.decided.verdict = { entry, layer: "repo", source: sourceOf(entry, "repo", "any") };
      }
    }
    const s = entry.effect.severity;
    if (s && SEVERITY_RANK[s] > SEVERITY_RANK[result.severity] && entryMatches(entry, input, roots, "any")) {
      result.severity = s;
      result.decided.severity = { entry, layer: "repo", source: sourceOf(entry, "repo", "any") };
    }
  }
  return result;
}

/** Whether an effect loosens, which decides how much of a target must match. */
function modeFor(entry: PolicyEntry, effect: Effect, recommended: RiskSeverity): Mode {
  if (effect === "verdict") return entry.effect.verdict === "allow" ? "all" : "any";
  if (effect === "severity") return SEVERITY_RANK[entry.effect.severity!] > SEVERITY_RANK[recommended] ? "any" : "all";
  return entry.effect.mute ? "all" : "any";
}

function specificity(entry: PolicyEntry, layer: PolicyLayer, home: string | undefined): number[] {
  const m = entry.match;
  const kind = m.rule_id !== undefined ? 2 : m.category !== undefined ? 1 : 0;
  const project = m.project !== undefined ? normalizePath(m.project, undefined, home) : null;
  return [m.target ? 1 : 0, kind, project !== null ? 1 : 0, project?.length ?? 0, layer === "machine" ? 1 : 0];
}

function compareKeys(a: number[], b: number[]): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

function pickBest(candidates: Candidate[], effect: Effect): Candidate | undefined {
  let best: Candidate | undefined;
  for (const c of candidates) {
    if (!best) {
      best = c;
      continue;
    }
    const cmp = compareKeys(c.key, best.key);
    if (cmp > 0 || (cmp === 0 && winsTie(c, best, effect))) best = c;
  }
  return best;
}

/** Between equally specific entries: the stricter verdict, the most recent severity, not muting. */
function winsTie(c: Candidate, best: Candidate, effect: Effect): boolean {
  if (effect === "verdict") {
    return STRENGTH[blockingVerdict(c.entry.effect.verdict!)] > STRENGTH[blockingVerdict(best.entry.effect.verdict!)];
  }
  if (effect === "severity") {
    const a = c.entry.created_at ?? "";
    const b = best.entry.created_at ?? "";
    return a > b || (a === b && c.index > best.index);
  }
  return best.entry.effect.mute === true && c.entry.effect.mute === false;
}

/** "<scope>-<kind>": a target that loosens is an exception, one that tightens a target. */
function sourceOf(entry: PolicyEntry, layer: PolicyLayer, mode: Mode): string {
  const m = entry.match;
  const scope = layer === "machine" ? (m.project !== undefined ? "project" : "user") : layer;
  let kind: string;
  if (m.target) {
    kind = mode === "all" ? "exception" : "target";
  } else {
    kind = m.rule_id !== undefined ? "rule" : m.category !== undefined ? "category" : "severity";
  }
  return `${scope}-${kind}`;
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

function projectRoots(input: PolicyInput): string[] {
  const roots = (input.projectRoots ?? []).map((r) => normalizePath(r, undefined, input.home));
  if (input.call?.cwd) roots.push(normalizePath(input.call.cwd, undefined, input.home));
  return roots;
}

function entryMatches(entry: PolicyEntry, input: PolicyInput, roots: readonly string[], mode: Mode): boolean {
  const { finding } = input;
  const m = entry.match;
  if (m.rule_id !== undefined && m.rule_id !== finding.rule_id) return false;
  if (m.category !== undefined && m.category !== finding.category) return false;
  if (m.severity !== undefined && m.severity !== finding.severity) return false;
  if (m.project !== undefined) {
    const root = normalizePath(m.project, undefined, input.home);
    if (!roots.some((r) => pathUnder(r, root))) return false;
  }
  if (!m.target) return true;
  return targetMatches(m.target, { call: input.call, finding }, mode, {
    base: m.project !== undefined && isAbsolute(m.project) ? m.project : undefined,
    home: input.home,
  });
}

export interface TargetSubject {
  call?: ToolInvokedEvent;
  finding?: Pick<PolicyFinding, "credential_fingerprints">;
}

export interface TargetOptions {
  /** The folder relative target paths resolve against. Defaults to the call's working directory. */
  base?: string;
  /** The user's home folder, for ~. */
  home?: string;
}

/**
 * Whether a target matches a call (or, for a credential, the finding).
 * "all": everything of the target's kind on the call is covered by it, and
 * there is at least one. "any": at least one thing is.
 */
export function targetMatches(target: PolicyTarget, subject: TargetSubject, mode: Mode, opts: TargetOptions = {}): boolean {
  if ("credential" in target) {
    const fps = subject.finding?.credential_fingerprints ?? [];
    return mode === "all" ? fps.length > 0 && fps.every((f) => f === target.credential) : fps.includes(target.credential);
  }
  const call = subject.call;
  if (!call) return false;
  if ("tool" in target) {
    return call.tool_name === target.tool && (target.server === undefined || call.mcp_server === target.server);
  }
  const action = normalizeAction(call);
  const resolve = (p: string, base: string | undefined): string => normalizePath(p, base, opts.home);
  const some = mode === "any";

  if ("access" in target) {
    const root = resolve(target.path, opts.base ?? call.cwd);
    const writes = action.writes.map((p) => resolve(p, call.cwd));
    if (target.access === "write") {
      if (some) return writes.some((p) => pathUnder(p, root));
      const touched = [...action.paths, ...action.writes].map((p) => resolve(p, call.cwd));
      return writes.length > 0 && touched.every((p) => pathUnder(p, root));
    }
    const reads = action.paths.filter((p) => !action.writes.includes(p)).map((p) => resolve(p, call.cwd));
    if (some) return reads.some((p) => pathUnder(p, root));
    return writes.length === 0 && reads.length > 0 && reads.every((p) => pathUnder(p, root));
  }
  if ("path" in target) {
    const root = resolve(target.path, opts.base ?? call.cwd);
    const paths = [...new Set([...action.paths, ...action.writes])].map((p) => resolve(p, call.cwd));
    return some ? paths.some((p) => pathUnder(p, root)) : paths.length > 0 && paths.every((p) => pathUnder(p, root));
  }
  if ("destination" in target) {
    const host = target.destination.toLowerCase().replace(/\.$/, "");
    const hosts = action.destinations.map((d) => d.host);
    const covered = (h: string): boolean => h === host || h.endsWith(`.${host}`);
    return some ? hosts.some(covered) : hosts.length > 0 && hosts.every(covered);
  }
  if ("command_prefix" in target) {
    const prefix = shellWords(target.command_prefix);
    if (prefix.length === 0 || action.exec === null) return false;
    const segments = shellSegments(action.exec).map(shellWords).filter((w) => w.length > 0);
    const starts = (words: string[]): boolean => prefix.every((w, i) => words[i] === w);
    if (some) return segments.some(starts);
    // Command substitution runs something the prefix does not name.
    if (/\$\(|`|<\(|>\(/.test(action.exec)) return false;
    return segments.length > 0 && segments.every(starts);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Paths, without the platform's path module
// ---------------------------------------------------------------------------

function isAbsolute(p: string): boolean {
  return /^(?:[A-Za-z]:)?[\\/]/.test(p) || p === "~" || /^~[\\/]/.test(p);
}

/**
 * An absolute, normalized path with forward slashes and no trailing slash.
 * A leading ~ is the home folder, as in a shell. Windows drive paths are
 * lower-cased, so they compare without regard to case.
 */
export function normalizePath(p: string, base: string | undefined, home: string | undefined): string {
  const expanded = home !== undefined && (p === "~" || /^~[\\/]/.test(p)) ? home + p.slice(1) : p;
  const slashed = expanded.replace(/\\/g, "/");
  const joined = /^(?:[A-Za-z]:)?\//.test(slashed) || !base ? slashed : `${base.replace(/\\/g, "/")}/${slashed}`;
  const m = /^([A-Za-z]:)?(\/?)(.*)$/s.exec(joined)!;
  const drive = m[1] ?? "";
  const rooted = m[2] === "/";
  const parts: string[] = [];
  for (const seg of m[3]!.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (parts.length > 0 && parts[parts.length - 1] !== "..") parts.pop();
      else if (!rooted) parts.push("..");
      continue;
    }
    parts.push(seg);
  }
  const out = drive + (rooted ? "/" : "") + parts.join("/");
  const normalized = out === "" ? "." : out;
  return drive ? normalized.toLowerCase() : normalized;
}

function pathUnder(p: string, root: string): boolean {
  return p === root || p.startsWith(root.endsWith("/") ? root : `${root}/`);
}
