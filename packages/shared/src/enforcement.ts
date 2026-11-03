// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Enforcement configuration: the shapes the CLI, the hook shims and the MCP
 * proxy read to decide whether a finding stops a tool call.
 *
 * Enforcement is a mode beside tracing. `monitor` records and never acts,
 * `shadow` records what it would have done, and `guardrails` acts. Which
 * verdict a rule gets resolves through overrides in the project's and the
 * user's configuration, most specific first (see the analyzer's
 * resolveVerdict). Omnodex never approves a call: a verdict either stops
 * it, asks for confirmation, or stays out of the way.
 *
 * This module holds types and a lenient parser only, no file access, so
 * every package can depend on it.
 */

import type { RiskSeverity } from "./index.js";

/**
 * The guardrails module interface this client speaks. A module declares the
 * version it implements; the cloud serves the newest module for the version
 * a client asks for, and the client refuses any other.
 */
export const GUARDRAILS_INTERFACE = 1;

/** Whether rules act on tool calls. `monitor` is the default. */
export type EnforcementMode = "monitor" | "shadow" | "guardrails";

export const ENFORCEMENT_MODES: readonly EnforcementMode[] = ["monitor", "shadow", "guardrails"];

/**
 * What a rule does to a matching call when enforcement acts.
 *
 * - "deny"       -- stop the call. The agent is told why and what to do instead.
 * - "confirm"    -- hold the call for the user. On hosts with no prompt the
 *                   hook can raise, the call is stopped with an instruction
 *                   to ask the user before retrying.
 * - "alert_only" -- record the finding and let the call run.
 */
export type BlockingVerdict = "deny" | "confirm" | "alert_only";

export const BLOCKING_VERDICTS: readonly BlockingVerdict[] = ["deny", "confirm", "alert_only"];

/**
 * A concrete, safer action the agent can take instead of the blocked one,
 * given in the block reason so the agent retries correctly rather than
 * stalling or asking the user what happened.
 */
export interface SafeAlternative {
  /** One-line instruction addressed to the agent, not the human. */
  suggestion: string;
  /** Literal replacement command or parameter set, when the rule can compute one. */
  replacement?: string;
}

/**
 * What an exception applies to. Exactly one field is set. Absent means the
 * whole rule.
 *
 * - path            -- a file or directory; a directory covers everything under it.
 * - destination     -- a host; it also covers that host's subdomains.
 * - command_prefix  -- the start of a command that runs, matched on whole words.
 */
export interface EnforcementTarget {
  path?: string;
  destination?: string;
  command_prefix?: string;
}

/**
 * A user's decision about one rule, optionally for one target.
 *
 * - "allow" -- the rule never stops a call on this target. Findings are still recorded.
 * - "mute"  -- as allow, and the finding is hidden from the default views.
 */
export interface EnforcementException {
  rule_id: string;
  kind: "allow" | "mute";
  target?: EnforcementTarget;
  /** Why the exception exists, in the user's words. */
  note?: string;
  /** When it was added, ISO 8601. */
  created_at?: string;
}

// ---------------------------------------------------------------------------
// Policy entries
// ---------------------------------------------------------------------------

/**
 * What a policy entry does to a matching call. "allow" lets it run, which is
 * the "alert_only" blocking verdict: the finding is still recorded.
 */
export type PolicyVerdict = "deny" | "confirm" | "allow";

export const POLICY_VERDICTS: readonly PolicyVerdict[] = ["deny", "confirm", "allow"];

/**
 * What a policy entry applies to within its rule, category or severity.
 * Absent means every call. Exactly one shape:
 *
 * - path            -- a file or directory; a directory covers everything under it. ~ is the home folder.
 * - destination     -- a host and its subdomains.
 * - command_prefix  -- the start of a command that runs, on whole words.
 * - credential      -- a short salted fingerprint of a credential value, as
 *                      the finding records it. Never the value.
 * - tool            -- a tool by name, optionally only on one MCP server.
 * - access          -- reads of, or writes to, a file or directory.
 */
export type PolicyTarget =
  | { path: string }
  | { destination: string }
  | { command_prefix: string }
  | { credential: string }
  | { tool: string; server?: string }
  | { access: "read" | "write"; path: string };

/**
 * Which findings an entry applies to. Exactly one of rule_id, category and
 * severity is set; severity matches the rule's own severity, before any
 * entry changes it.
 */
export interface PolicyMatch {
  rule_id?: string;
  category?: string;
  severity?: RiskSeverity;
  /** Only calls touching this. */
  target?: PolicyTarget;
  /** Only calls made under this project root. */
  project?: string;
}

/** What an entry changes. At least one field is set. */
export interface PolicyEffect {
  /** deny and confirm act only in guardrails. */
  verdict?: PolicyVerdict;
  /** The finding's effective severity, in place of the rule's. */
  severity?: RiskSeverity;
  /** Keep the finding out of default views, counts and notifications. */
  mute?: boolean;
}

/**
 * One decision a user made about findings like one in front of them: block
 * them, hold them, let them through, mute them or change their severity,
 * for a rule, a category or a severity, optionally for one target or one
 * project. See the analyzer's evaluatePolicy for how entries combine.
 */
export interface PolicyEntry {
  /** Stable, for edits and sync. */
  id: string;
  match: PolicyMatch;
  effect: PolicyEffect;
  /** Why the entry exists, in the user's words. */
  note?: string;
  /** When it was added, ISO 8601. Among equal entries, the most recent severity wins. */
  created_at?: string;
  /** Where it was written. "config" is an entry read from the older per-rule keys. */
  created_by?: "dashboard" | "cli" | "config";
}

/** The rule's blocking verdict for a policy verdict. */
export function blockingVerdict(v: PolicyVerdict): BlockingVerdict {
  return v === "allow" ? "alert_only" : v;
}

/** The policy verdict for a rule's blocking verdict. */
export function policyVerdict(v: BlockingVerdict): PolicyVerdict {
  return v === "alert_only" ? "allow" : v;
}

/**
 * The `enforcement` section of a configuration file. Every field is
 * optional; a project file usually sets only `rules` or `exceptions`.
 *
 * `policy` holds entries in the current shape. `rules`, `severity_defaults`,
 * `exceptions` and `projects` are the older keys: they are still read, and
 * policyEntries turns them into entries with the same effect.
 */
export interface EnforcementConfig {
  mode?: EnforcementMode;
  /**
   * What happens when the enforcement path itself fails (the rule set cannot
   * load, evaluation throws or runs out of time). "allow" lets the call run
   * and records the error. "block" stops it.
   */
  on_error?: "allow" | "block";
  /** A verdict for every rule of a severity, unless a per-rule override says otherwise. */
  severity_defaults?: Partial<Record<RiskSeverity, BlockingVerdict>>;
  /** Per-rule verdicts by rule id. */
  rules?: Record<string, BlockingVerdict>;
  exceptions?: EnforcementException[];
  /**
   * The user's overrides for one project, keyed by the project's absolute
   * root. Read from the user's own file only: a project's choices about
   * itself live with the user, not in the repository.
   */
  projects?: Record<string, EnforcementConfig>;
  /** Policy entries. Read from the top level of the user's file only. */
  policy?: PolicyEntry[];
}

/**
 * What enforcement made of a finding when it was captured, stamped on the
 * risk.detected event so it travels with the finding to the log, the live
 * relay, the sync payload and both dashboards. Absent in monitor mode, on
 * findings judged after the fact (the background pass), and on findings
 * recorded before enforcement existed.
 */
export interface FindingEnforcement {
  /** The mode in force when the finding was captured. */
  mode: Exclude<EnforcementMode, "monitor">;
  /** What the rule's own hint would do, whether or not it is in force. */
  candidate: BlockingVerdict;
  /** What the user's settings make of it: the verdict guardrails acts on. */
  action: BlockingVerdict;
  /** Whether the call was actually stopped or held. Only ever true in guardrails. */
  held: boolean;
  /** Which part of the precedence chain decided the action. */
  source: string;
  /** A mute exception matched: keep the finding out of default views. */
  muted?: boolean;
}

/** Whether a finding would have stopped or held its call: the shadow-mode question. */
export function wouldBlock(e: FindingEnforcement | undefined): boolean {
  return e !== undefined && !e.muted && (e.candidate !== "alert_only" || e.action !== "alert_only");
}

/** The shared policy file inside a repository: `<root>/.omnodex/config.json`. */
export const PROJECT_CONFIG_DIR = ".omnodex";
export const PROJECT_CONFIG_FILE = "config.json";

const SEVERITIES: readonly RiskSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function parseTarget(raw: unknown): EnforcementTarget | undefined | null {
  if (raw === undefined) return undefined;
  if (!isRecord(raw)) return null;
  const set = (["path", "destination", "command_prefix"] as const).filter((k) => nonEmpty(raw[k]));
  const [key] = set;
  if (set.length !== 1 || !key) return null;
  return { [key]: (raw[key] as string).trim() };
}

function parseException(raw: unknown): EnforcementException | null {
  if (!isRecord(raw) || !nonEmpty(raw.rule_id)) return null;
  if (raw.kind !== "allow" && raw.kind !== "mute") return null;
  const target = parseTarget(raw.target);
  if (target === null) return null;
  const out: EnforcementException = { rule_id: raw.rule_id, kind: raw.kind };
  if (target) out.target = target;
  if (typeof raw.note === "string") out.note = raw.note;
  if (typeof raw.created_at === "string") out.created_at = raw.created_at;
  return out;
}

/**
 * The enforcement section of a parsed configuration file. Unknown or
 * malformed entries are dropped one by one, so a typo in one override never
 * disables the rest, and anything that is not an object gives an empty config.
 */
export function parseEnforcementConfig(raw: unknown, nested = true): EnforcementConfig {
  if (!isRecord(raw)) return {};
  const out: EnforcementConfig = {};
  if (ENFORCEMENT_MODES.includes(raw.mode as EnforcementMode)) out.mode = raw.mode as EnforcementMode;
  if (raw.on_error === "allow" || raw.on_error === "block") out.on_error = raw.on_error;

  if (isRecord(raw.severity_defaults)) {
    const defaults: Partial<Record<RiskSeverity, BlockingVerdict>> = {};
    for (const sev of SEVERITIES) {
      const v = raw.severity_defaults[sev];
      if (BLOCKING_VERDICTS.includes(v as BlockingVerdict)) defaults[sev] = v as BlockingVerdict;
    }
    if (Object.keys(defaults).length > 0) out.severity_defaults = defaults;
  }

  if (isRecord(raw.rules)) {
    const rules: Record<string, BlockingVerdict> = {};
    for (const [id, v] of Object.entries(raw.rules)) {
      if (nonEmpty(id) && BLOCKING_VERDICTS.includes(v as BlockingVerdict)) rules[id] = v as BlockingVerdict;
    }
    if (Object.keys(rules).length > 0) out.rules = rules;
  }

  if (Array.isArray(raw.exceptions)) {
    const exceptions = raw.exceptions.map(parseException).filter((e): e is EnforcementException => e !== null);
    if (exceptions.length > 0) out.exceptions = exceptions;
  }

  if (nested && Array.isArray(raw.policy)) {
    const policy = parsePolicy(raw.policy);
    if (policy.length > 0) out.policy = policy;
  }

  if (nested && isRecord(raw.projects)) {
    const projects: Record<string, EnforcementConfig> = {};
    for (const [root, section] of Object.entries(raw.projects)) {
      if (!nonEmpty(root)) continue;
      const parsed = parseEnforcementConfig(section, false);
      delete parsed.mode;
      if (Object.keys(parsed).length > 0) projects[root] = parsed;
    }
    if (Object.keys(projects).length > 0) out.projects = projects;
  }
  return out;
}

/**
 * The section a repository's shared policy file may set: per-rule and
 * severity verdicts, and policy entries that can only tighten (a deny or
 * confirm verdict, a severity, which applies only when it is higher). Everything
 * that could loosen protection (mode, on_error, exceptions, allow and mute
 * effects, per-project sections) is dropped.
 */
export function parseRepoEnforcementConfig(raw: unknown): EnforcementConfig {
  const { rules, severity_defaults } = parseEnforcementConfig(raw, false);
  const policy = isRecord(raw) && Array.isArray(raw.policy)
    ? parsePolicy(raw.policy).flatMap((e): PolicyEntry[] => {
        const effect: PolicyEffect = {};
        if (e.effect.verdict === "deny" || e.effect.verdict === "confirm") effect.verdict = e.effect.verdict;
        if (e.effect.severity) effect.severity = e.effect.severity;
        if (Object.keys(effect).length === 0) return [];
        const { project: _, ...match } = e.match;
        return [{ ...e, match, effect }];
      })
    : [];
  return {
    ...(rules ? { rules } : {}),
    ...(severity_defaults ? { severity_defaults } : {}),
    ...(policy.length > 0 ? { policy } : {}),
  };
}

function parsePolicyTarget(raw: unknown): PolicyTarget | undefined | null {
  if (raw === undefined) return undefined;
  if (!isRecord(raw)) return null;
  const keys = Object.keys(raw).filter((k) => raw[k] !== undefined);
  const only = (...allowed: string[]): boolean => keys.every((k) => allowed.includes(k));
  if ("access" in raw) {
    if ((raw.access !== "read" && raw.access !== "write") || !nonEmpty(raw.path) || !only("access", "path")) return null;
    return { access: raw.access, path: raw.path.trim() };
  }
  if ("tool" in raw) {
    if (!nonEmpty(raw.tool) || !only("tool", "server")) return null;
    if (raw.server !== undefined && !nonEmpty(raw.server)) return null;
    return { tool: raw.tool.trim(), ...(nonEmpty(raw.server) ? { server: raw.server.trim() } : {}) };
  }
  if (keys.length !== 1) return null;
  const [key] = keys;
  if (key !== "path" && key !== "destination" && key !== "command_prefix" && key !== "credential") return null;
  const value = raw[key];
  if (!nonEmpty(value)) return null;
  return { [key]: value.trim() } as PolicyTarget;
}

/** One policy entry, or null when it is malformed or does nothing. */
export function parsePolicyEntry(raw: unknown): PolicyEntry | null {
  if (!isRecord(raw) || !nonEmpty(raw.id) || !isRecord(raw.match) || !isRecord(raw.effect)) return null;
  const m = raw.match;
  const kinds = [nonEmpty(m.rule_id), nonEmpty(m.category), SEVERITIES.includes(m.severity as RiskSeverity)];
  if (kinds.filter(Boolean).length !== 1) return null;
  for (const [key, ok] of [["rule_id", kinds[0]], ["category", kinds[1]], ["severity", kinds[2]]] as const) {
    if (m[key] !== undefined && !ok) return null;
  }
  const target = parsePolicyTarget(m.target);
  if (target === null) return null;
  if (m.project !== undefined && !nonEmpty(m.project)) return null;
  const match: PolicyMatch = {};
  if (kinds[0]) match.rule_id = m.rule_id as string;
  if (kinds[1]) match.category = m.category as string;
  if (kinds[2]) match.severity = m.severity as RiskSeverity;
  if (target) match.target = target;
  if (nonEmpty(m.project)) match.project = m.project;

  const f = raw.effect;
  const effect: PolicyEffect = {};
  if (f.verdict !== undefined) {
    if (!POLICY_VERDICTS.includes(f.verdict as PolicyVerdict)) return null;
    effect.verdict = f.verdict as PolicyVerdict;
  }
  if (f.severity !== undefined) {
    if (!SEVERITIES.includes(f.severity as RiskSeverity)) return null;
    effect.severity = f.severity as RiskSeverity;
  }
  if (f.mute !== undefined) {
    if (typeof f.mute !== "boolean") return null;
    effect.mute = f.mute;
  }
  if (Object.keys(effect).length === 0) return null;

  const out: PolicyEntry = { id: raw.id, match, effect };
  if (typeof raw.note === "string") out.note = raw.note;
  if (typeof raw.created_at === "string") out.created_at = raw.created_at;
  if (raw.created_by === "dashboard" || raw.created_by === "cli" || raw.created_by === "config") out.created_by = raw.created_by;
  return out;
}

/**
 * A list of policy entries. Malformed entries are dropped one by one, as are
 * later entries reusing an id.
 */
export function parsePolicy(raw: unknown): PolicyEntry[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: PolicyEntry[] = [];
  for (const item of raw) {
    const entry = parsePolicyEntry(item);
    if (!entry || seen.has(entry.id)) continue;
    seen.add(entry.id);
    out.push(entry);
  }
  return out;
}

function targetKey(t: EnforcementTarget | undefined): string {
  if (!t) return "any";
  const [key] = Object.keys(t) as (keyof EnforcementTarget)[];
  return key ? `${key}=${t[key]}` : "any";
}

/**
 * Every decision in a configuration section, as policy entries: its
 * `policy` list, and its older keys (`rules`, `severity_defaults`,
 * `exceptions` and the user's per-project sections) turned into entries
 * with the same effect. The older keys are never rewritten or dropped; this
 * is how they are read.
 *
 * Entries for a per-project section are scoped to its root. `project`
 * scopes the section itself, for a section already chosen for one project.
 *
 * One older behavior needs care: an exception beat a per-rule verdict in the
 * same section, where entries at the same level take the stricter verdict.
 * So a rule's verdict is left out of the entries when the same section has
 * an exception covering the whole rule.
 */
export function policyEntries(config: EnforcementConfig, project?: string): PolicyEntry[] {
  const out: PolicyEntry[] = [];
  const scope = project !== undefined ? { project } : {};
  const prefix = project !== undefined ? `config:project:${project}:` : "config:";
  const wholeRule = new Set((config.exceptions ?? []).filter((e) => !e.target).map((e) => e.rule_id));

  for (const [rule_id, verdict] of Object.entries(config.rules ?? {})) {
    if (wholeRule.has(rule_id)) continue;
    out.push({
      id: `${prefix}rule:${rule_id}`,
      match: { rule_id, ...scope },
      effect: { verdict: policyVerdict(verdict) },
      created_by: "config",
    });
  }
  for (const sev of SEVERITIES) {
    const verdict = config.severity_defaults?.[sev];
    if (!verdict) continue;
    out.push({
      id: `${prefix}severity:${sev}`,
      match: { severity: sev, ...scope },
      effect: { verdict: policyVerdict(verdict) },
      created_by: "config",
    });
  }
  for (const e of config.exceptions ?? []) {
    const entry: PolicyEntry = {
      id: `${prefix}exception:${e.rule_id}:${e.kind}:${targetKey(e.target)}`,
      match: { rule_id: e.rule_id, ...(e.target ? { target: { ...e.target } as PolicyTarget } : {}), ...scope },
      effect: e.kind === "mute" ? { verdict: "allow", mute: true } : { verdict: "allow" },
      created_by: "config",
    };
    if (e.note !== undefined) entry.note = e.note;
    if (e.created_at !== undefined) entry.created_at = e.created_at;
    out.push(entry);
  }
  if (project === undefined) {
    for (const [root, section] of Object.entries(config.projects ?? {})) out.push(...policyEntries(section, root));
  }
  // Explicit entries take a scope only from their own match.
  out.push(...(config.policy ?? []));
  return out;
}
