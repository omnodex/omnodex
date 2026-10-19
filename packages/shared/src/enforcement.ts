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

/**
 * The `enforcement` section of a configuration file. Every field is
 * optional; a project file usually sets only `rules` or `exceptions`.
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
 * severity verdicts only. Everything that could loosen protection (mode,
 * on_error, exceptions, per-project sections) is dropped.
 */
export function parseRepoEnforcementConfig(raw: unknown): EnforcementConfig {
  const { rules, severity_defaults } = parseEnforcementConfig(raw, false);
  return { ...(rules ? { rules } : {}), ...(severity_defaults ? { severity_defaults } : {}) };
}
