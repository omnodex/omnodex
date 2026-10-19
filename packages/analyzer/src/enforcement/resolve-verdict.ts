// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Which verdict a finding gets: the precedence chain from a user's and a
 * project's overrides down to the rule's own hint.
 *
 * Most specific wins:
 *
 *   1. An allow or mute exception matching the rule and the call's target
 *      (user scope for this project, then user scope everywhere)
 *   2. A per-rule verdict for this project, then everywhere
 *   3. A verdict for the rule's severity, for this project, then everywhere
 *   4. The rule's blocking_hint, once the rule carries a safe_alternative
 *   5. alert_only
 *
 * A shared policy file in the repository (`.omnodex/config.json`) can only
 * tighten: its per-rule and severity verdicts apply when they are stricter
 * than what the chain gives, and it cannot add exceptions. A repository is
 * content the agent works on and may not be the user's own, so it must not
 * be able to switch protection off.
 *
 * The verdict also carries the candidate: what the rule's hint would do if
 * it were in force. Shadow mode records candidates, which is how a rule
 * earns a safe_alternative and a default hint.
 */

import os from "node:os";
import path from "node:path";
import type {
  BlockingVerdict,
  EnforcementConfig,
  EnforcementException,
  EnforcementTarget,
  RiskSeverity,
  SafeAlternative,
  ToolInvokedEvent,
} from "@omnodex/shared";
import { normalizeAction, shellSegments, shellWords } from "../action.js";

/** Where a verdict came from, for status output and the would-block record. */
export type VerdictSource =
  | "project-exception"
  | "user-exception"
  | "project-rule"
  | "user-rule"
  | "repo-rule"
  | "project-severity"
  | "user-severity"
  | "repo-severity"
  | "rule-hint"
  | "default";

export interface Verdict {
  rule_id: string;
  /** What enforcement does to the call. */
  action: BlockingVerdict;
  /** What the rule's hint would do if it were in force, for shadow mode. */
  candidate: BlockingVerdict;
  source: VerdictSource;
  /** Set when a mute exception matched: the finding stays out of default views. */
  muted: boolean;
  /** The exception that matched, for sources ending in "-exception". */
  exception?: EnforcementException;
  safe_alternative?: SafeAlternative;
  /** The finding's description, carried through for the block reason. */
  description?: string;
}

/** The parts of a rule definition the chain reads. */
export interface VerdictRule {
  rule_id: string;
  severity: RiskSeverity;
  blocking_hint?: BlockingVerdict;
  safe_alternative?: SafeAlternative;
}

/**
 * The configuration the chain reads, already loaded.
 *
 * `user` is the user's enforcement section; `userProject` is the section the
 * user keeps for the project this call is in (also in the user's file).
 * `repo` is the shared policy file in the repository, which can only tighten.
 */
export interface VerdictConfig {
  user?: EnforcementConfig;
  userProject?: EnforcementConfig;
  repo?: EnforcementConfig;
  /** The project root, for exception paths given relative to it. */
  projectRoot?: string;
}

export interface ResolveVerdictInput {
  rule: VerdictRule;
  /** The call the finding is about. Without it, only exceptions with no target can match. */
  call?: ToolInvokedEvent;
  config?: VerdictConfig;
  description?: string;
}

const STRENGTH: Readonly<Record<BlockingVerdict, number>> = { alert_only: 0, confirm: 1, deny: 2 };

/** The stricter of two verdicts. */
export function stricter(a: BlockingVerdict, b: BlockingVerdict): BlockingVerdict {
  return STRENGTH[b] > STRENGTH[a] ? b : a;
}

/** Whether a verdict holds the call (deny or confirm). */
export function blocks(v: BlockingVerdict): boolean {
  return v !== "alert_only";
}

export function resolveVerdict(input: ResolveVerdictInput): Verdict {
  const { rule, call, description } = input;
  const config = input.config ?? {};
  const hint = rule.blocking_hint ?? "alert_only";
  const base = {
    rule_id: rule.rule_id,
    candidate: hint,
    muted: false,
    ...(rule.safe_alternative ? { safe_alternative: rule.safe_alternative } : {}),
    ...(description !== undefined ? { description } : {}),
  };

  // 1. Exceptions. The user's own, never the repository's.
  for (const [scope, cfg, source] of [
    ["project", config.userProject, "project-exception"],
    ["user", config.user, "user-exception"],
  ] as const) {
    const hit = cfg?.exceptions?.find(
      (e) => e.rule_id === rule.rule_id && exceptionMatches(e, call, scope === "project" ? config.projectRoot : undefined),
    );
    if (hit) return { ...base, action: "alert_only", source, muted: hit.kind === "mute", exception: hit };
  }

  // 2 to 5, then the repository's policy on top when it is stricter.
  const chain = chainVerdict(rule, config);
  const repo = repoVerdict(rule, config.repo);
  if (repo && STRENGTH[repo.action] > STRENGTH[chain.action]) return { ...base, ...repo };
  return { ...base, ...chain };
}

function chainVerdict(rule: VerdictRule, config: VerdictConfig): { action: BlockingVerdict; source: VerdictSource } {
  const projectRule = config.userProject?.rules?.[rule.rule_id];
  if (projectRule) return { action: projectRule, source: "project-rule" };
  const userRule = config.user?.rules?.[rule.rule_id];
  if (userRule) return { action: userRule, source: "user-rule" };
  const projectSev = config.userProject?.severity_defaults?.[rule.severity];
  if (projectSev) return { action: projectSev, source: "project-severity" };
  const userSev = config.user?.severity_defaults?.[rule.severity];
  if (userSev) return { action: userSev, source: "user-severity" };
  if (rule.blocking_hint) {
    // A hint that would hold a call is in force only once the rule can tell
    // the agent what to do instead.
    const inForce = !blocks(rule.blocking_hint) || rule.safe_alternative !== undefined;
    return { action: inForce ? rule.blocking_hint : "alert_only", source: "rule-hint" };
  }
  return { action: "alert_only", source: "default" };
}

function repoVerdict(
  rule: VerdictRule,
  repo: EnforcementConfig | undefined,
): { action: BlockingVerdict; source: VerdictSource } | null {
  const byRule = repo?.rules?.[rule.rule_id];
  const bySeverity = repo?.severity_defaults?.[rule.severity];
  if (byRule && (!bySeverity || STRENGTH[byRule] >= STRENGTH[bySeverity])) return { action: byRule, source: "repo-rule" };
  if (bySeverity) return { action: bySeverity, source: "repo-severity" };
  return null;
}

// ---------------------------------------------------------------------------
// Exception targets
// ---------------------------------------------------------------------------

/**
 * Whether an exception covers a call. An exception without a target covers
 * every call. With a target, everything of that kind the call touches must
 * be covered, so allowing one path never allows a call that also reads
 * another, and allowing `npm test` never allows `npm test && curl ...`.
 */
export function exceptionMatches(e: EnforcementException, call: ToolInvokedEvent | undefined, base?: string): boolean {
  if (!e.target) return true;
  if (!call) return false;
  return targetCovers(e.target, call, base);
}

export function targetCovers(target: EnforcementTarget, call: ToolInvokedEvent, base?: string): boolean {
  const action = normalizeAction(call);
  if (target.path !== undefined) {
    const root = resolvePath(target.path, base ?? call.cwd);
    const paths = [...new Set([...action.paths, ...action.writes])].map((p) => resolvePath(p, call.cwd));
    return paths.length > 0 && paths.every((p) => pathUnder(p, root));
  }
  if (target.destination !== undefined) {
    const host = target.destination.toLowerCase().replace(/\.$/, "");
    const hosts = action.destinations.map((d) => d.host);
    return hosts.length > 0 && hosts.every((h) => h === host || h.endsWith(`.${host}`));
  }
  if (target.command_prefix !== undefined) {
    const prefix = shellWords(target.command_prefix);
    if (prefix.length === 0 || action.exec === null) return false;
    // Command substitution runs something the prefix does not name.
    if (/\$\(|`|<\(|>\(/.test(action.exec)) return false;
    const segments = shellSegments(action.exec).map(shellWords).filter((w) => w.length > 0);
    return segments.length > 0 && segments.every((words) => prefix.every((w, i) => words[i] === w));
  }
  return false;
}

function resolvePath(p: string, base: string | undefined): string {
  // A leading ~ is the user's home folder, as in a shell.
  const expanded = p === "~" || /^~[\\/]/.test(p) ? os.homedir() + p.slice(1) : p;
  const slashed = expanded.replace(/\\/g, "/");
  const absolute = /^(?:[A-Za-z]:)?\//.test(slashed) || !base ? slashed : `${base.replace(/\\/g, "/")}/${slashed}`;
  const normalized = path.posix.normalize(absolute).replace(/\/+$/, "");
  // Windows drive paths compare without regard to case.
  return /^[A-Za-z]:/.test(normalized) ? normalized.toLowerCase() : normalized;
}

function pathUnder(p: string, root: string): boolean {
  return p === root || p.startsWith(root.endsWith("/") ? root : `${root}/`);
}
