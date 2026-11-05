// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex policy list | add | watch | remove | pull`: this machine's policy
 * entries, and the account's.
 *
 * An entry says what to do with findings like one in front of you: block
 * them, hold them, let them through, mute them or change their severity,
 * for a rule, a category or a severity, optionally only for one target
 * (a path, a host, a command, a credential, a tool, reads or writes of a
 * path) and one project. Entries live in OMNODEX_HOME/omnodex-config.json,
 * `enforcement.policy`; the older per-rule, per-severity and exception keys
 * in the same section are listed as entries too, and can be removed by
 * their ids. Entries made for the whole account in the hosted dashboard
 * are pulled by the background pass, or at once by `pull`, and listed
 * beside them; they are changed in the dashboard, not here.
 *
 * `watch` adds an entry that raises a finding of its own: a tool call that
 * changes, moves or deletes the path, folder or glob. Adding one leaves a
 * marker. Removing one needs a person, as other loosening does, and leaves a
 * marker too.
 *
 * Turning protection down is for a person, not an agent: an entry that
 * allows, mutes or lowers a severity, and removing one that blocks, holds,
 * raises a severity or unmutes, need an interactive terminal and a typed
 * confirmation, as leaving guardrails does. Block and hold act only in
 * guardrails, which is Pro, so adding them needs a plan that includes it.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import {
  parseEnforcementConfig,
  parsePolicy,
  parsePolicyEntry,
  policyEntries,
  isWatchEntry,
  WATCHED_PATH_RULE_ID,
  type EnforcementConfig,
  type PolicyEntry,
  type PolicyTarget,
  type RiskSeverity,
} from "@omnodex/shared";
import type { ControlIo } from "./capture-controls.js";
import { USER_CONFIG_FILE } from "./enforce-command.js";
import { recordMonitoringChange } from "./monitoring-markers.js";

export interface PolicyOptions {
  home: string;
  io: ControlIo;
  /** The working directory, for --here. */
  cwd?: string;
  /** Whether this machine's plan includes guardrails, for block and hold. */
  guardrailsEntitled?: () => Promise<boolean>;
  /** A rule's own severity, when the rule is known, to tell a lower severity from a higher one. */
  ruleSeverity?: (ruleId: string) => RiskSeverity | undefined;
  /** Fetch the account's policy now. */
  pull?: () => Promise<{ outcome: string; version?: number; entries?: number }>;
  /** The account policy as last pulled. */
  accountPolicy?: () => Promise<{ version: number; pulled_at: string; entries: PolicyEntry[] } | null>;
  /** For tests. */
  now?: () => Date;
  newId?: () => string;
}

const TAG = "[policy]";
const USAGE = "omnodex policy list | add <match> [target] <effect> | watch <path> | remove <id> | pull";
const SEVERITIES: readonly RiskSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const RANK: Readonly<Record<RiskSeverity, number>> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/** The flags `policy add` takes, each followed by a value. */
export const POLICY_ADD_VALUES = [
  "--rule", "--category", "--severity",
  "--path", "--destination", "--command-prefix", "--credential", "--tool", "--server", "--reads", "--writes",
  "--project", "--set-severity", "--note",
] as const;
/** The flags `policy watch` takes, beside the path. */
export const POLICY_WATCH_VALUES = ["--project", "--note"] as const;
export const POLICY_WATCH_FLAGS = ["--here", "--block", "--hold"] as const;
/** The flags `policy add` takes alone. */
export const POLICY_ADD_FLAGS = ["--here", "--block", "--hold", "--allow", "--mute", "--unmute"] as const;

// ---------------------------------------------------------------------------
// Config file
// ---------------------------------------------------------------------------

async function readConfig(file: string): Promise<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as unknown;
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    throw new Error("not a JSON object");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new Error(`cannot read ${file}: ${(err as Error).message}`);
  }
}

async function writeConfig(file: string, config: Record<string, unknown>): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  // Write then rename, so a crash mid-write never leaves a torn file.
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(config, null, 2) + "\n");
  await fs.rename(tmp, file);
}

function sectionOf(config: Record<string, unknown>): Record<string, unknown> {
  const s = config.enforcement;
  return typeof s === "object" && s !== null && !Array.isArray(s) ? { ...(s as Record<string, unknown>) } : {};
}

/** Add an entry to this machine's policy. The caller has already checked who may add it. */
export async function appendPolicyEntry(home: string, entry: PolicyEntry): Promise<void> {
  const file = path.join(home, USER_CONFIG_FILE);
  const config = await readConfig(file);
  const section = sectionOf(config);
  const policy = parsePolicy(section.policy);
  await writeConfig(file, { ...config, enforcement: { ...section, policy: [...policy, entry] } });
  if (isWatchEntry(entry)) await markWatch("watch_add", entry, home);
}

// ---------------------------------------------------------------------------
// Describing entries
// ---------------------------------------------------------------------------

function describeTarget(t: PolicyTarget): string {
  if ("access" in t) return `${t.access === "read" ? "reads of" : "writes to"} ${t.path}`;
  if ("tool" in t) return t.server ? `tool ${t.tool} on ${t.server}` : `tool ${t.tool}`;
  if ("path" in t) return `path ${t.path}`;
  if ("destination" in t) return `host ${t.destination}`;
  if ("command_prefix" in t) return `command "${t.command_prefix}"`;
  return `credential ${t.credential}`;
}

/** One line for an entry: what it matches and what it does. */
export function describeEntry(e: PolicyEntry): string {
  const m = e.match;
  if (isWatchEntry(e) && m.target && "path" in m.target) {
    const acts = e.effect.verdict === "deny" ? ", block" : e.effect.verdict === "confirm" ? ", hold" : "";
    return `watching ${m.target.path}, ${m.project ? `in ${m.project}` : "everywhere"}: ${e.effect.severity ?? "HIGH"} finding on a change${acts}`;
  }
  const what = m.rule_id ? `rule ${m.rule_id}` : m.category ? `category ${m.category}` : `severity ${m.severity}`;
  const where = [m.target ? describeTarget(m.target) : null, m.project ? `in ${m.project}` : "everywhere"].filter(Boolean).join(", ");
  const does: string[] = [];
  if (e.effect.verdict) does.push({ deny: "block", confirm: "hold", allow: "allow" }[e.effect.verdict]);
  if (e.effect.severity) does.push(`severity ${e.effect.severity}`);
  if (e.effect.mute !== undefined) does.push(e.effect.mute ? "mute" : "unmute");
  return `${what}, ${where}: ${does.join(", ")}`;
}

/**
 * Whether an entry turns protection down: allows, mutes, or sets a severity
 * lower than the one it applies to. A severity for a category, or for a rule
 * whose severity is unknown, counts as lower unless it is CRITICAL.
 */
export function loosens(e: PolicyEntry, ruleSeverity?: (id: string) => RiskSeverity | undefined): boolean {
  if (isWatchEntry(e)) return false;
  if (e.effect.verdict === "allow" || e.effect.mute === true) return true;
  const set = e.effect.severity;
  if (!set) return false;
  const base = e.match.severity ?? (e.match.rule_id ? ruleSeverity?.(e.match.rule_id) : undefined);
  return base ? RANK[set] < RANK[base] : set !== "CRITICAL";
}

/** Whether an entry turns protection up, so removing it turns protection down. */
export function tightens(e: PolicyEntry, ruleSeverity?: (id: string) => RiskSeverity | undefined): boolean {
  if (e.effect.verdict === "deny" || e.effect.verdict === "confirm" || e.effect.mute === false) return true;
  const set = e.effect.severity;
  if (!set) return false;
  const base = e.match.severity ?? (e.match.rule_id ? ruleSeverity?.(e.match.rule_id) : undefined);
  return base ? RANK[set] > RANK[base] : set === "CRITICAL";
}

// ---------------------------------------------------------------------------
// Parsing `add`
// ---------------------------------------------------------------------------

function flagValues(args: string[]): { values: Map<string, string>; flags: Set<string>; error?: string } {
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if ((POLICY_ADD_VALUES as readonly string[]).includes(a)) {
      const v = args[++i];
      if (v === undefined) return { values, flags, error: `${a} needs a value` };
      if (values.has(a)) return { values, flags, error: `${a} given twice` };
      values.set(a, v);
    } else if ((POLICY_ADD_FLAGS as readonly string[]).includes(a)) {
      flags.add(a);
    } else {
      return { values, flags, error: `unexpected '${a}'` };
    }
  }
  return { values, flags };
}

/** The entry `policy add` describes, or an error. */
export function entryFromArgs(
  args: string[],
  opts: { cwd?: string; now: Date; id: string },
): { entry: PolicyEntry } | { error: string } {
  const { values, flags, error } = flagValues(args);
  if (error) return { error };
  const v = (k: string): string | undefined => values.get(k);

  const kinds = ["--rule", "--category", "--severity"].filter((k) => values.has(k));
  if (kinds.length !== 1) return { error: "give exactly one of --rule, --category or --severity" };
  const match: Record<string, unknown> = {};
  if (v("--rule")) match.rule_id = v("--rule");
  if (v("--category")) match.category = v("--category");
  if (v("--severity")) match.severity = v("--severity")!.toUpperCase();

  const targets = ["--path", "--destination", "--command-prefix", "--credential", "--tool", "--reads", "--writes"].filter((k) => values.has(k));
  if (targets.length > 1) return { error: "give at most one target" };
  if (values.has("--server") && !values.has("--tool")) return { error: "--server goes with --tool" };
  const t = targets[0];
  if (t === "--path") match.target = { path: v(t) };
  if (t === "--destination") match.target = { destination: v(t) };
  if (t === "--command-prefix") match.target = { command_prefix: v(t) };
  if (t === "--credential") match.target = { credential: v(t) };
  if (t === "--tool") match.target = { tool: v(t), ...(v("--server") ? { server: v("--server") } : {}) };
  if (t === "--reads") match.target = { access: "read", path: v(t) };
  if (t === "--writes") match.target = { access: "write", path: v(t) };

  if (values.has("--project") && flags.has("--here")) return { error: "give --project or --here, not both" };
  if (flags.has("--here")) {
    if (!opts.cwd) return { error: "--here needs a working directory" };
    match.project = opts.cwd;
  } else if (v("--project")) {
    match.project = path.resolve(v("--project")!);
  }
  // A relative path target in a project resolves against the project root,
  // as the evaluator reads it; elsewhere it is made absolute here.
  const tgt = match.target as Record<string, string> | undefined;
  if (tgt?.path !== undefined && !match.project && !/^(?:~([\\/]|$)|\*\*[\\/])/.test(tgt.path)) tgt.path = path.resolve(tgt.path);

  const verdicts = ["--block", "--hold", "--allow"].filter((k) => flags.has(k));
  if (verdicts.length > 1) return { error: "give at most one of --block, --hold or --allow" };
  if (flags.has("--mute") && flags.has("--unmute")) return { error: "give --mute or --unmute, not both" };
  const effect: Record<string, unknown> = {};
  if (verdicts[0]) effect.verdict = { "--block": "deny", "--hold": "confirm", "--allow": "allow" }[verdicts[0]];
  if (v("--set-severity")) effect.severity = v("--set-severity")!.toUpperCase();
  if (flags.has("--mute")) effect.mute = true;
  if (flags.has("--unmute")) effect.mute = false;
  if (Object.keys(effect).length === 0) return { error: "give an effect: --block, --hold, --allow, --mute, --unmute or --set-severity" };

  const raw = {
    id: opts.id,
    match,
    effect,
    ...(v("--note") ? { note: v("--note") } : {}),
    created_at: opts.now.toISOString(),
    created_by: "cli",
  };
  const entry = parsePolicyEntry(raw);
  if (!entry) {
    const bad = [match.severity, effect.severity].find((s) => s !== undefined && !SEVERITIES.includes(s as RiskSeverity));
    return { error: bad ? `unknown severity '${String(bad)}': use LOW, MEDIUM, HIGH or CRITICAL` : "that entry is not valid" };
  }
  return { entry };
}

/** One argument quoted for the user's shell when it needs it. */
function shellQuote(v: string, windows: boolean): string {
  if (/^[A-Za-z0-9_@%+=:,./~-]+$/.test(v)) return v;
  return windows ? `'${v.replace(/'/g, "''")}'` : `'${v.replace(/'/g, `'\\''`)}'`;
}

/**
 * The `omnodex policy add` command that makes `e`: the inverse of
 * entryFromArgs. A project is given with --project, so the command does not
 * depend on the directory it is run from.
 */
export function commandForEntry(e: PolicyEntry, windows: boolean = process.platform === "win32"): string {
  const q = (v: string): string => shellQuote(v, windows);
  const m = e.match;
  const parts = ["omnodex", "policy", "add"];
  if (m.rule_id) parts.push("--rule", q(m.rule_id));
  else if (m.category) parts.push("--category", q(m.category));
  else if (m.severity) parts.push("--severity", m.severity);
  const t = m.target;
  if (t) {
    if ("access" in t) parts.push(t.access === "read" ? "--reads" : "--writes", q(t.path));
    else if ("tool" in t) parts.push("--tool", q(t.tool), ...(t.server ? ["--server", q(t.server)] : []));
    else if ("path" in t) parts.push("--path", q(t.path));
    else if ("destination" in t) parts.push("--destination", q(t.destination));
    else if ("command_prefix" in t) parts.push("--command-prefix", q(t.command_prefix));
    else parts.push("--credential", q(t.credential));
  }
  if (m.project) parts.push("--project", q(m.project));
  if (e.effect.verdict) parts.push({ deny: "--block", confirm: "--hold", allow: "--allow" }[e.effect.verdict]);
  if (e.effect.severity) parts.push("--set-severity", e.effect.severity);
  if (e.effect.mute !== undefined) parts.push(e.effect.mute ? "--mute" : "--unmute");
  if (e.note) parts.push("--note", q(e.note));
  return parts.join(" ");
}

// ---------------------------------------------------------------------------
// Removing older keys by entry id
// ---------------------------------------------------------------------------

/**
 * The section without the older key that `id` names, or null when no older
 * key has that id. Ids are the ones policyEntries gives: config:rule:<id>,
 * config:severity:<SEV>, config:exception:<rule>:<kind>:<target>, each
 * optionally inside config:project:<root>:.
 */
function withoutLegacy(section: Record<string, unknown>, id: string): Record<string, unknown> | null {
  const parsed = parseEnforcementConfig(section);
  for (const entry of policyEntries({ ...parsed, policy: [] })) {
    if (entry.id !== id) continue;
    const project = entry.match.project;
    const scope: EnforcementConfig = project !== undefined ? (parsed.projects?.[project] ?? {}) : parsed;
    const ruleId = entry.match.rule_id;
    const rawScope = (project !== undefined
      ? ((section.projects as Record<string, Record<string, unknown>>)[project] ?? {})
      : section) as Record<string, unknown>;
    const next: Record<string, unknown> = { ...rawScope };
    if (id.endsWith(`rule:${ruleId}`) && scope.rules?.[ruleId!]) {
      const rules = { ...(rawScope.rules as Record<string, unknown>) };
      delete rules[ruleId!];
      next.rules = rules;
    } else if (entry.match.severity !== undefined) {
      const sev = { ...(rawScope.severity_defaults as Record<string, unknown>) };
      delete sev[entry.match.severity];
      next.severity_defaults = sev;
    } else {
      const kind = entry.effect.mute ? "mute" : "allow";
      const key = JSON.stringify(entry.match.target ?? null);
      const list = Array.isArray(rawScope.exceptions) ? rawScope.exceptions : [];
      next.exceptions = list.filter((e) => {
        const r = e as { rule_id?: unknown; kind?: unknown; target?: unknown };
        return !(r.rule_id === ruleId && r.kind === kind && JSON.stringify(r.target ?? null) === key);
      });
    }
    if (project === undefined) return next;
    return { ...section, projects: { ...(section.projects as Record<string, unknown>), [project]: next } };
  }
  return null;
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/** A person at a terminal confirms turning protection down. False when there is none, or they decline. */
async function confirmLoosening(io: ControlIo, what: string, word: string): Promise<boolean> {
  // Human only: an agent running this through a shell has no terminal.
  if (!io.stdinIsTTY || !io.stdoutIsTTY) {
    io.error(
      `${TAG} ${what} turns protection down, which needs a person at an interactive terminal, ` +
        `so an agent cannot do it. Run the command yourself in a terminal.`,
    );
    return false;
  }
  io.log(`${TAG} ${what} turns protection down.`);
  const answer = (await io.ask(`${TAG} type "${word}" to confirm: `)).trim().toLowerCase();
  if (answer !== word) {
    io.log(`${TAG} unchanged.`);
    return false;
  }
  return true;
}

/** The marker for a watch added or removed. It names the entry and never the watched path. */
async function markWatch(action: "watch_add" | "watch_remove", entry: PolicyEntry, home: string): Promise<void> {
  const project = entry.match.project;
  await recordMonitoringChange(
    {
      action,
      scope: project !== undefined ? "project" : "user",
      ...(project !== undefined ? { project_path: project } : {}),
      ...(action === "watch_add" ? { to: entry.id } : { from: entry.id }),
    },
    home,
  );
}

/** `policy watch <path> [--here | --project <root>] [--block | --hold] [--note <text>]`. */
async function runWatch(args: string[], opts: PolicyOptions, file: string): Promise<number> {
  const { io, home } = opts;
  const [target, ...rest] = args;
  if (!target || target.startsWith("-")) {
    io.error(`${TAG} watch takes a file, folder or glob. Usage: ${USAGE}`);
    return 1;
  }
  const known: readonly string[] = [...POLICY_WATCH_VALUES, ...POLICY_WATCH_FLAGS];
  const bad = rest.find((a, i) => a.startsWith("--") && !known.includes(a) && !(POLICY_WATCH_VALUES as readonly string[]).includes(rest[i - 1] ?? ""));
  if (bad) {
    io.error(`${TAG} watch does not take ${bad}. Usage: ${USAGE}`);
    return 1;
  }
  const stops = rest.includes("--block") || rest.includes("--hold");
  const built = entryFromArgs(
    ["--rule", WATCHED_PATH_RULE_ID, "--writes", target, ...rest, ...(stops ? [] : ["--set-severity", "HIGH"])],
    { cwd: opts.cwd, now: opts.now?.() ?? new Date(), id: opts.newId?.() ?? `p-${randomUUID().slice(0, 8)}` },
  );
  if ("error" in built) {
    io.error(`${TAG} ${built.error}. Usage: ${USAGE}`);
    return 1;
  }
  const { entry } = built;
  if (stops && opts.guardrailsEntitled && !(await opts.guardrailsEntitled())) {
    io.error(`${TAG} block and hold act through guardrails, which are part of Omnodex Pro. Watching a path without them is free.`);
    return 1;
  }
  const config = await readConfig(file);
  const section = sectionOf(config);
  await writeConfig(file, { ...config, enforcement: { ...section, policy: [...parsePolicy(section.policy), entry] } });
  await markWatch("watch_add", entry, home);
  io.log(`${TAG} added ${entry.id}: ${describeEntry(entry)}.`);
  io.log(`${TAG} only changes a tool call names are seen; a script run later, or another process, is not.`);
  if (stops) io.log(`${TAG} it stops or holds calls in guardrails mode; in shadow mode it is recorded on each finding.`);
  return 0;
}

/** Run `omnodex policy <sub>`. Returns the exit code. */
export async function runPolicy(args: string[], opts: PolicyOptions): Promise<number> {
  const { home, io } = opts;
  const file = path.join(home, USER_CONFIG_FILE);
  const sub = args[0] ?? "list";
  const rest = args.slice(1);

  try {
    if (sub === "list") {
      if (rest.length > 0) {
        io.error(`${TAG} list takes no arguments. Usage: ${USAGE}`);
        return 1;
      }
      const entries = policyEntries(parseEnforcementConfig(sectionOf(await readConfig(file))));
      if (entries.length === 0) io.log(`${TAG} no policy entries in ${file}.`);
      for (const e of entries) io.log(`${e.id}  ${describeEntry(e)}${e.note ? `  (${e.note})` : ""}`);
      const account = await opts.accountPolicy?.();
      if (account && account.entries.length > 0) {
        io.log(`${TAG} for the whole account (version ${account.version}, pulled ${account.pulled_at}; edit in the hosted dashboard):`);
        for (const e of account.entries) io.log(`${e.id}  ${describeEntry(e)}${e.note ? `  (${e.note})` : ""}`);
      }
      return 0;
    }

    if (sub === "add") {
      const now = opts.now?.() ?? new Date();
      const built = entryFromArgs(rest, { cwd: opts.cwd, now, id: opts.newId?.() ?? `p-${randomUUID().slice(0, 8)}` });
      if ("error" in built) {
        io.error(`${TAG} ${built.error}. Usage: ${USAGE}`);
        return 1;
      }
      const { entry } = built;
      const verdict = entry.effect.verdict;
      if ((verdict === "deny" || verdict === "confirm") && opts.guardrailsEntitled && !(await opts.guardrailsEntitled())) {
        io.error(
          `${TAG} block and hold act through guardrails, which are part of Omnodex Pro. ` +
            `Allow, mute and severity entries are free.`,
        );
        return 1;
      }
      if (loosens(entry, opts.ruleSeverity) && !(await confirmLoosening(io, `"${describeEntry(entry)}"`, "add"))) return 1;
      await appendPolicyEntry(home, entry);
      io.log(`${TAG} added ${entry.id}: ${describeEntry(entry)}.`);
      if (verdict === "deny" || verdict === "confirm") {
        io.log(`${TAG} it stops or holds calls in guardrails mode; in shadow mode it is recorded on each finding.`);
      }
      return 0;
    }

    if (sub === "watch") return await runWatch(rest, opts, file);

    if (sub === "remove") {
      const id = rest[0];
      if (!id || rest.length > 1) {
        io.error(`${TAG} remove takes one entry id, as \`omnodex policy list\` shows it. Usage: ${USAGE}`);
        return 1;
      }
      const config = await readConfig(file);
      const section = sectionOf(config);
      const entry = policyEntries(parseEnforcementConfig(section)).find((e) => e.id === id);
      if (!entry) {
        io.error(`${TAG} no entry '${id}' in ${file}.`);
        return 1;
      }
      const watch = isWatchEntry(entry);
      if ((watch || tightens(entry, opts.ruleSeverity)) && !(await confirmLoosening(io, `removing "${describeEntry(entry)}"`, "remove"))) {
        return 1;
      }
      let next = withoutLegacy(section, id);
      if (!next) {
        const policy = Array.isArray(section.policy) ? section.policy : [];
        next = { ...section, policy: policy.filter((e) => (e as { id?: unknown }).id !== id) };
      }
      await writeConfig(file, { ...config, enforcement: next });
      if (watch) await markWatch("watch_remove", entry, home);
      io.log(`${TAG} removed ${id}: ${describeEntry(entry)}.`);
      return 0;
    }
    if (sub === "pull") {
      if (rest.length > 0 || !opts.pull) {
        io.error(`${TAG} pull takes no arguments. Usage: ${USAGE}`);
        return 1;
      }
      const r = await opts.pull();
      const said: Record<string, string> = {
        updated: `account policy version ${r.version} pulled: ${r.entries} entr${r.entries === 1 ? "y" : "ies"}.`,
        current: `account policy already current (version ${r.version}).`,
        none: "the account has no policy for this machine's stream.",
        "no-credentials": "this machine is not connected to a dashboard account (`omnodex connect`).",
        disabled: "pulling is switched off (OMNODEX_POLICY_PULL=0).",
      };
      if (r.outcome in said) {
        io.log(`${TAG} ${said[r.outcome]}`);
        return 0;
      }
      io.error(`${TAG} could not pull the account policy; the last one pulled stays in use.`);
      return 1;
    }
  } catch (err) {
    io.error(`${TAG} ${(err as Error).message}`);
    return 1;
  }

  io.error(`${TAG} unknown subcommand '${sub}'. Usage: ${USAGE}`);
  return 1;
}
