// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Session start check of Claude Code's local settings file.
 *
 * Choosing "Yes, and don't ask again" makes Claude Code save the exact
 * approved command to `.claude/settings.local.json` in the project, secrets
 * typed into it included. Claude Code writes the file itself, outside any
 * tool call, so no rule on tool calls sees it. This check reads the file at
 * session start and reports a credential in it, with two facts that decide
 * how exposed it is: whether the repository's own ignore rules cover it, and
 * whether git already tracks it.
 *
 * "The repository's own ignore rules" are the .gitignore files from the
 * project up to the repository root and .git/info/exclude. The user's global
 * git ignore is deliberately not counted: Claude Code adds the file there,
 * which protects this machine only, not a clone elsewhere.
 *
 * The finding names credential types and counts, never a value. It is
 * written once per change of what it reports (types, ignored, tracked) for
 * each project, so a leak that stays does not repeat on every session.
 *
 * Never throws; a problem reading anything means no finding.
 */

import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { RiskDetectedEvent, RiskSeverity } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

export const SETTINGS_SECRET_RULE_ID = "RULE_CREDENTIAL_IN_SETTINGS_LOCAL";

const STATE_FILE = "settings-secret-check.json";
const SETTINGS_RELATIVE = [".claude", "settings.local.json"];
const GIT_TIMEOUT_MS = 1500;

/** What the check found in one project's local settings file. */
export interface SettingsSecretReport {
  file: string;
  /** Distinct credential type labels, sorted. */
  types: string[];
  /** The repository's own ignore rules cover the file. */
  ignored: boolean;
  /** Git already tracks the file. Undefined when git could not say. */
  tracked: boolean | undefined;
  /** The project is inside a git repository. */
  inRepo: boolean;
}

export interface SettingsSecretOptions {
  /** Credential types found in a text. Defaults to the analyzer's patterns. */
  scan?: (text: string) => Promise<string[]> | string[];
  /** Answers whether git tracks the file. Defaults to `git ls-files`. */
  isTracked?: (project: string, relative: string) => Promise<boolean | undefined>;
}

/** Inspect the project's settings.local.json. Null when absent or clean. */
export async function inspectSettingsLocal(
  project: string,
  opts: SettingsSecretOptions = {},
): Promise<SettingsSecretReport | null> {
  try {
    const file = path.join(project, ...SETTINGS_RELATIVE);
    const text = await fs.readFile(file, "utf8").catch(() => null);
    if (text === null || text.length === 0) return null;
    const types = [...new Set(await (opts.scan ?? defaultScan)(text))].sort();
    if (types.length === 0) return null;

    const root = await repoRoot(project);
    let ignored = false;
    if (root) ignored = await coveredByRepoIgnore(root, path.join(project, ...SETTINGS_RELATIVE));
    const tracked = root ? await (opts.isTracked ?? gitTracks)(project, SETTINGS_RELATIVE.join("/")) : false;
    return { file, types, ignored, tracked, inRepo: root !== null };
  } catch {
    return null;
  }
}

/**
 * The finding for a session start, or null when there is nothing to report
 * or the same thing was already reported for this project.
 */
export async function settingsSecretFinding(input: {
  project: string;
  sessionId: string;
  relatedEventId: string;
  home: string;
  newEventId: () => string;
  now?: Date;
  options?: SettingsSecretOptions;
}): Promise<RiskDetectedEvent | null> {
  try {
    const key = path.resolve(input.project);
    const state = await readState(input.home);
    const report = await inspectSettingsLocal(input.project, input.options);
    if (!report) {
      if (key in state) {
        delete state[key];
        await writeState(input.home, state);
      }
      return null;
    }
    const signature = [report.types.join(","), report.ignored, report.tracked].join("|");
    if (state[key] === signature) return null;
    state[key] = signature;
    await writeState(input.home, state);

    const at = (input.now ?? new Date()).toISOString();
    return {
      schema_version: SCHEMA_VERSION,
      event_id: input.newEventId(),
      session_id: input.sessionId,
      occurred_at: at,
      recorded_at: at,
      interceptor: "claude-code-hook",
      event_type: "risk.detected",
      severity: severityOf(report),
      category: "credential_exposure",
      description: describe(report),
      related_event_id: input.relatedEventId,
      rule_id: SETTINGS_SECRET_RULE_ID,
      rule_tier: "community",
    };
  } catch {
    return null;
  }
}

function severityOf(r: SettingsSecretReport): RiskSeverity {
  if (r.tracked === true) return "HIGH";
  if (r.inRepo && !r.ignored) return "MEDIUM";
  return "LOW";
}

function describe(r: SettingsSecretReport): string {
  const what =
    `Claude Code's local settings file ${r.file} holds a saved command with a credential ` +
    `(${r.types.join(", ")}). "Yes, and don't ask again" stores the exact approved command in it.`;
  let where: string;
  if (r.tracked === true) where = " Git already tracks the file, so the secret is in the repository.";
  else if (!r.inRepo) where = " The project is not in a git repository.";
  else if (!r.ignored) where = " The repository's own .gitignore does not cover it, so a broad `git add` can commit it.";
  else where = " The repository's .gitignore covers it.";
  return what + where + " Remove the entry and rotate the credential.";
}

async function defaultScan(text: string): Promise<string[]> {
  const analyzer = await import("@omnodex/analyzer");
  return analyzer.findCredentialTypes(text, analyzer.CREDENTIAL_PATTERNS);
}

/** The directory holding .git (a folder, or a file in a worktree), going up. */
async function repoRoot(start: string): Promise<string | null> {
  let dir = path.resolve(start);
  for (;;) {
    try {
      await fs.stat(path.join(dir, ".git"));
      return dir;
    } catch {
      // keep going up
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function gitTracks(project: string, relative: string): Promise<boolean | undefined> {
  return new Promise((resolve) => {
    try {
      execFile(
        "git",
        ["ls-files", "--error-unmatch", "--", relative],
        { cwd: project, timeout: GIT_TIMEOUT_MS, windowsHide: true },
        (err) => {
          if (!err) return resolve(true);
          // Exit 1: the path is not tracked. Anything else (no git): unknown.
          resolve((err as { code?: unknown }).code === 1 ? false : undefined);
        },
      );
    } catch {
      resolve(undefined);
    }
  });
}

// ---------------------------------------------------------------------------
// Ignore rules
// ---------------------------------------------------------------------------

interface IgnoreRule {
  base: string; // directory the rule's file lives in
  negate: boolean;
  dirOnly: boolean;
  anchored: boolean;
  regex: RegExp;
}

/** Whether the repository's own ignore files exclude the file. */
async function coveredByRepoIgnore(root: string, file: string): Promise<boolean> {
  const rules: IgnoreRule[] = [];
  // Lowest precedence first: info/exclude, then .gitignore files root down.
  rules.push(...parseIgnore(await readIfFile(path.join(root, ".git", "info", "exclude")), root));
  const dirs = [root];
  const rel = path.relative(root, path.dirname(file)).split(path.sep).filter(Boolean);
  let cur = root;
  for (const part of rel) {
    cur = path.join(cur, part);
    dirs.push(cur);
  }
  for (const dir of dirs) rules.push(...parseIgnore(await readIfFile(path.join(dir, ".gitignore")), dir));

  const segments = path.relative(root, file).split(path.sep);
  // A file inside an ignored directory is ignored, whatever follows.
  for (let i = 1; i <= segments.length; i++) {
    const isDir = i < segments.length;
    if (decide(rules, root, segments.slice(0, i), isDir)) return true;
  }
  return false;
}

function decide(rules: IgnoreRule[], root: string, parts: string[], isDir: boolean): boolean {
  const abs = path.join(root, ...parts);
  let ignored = false;
  for (const rule of rules) {
    if (rule.dirOnly && !isDir) continue;
    const rel = path.relative(rule.base, abs).split(path.sep).join("/");
    if (rel.startsWith("..")) continue;
    const subject = rule.anchored ? rel : rel.split("/").pop()!;
    if (rule.regex.test(subject)) ignored = !rule.negate;
  }
  return ignored;
}

function parseIgnore(text: string | null, base: string): IgnoreRule[] {
  if (!text) return [];
  const out: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.replace(/(?<!\\)\s+$/, "");
    if (line === "" || line.startsWith("#")) continue;
    let negate = false;
    if (line.startsWith("!")) {
      negate = true;
      line = line.slice(1);
    } else if (line.startsWith("\\!") || line.startsWith("\\#")) {
      line = line.slice(1);
    }
    let dirOnly = false;
    if (line.endsWith("/")) {
      dirOnly = true;
      line = line.slice(0, -1);
    }
    if (line === "") continue;
    const anchored = line.includes("/");
    if (line.startsWith("/")) line = line.slice(1);
    out.push({ base, negate, dirOnly, anchored, regex: globToRegex(line) });
  }
  return out;
}

function globToRegex(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else re += "[^/]*";
    } else if (ch === "?") re += "[^/]";
    else if (ch === "[") {
      const end = glob.indexOf("]", i + 2);
      if (end === -1) re += "\\[";
      else {
        re += "[" + glob.slice(i + 1, end).replace(/^!/, "^").replace(/\\/g, "\\\\") + "]";
        i = end;
      }
    } else if (ch === "\\" && i + 1 < glob.length) {
      re += escapeRe(glob[++i]!);
    } else re += escapeRe(ch);
  }
  return new RegExp("^" + re + "$");
}

function escapeRe(ch: string): string {
  return /[.+^${}()|\\\]\[]/.test(ch) ? "\\" + ch : ch;
}

async function readIfFile(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// What was already reported
// ---------------------------------------------------------------------------

async function readState(home: string): Promise<Record<string, string>> {
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(home, STATE_FILE), "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function writeState(home: string, state: Record<string, string>): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  const dest = path.join(home, STATE_FILE);
  const tmp = `${dest}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2) + "\n", "utf8");
  await fs.rename(tmp, dest);
}
