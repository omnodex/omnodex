// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Loading enforcement configuration for one call.
 *
 * The user's file is `$OMNODEX_HOME/omnodex-config.json`, section
 * `enforcement`; its `projects` map holds the user's overrides per project
 * root. The repository's shared policy is `<root>/.omnodex/config.json`,
 * section `enforcement`, found by walking up from the call's working
 * directory, and it can only tighten (see resolveVerdict).
 *
 * Reads are synchronous and small: this runs in a hook process that is
 * already waiting on the agent. A missing or unreadable file is an empty
 * section, never an error.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  PROJECT_CONFIG_DIR,
  PROJECT_CONFIG_FILE,
  parseEnforcementConfig,
  parseRepoEnforcementConfig,
  type EnforcementConfig,
  type EnforcementMode,
} from "@omnodex/shared";
import type { VerdictConfig } from "./resolve-verdict.js";

export const USER_CONFIG_FILE = "omnodex-config.json";

export interface LoadedEnforcement extends VerdictConfig {
  mode: EnforcementMode;
  on_error: "allow" | "block";
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as unknown;
  } catch {
    return undefined;
  }
}

function section(raw: unknown): unknown {
  return typeof raw === "object" && raw !== null ? (raw as { enforcement?: unknown }).enforcement : undefined;
}

/** The user's enforcement section. */
export function readUserEnforcement(home: string): EnforcementConfig {
  return parseEnforcementConfig(section(readJson(path.join(home, USER_CONFIG_FILE))));
}

/**
 * The nearest directory at or above `cwd` holding a repository policy file,
 * or null. The walk stops below the user's home directory, whose `.omnodex`
 * directory is Omnodex's own state, not a project's.
 */
export function findRepoPolicy(cwd: string, userHome = os.homedir()): string | null {
  const home = path.resolve(userHome);
  let dir = path.resolve(cwd);
  for (;;) {
    if (dir === home) return null;
    if (fs.existsSync(path.join(dir, PROJECT_CONFIG_DIR, PROJECT_CONFIG_FILE))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** The user's section for the project containing `cwd`: the longest matching root. */
export function userProjectSection(
  user: EnforcementConfig,
  cwd: string,
): { root: string; config: EnforcementConfig } | null {
  if (!user.projects) return null;
  const at = normalize(cwd);
  let best: { root: string; config: EnforcementConfig } | null = null;
  for (const [root, config] of Object.entries(user.projects)) {
    const r = normalize(root);
    if ((at === r || at.startsWith(`${r}/`)) && (!best || r.length > normalize(best.root).length)) {
      best = { root, config };
    }
  }
  return best;
}

function normalize(p: string): string {
  const n = path.resolve(p).replace(/\\/g, "/").replace(/\/+$/, "");
  return /^[A-Za-z]:/.test(n) ? n.toLowerCase() : n;
}

export interface LoadEnforcementOptions {
  /** OMNODEX_HOME. */
  home?: string;
  /** The call's working directory. Without it, only the user's file is read. */
  cwd?: string;
  /** The user's home directory, where the repository-policy walk stops. */
  userHome?: string;
}

/** Everything resolveVerdict needs for calls made in `cwd`. */
export function loadEnforcement(opts: LoadEnforcementOptions = {}): LoadedEnforcement {
  const home = opts.home ?? process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  const user = readUserEnforcement(home);
  const out: LoadedEnforcement = { mode: user.mode ?? "monitor", on_error: user.on_error ?? "allow", user };
  if (!opts.cwd) return out;

  const project = userProjectSection(user, opts.cwd);
  if (project) {
    out.userProject = project.config;
    out.projectRoot = project.root;
  }
  const repoRoot = findRepoPolicy(opts.cwd, opts.userHome);
  if (repoRoot) {
    const repo = parseRepoEnforcementConfig(
      section(readJson(path.join(repoRoot, PROJECT_CONFIG_DIR, PROJECT_CONFIG_FILE))),
    );
    if (Object.keys(repo).length > 0) out.repo = repo;
    out.projectRoot ??= repoRoot;
  }
  return out;
}
