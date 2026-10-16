// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * hook-scope.ts
 *
 * Where hooks record: every project (hooks in each agent's user-level file)
 * or only the projects they were installed into, plus the projects left out
 * while every-project recording is on.
 *
 * Stored at <OMNODEX_HOME>/hook-scope.json and read by the hook launchers
 * at runtime, so the format is kept small and stable:
 *
 *   {
 *     "version": 1,
 *     "everywhere": ["claude-code", "codex"],
 *     "excluded": { "/abs/project": ["codex"] }
 *   }
 *
 * This is Omnodex's own model; each agent's hook files are written from it,
 * so an agent whose native scopes behave differently can be mapped
 * differently without changing what `omnodex status` reports.
 */

import { promises as fs, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { LauncherPlatform } from "./launcher-template.js";

export const HOOK_SCOPE_FILE = "hook-scope.json";

/** First launcher argument of hook commands written to a user-level file. */
export const USER_SCOPE_ARG = "--user-scope";

export interface HookScope {
  version: 1;
  /** Targets whose hooks are installed in the agent's user-level file. */
  everywhere: LauncherPlatform[];
  /** Project path -> targets not recorded there. */
  excluded: Record<string, LauncherPlatform[]>;
}

const TARGETS: readonly string[] = ["claude-code", "codex", "antigravity"];

export function hookScopePath(omnodexHome: string): string {
  return path.join(omnodexHome, HOOK_SCOPE_FILE);
}

const isTarget = (t: unknown): t is LauncherPlatform => typeof t === "string" && TARGETS.includes(t);

export async function readHookScope(omnodexHome: string): Promise<HookScope> {
  const empty: HookScope = { version: 1, everywhere: [], excluded: {} };
  let raw: string;
  try {
    raw = await fs.readFile(hookScopePath(omnodexHome), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return empty;
    throw err;
  }
  const parsed = JSON.parse(raw) as Partial<HookScope>;
  const everywhere = Array.isArray(parsed.everywhere) ? parsed.everywhere.filter(isTarget) : [];
  const excluded: Record<string, LauncherPlatform[]> = {};
  for (const [project, targets] of Object.entries(parsed.excluded ?? {})) {
    const valid = Array.isArray(targets) ? targets.filter(isTarget) : [];
    if (valid.length > 0) excluded[project] = valid;
  }
  return { version: 1, everywhere, excluded };
}

export async function writeHookScope(omnodexHome: string, scope: HookScope): Promise<void> {
  await fs.mkdir(omnodexHome, { recursive: true });
  const sorted: HookScope = {
    version: 1,
    everywhere: [...new Set(scope.everywhere)].sort(),
    excluded: Object.fromEntries(
      Object.entries(scope.excluded)
        .filter(([, targets]) => targets.length > 0)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([p, targets]) => [p, [...new Set(targets)].sort()]),
    ),
  };
  await fs.writeFile(hookScopePath(omnodexHome), JSON.stringify(sorted, null, 2) + "\n", "utf8");
}

/**
 * The form a project path is stored in: absolute, symlinks resolved when
 * the path exists (macOS reports /var as /private/var), lowercase on
 * Windows. The launcher normalizes the path it sees the same way.
 */
export function canonicalProjectPath(p: string, platform: NodeJS.Platform = process.platform): string {
  let resolved = path.resolve(p);
  try {
    resolved = realpathSync(resolved);
  } catch {
    // not on disk; keep the resolved path
  }
  return platform === "win32" ? resolved.toLowerCase() : resolved;
}

/** True when `project` is `root` or inside it. */
function within(project: string, root: string): boolean {
  if (project === root) return true;
  const prefix = root.endsWith(path.sep) ? root : root + path.sep;
  return project.startsWith(prefix);
}

/** The excluded root that covers this project for this target, if any. */
export function exclusionFor(scope: HookScope, target: LauncherPlatform, projectPath: string): string | null {
  const project = canonicalProjectPath(projectPath);
  for (const [root, targets] of Object.entries(scope.excluded)) {
    if (targets.includes(target) && within(project, root)) return root;
  }
  return null;
}

export function isEverywhere(scope: HookScope, target: LauncherPlatform): boolean {
  return scope.everywhere.includes(target);
}

/** Turn every-project recording on or off for a target. Off also drops its exclusions. */
export async function setEverywhere(omnodexHome: string, target: LauncherPlatform, on: boolean): Promise<void> {
  const scope = await readHookScope(omnodexHome);
  if (on) {
    scope.everywhere.push(target);
  } else {
    scope.everywhere = scope.everywhere.filter((t) => t !== target);
    for (const [p, targets] of Object.entries(scope.excluded)) {
      scope.excluded[p] = targets.filter((t) => t !== target);
    }
  }
  await writeHookScope(omnodexHome, scope);
}

export async function addExclusion(omnodexHome: string, target: LauncherPlatform, projectPath: string): Promise<void> {
  const scope = await readHookScope(omnodexHome);
  const key = canonicalProjectPath(projectPath);
  scope.excluded[key] = [...(scope.excluded[key] ?? []), target];
  await writeHookScope(omnodexHome, scope);
}

/**
 * Record this project again for a target. Removes the exclusion that covers
 * it; returns the removed root, or null when it was not excluded. An
 * exclusion of a parent folder is removed too, since it is what stops the
 * project from being recorded.
 */
export async function removeExclusion(omnodexHome: string, target: LauncherPlatform, projectPath: string): Promise<string | null> {
  const scope = await readHookScope(omnodexHome);
  const root = exclusionFor(scope, target, projectPath);
  if (!root) return null;
  scope.excluded[root] = scope.excluded[root].filter((t) => t !== target);
  await writeHookScope(omnodexHome, scope);
  return root;
}

/**
 * Each agent's user-level hooks file, which applies to every project.
 * CLAUDE_CONFIG_DIR and CODEX_HOME move Claude Code's and Codex's user
 * folders, as they do for the agents themselves.
 */
export function userHooksFile(
  target: LauncherPlatform,
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
): string {
  switch (target) {
    case "claude-code":
      return path.join(env.CLAUDE_CONFIG_DIR || path.join(home, ".claude"), "settings.json");
    case "codex":
      return path.join(env.CODEX_HOME || path.join(home, ".codex"), "hooks.json");
    case "antigravity":
      return path.join(home, ".gemini", "config", "hooks.json");
  }
}
