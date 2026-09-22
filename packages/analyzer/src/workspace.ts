// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Workspace roots: the directories a session may write to without that
 * being "outside the workspace".
 *
 * A single working directory is too narrow for real projects: a session
 * started in a repo writes into its git top level, and a repo with git
 * worktrees has sibling checkouts that are the same project. Roots are:
 *
 *   - the working directory itself
 *   - the git top level containing it
 *   - for a git worktree, the main checkout and every other worktree
 *     registered with the same repository
 *   - any directories listed under "workspace_roots" in
 *     $OMNODEX_HOME/omnodex-config.json (a leading ~ is the home directory)
 *
 * Resolution reads a handful of small files, so results are cached per
 * working directory for the life of the process.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export type WorkspaceRootsFn = (cwd: string) => string[];

function expandHome(p: string, home: string): string {
  return p === "~" || p.startsWith("~/") || p.startsWith("~\\") ? home + p.slice(1) : p;
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf8").trim();
  } catch {
    return null;
  }
}

/** Roots from git: top level, main checkout and sibling worktrees. */
export function gitRoots(cwd: string): string[] {
  let dir = path.resolve(cwd);
  for (;;) {
    const dotGit = path.join(dir, ".git");
    let stat: fs.Stats | null = null;
    try {
      stat = fs.statSync(dotGit);
    } catch {
      stat = null;
    }
    if (stat) {
      const roots = [dir];
      let commonDir: string | null = null;
      if (stat.isDirectory()) {
        commonDir = dotGit;
      } else {
        const pointer = readText(dotGit)?.match(/^gitdir:\s*(.+)$/m)?.[1];
        if (pointer) {
          const gitDir = path.resolve(dir, pointer);
          const common = readText(path.join(gitDir, "commondir"));
          commonDir = common ? path.resolve(gitDir, common) : null;
        }
      }
      if (commonDir) {
        if (path.basename(commonDir) === ".git") roots.push(path.dirname(commonDir));
        let entries: string[] = [];
        try {
          entries = fs.readdirSync(path.join(commonDir, "worktrees"));
        } catch {
          entries = [];
        }
        for (const name of entries) {
          const gitFile = readText(path.join(commonDir, "worktrees", name, "gitdir"));
          if (gitFile) roots.push(path.dirname(gitFile));
        }
      }
      return [...new Set(roots)];
    }
    const parent = path.dirname(dir);
    if (parent === dir) return [];
    dir = parent;
  }
}

/** "workspace_roots" from omnodex-config.json, with ~ expanded. */
export function configuredRoots(home: string, userHome = os.homedir()): string[] {
  const raw = readText(path.join(home, "omnodex-config.json"));
  if (!raw) return [];
  try {
    const roots = (JSON.parse(raw) as { workspace_roots?: unknown }).workspace_roots;
    return Array.isArray(roots)
      ? roots.filter((r): r is string => typeof r === "string").map((r) => expandHome(r, userHome))
      : [];
  } catch {
    return [];
  }
}

/**
 * A cached resolver for one installation. `home` is OMNODEX_HOME, where the
 * configuration lives.
 */
export function createWorkspaceResolver(
  home: string = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex"),
): WorkspaceRootsFn {
  const configured = configuredRoots(home);
  const cache = new Map<string, string[]>();
  return (cwd: string): string[] => {
    let roots = cache.get(cwd);
    if (!roots) {
      roots = [...new Set([cwd, ...gitRoots(cwd), ...configured])];
      cache.set(cwd, roots);
    }
    return roots;
  };
}
