// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Keep a file Omnodex writes into a repository out of git, without touching
 * the repository's tracked files: the pattern goes in the clone's own
 * `info/exclude`, which is never committed or shared.
 *
 * Copilot runs every hook file in a repository's `.github/hooks/` for anyone
 * who opens it and refuses a tool call when a hook cannot start, so a
 * committed Omnodex hook file would stop Copilot for every person who does
 * not have Omnodex installed.
 */

import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as path from "node:path";

const MARK = "# omnodex";

function git(cwd: string, args: string[]): { ok: boolean; out: string } {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", windowsHide: true, timeout: 10_000 });
  return { ok: r.status === 0, out: (r.stdout ?? "").trim() };
}

/** The clone's info/exclude file for a project folder, or null outside a git work tree. */
export function excludeFileFor(projectPath: string): string | null {
  const inside = git(projectPath, ["rev-parse", "--is-inside-work-tree"]);
  if (!inside.ok || inside.out !== "true") return null;
  const file = git(projectPath, ["rev-parse", "--path-format=absolute", "--git-path", "info/exclude"]);
  return file.ok && file.out ? file.out : null;
}

/** Whether git already tracks the file, so excluding it would change nothing. */
export function isTracked(projectPath: string, relFile: string): boolean {
  return git(projectPath, ["ls-files", "--error-unmatch", "--", relFile]).ok;
}

/**
 * Add `/<relFile>` to the clone's exclude file. Returns the exclude file when
 * it was added (or already there), null when the project is not in a git repo.
 */
export async function addGitExclude(projectPath: string, relFile: string): Promise<string | null> {
  const file = excludeFileFor(projectPath);
  if (!file) return null;
  const line = `/${relFile.split(path.sep).join("/")}`;
  let text = "";
  try {
    text = await fs.readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (text.split(/\r?\n/).includes(line)) return file;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${MARK}\n${line}\n`, "utf8");
  return file;
}

/** Remove the line (and its marker) that addGitExclude wrote. True when something was removed. */
export async function removeGitExclude(projectPath: string, relFile: string): Promise<boolean> {
  const file = excludeFileFor(projectPath);
  if (!file) return false;
  let text: string;
  try {
    text = await fs.readFile(file, "utf8");
  } catch {
    return false;
  }
  const line = `/${relFile.split(path.sep).join("/")}`;
  const lines = text.split("\n");
  const at = lines.findIndex((l) => l.replace(/\r$/, "") === line);
  if (at === -1) return false;
  const from = at > 0 && lines[at - 1]!.replace(/\r$/, "") === MARK ? at - 1 : at;
  lines.splice(from, at - from + 1);
  await fs.writeFile(file, lines.join("\n"), "utf8");
  return true;
}
