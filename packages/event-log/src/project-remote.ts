// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The git remote a session's project belongs to.
 *
 * A project folder has a different path on every machine, and often a
 * different name too, while its `origin` remote is the same. Capture reads
 * `origin` from the repository's config when a session starts and records it
 * on `session.started` as `project_remote`, normalized so the ssh and https
 * forms of one repository compare equal.
 *
 * Reads files only (no git process), so it fits in a hook's time budget:
 * a few stats walking up to the repository, then one small config file.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { TraceEvent } from "@omnodex/shared";

/** How many parent folders to search for `.git` before giving up. */
const MAX_DEPTH = 40;

/**
 * `host/owner/repo` for a remote URL, or undefined for a local path or
 * anything unparseable. The host is lowercased; the path keeps its case,
 * since some hosts treat it as case-sensitive.
 *
 * - `git@github.com:owner/repo.git` → `github.com/owner/repo`
 * - `ssh://git@github.com:22/owner/repo` → `github.com/owner/repo`
 * - `https://user:token@github.com/owner/repo.git` → `github.com/owner/repo`
 */
export function normalizeGitRemote(url: string): string | undefined {
  const raw = url.trim();
  if (!raw) return undefined;
  let host: string;
  let repoPath: string;
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw);
  if (scheme) {
    const kind = scheme[1]!.toLowerCase();
    if (kind === "file") return undefined;
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      return undefined;
    }
    host = parsed.hostname;
    repoPath = decodeURIComponent(parsed.pathname);
  } else {
    // scp-like syntax: [user@]host:path. A colon after a slash, or a
    // single letter before it (a Windows drive), means a local path.
    const scp = /^(?:[^@/]+@)?([^:/]+):(.+)$/.exec(raw);
    if (!scp || scp[1]!.length === 1) return undefined;
    host = scp[1]!;
    repoPath = scp[2]!;
  }
  host = host.toLowerCase().replace(/^\[|\]$/g, "");
  repoPath = repoPath.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "").replace(/\/+$/, "");
  if (!host || !repoPath) return undefined;
  return `${host}/${repoPath}`;
}

/** The `url` of `[remote "origin"]` in a git config file's text. */
export function originUrlFromConfig(text: string): string | undefined {
  let inOrigin = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const section = /^\[\s*([^\]\s"]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/.exec(line);
    if (section) {
      inOrigin = section[1]!.toLowerCase() === "remote" && section[2] === "origin";
      continue;
    }
    if (!inOrigin) continue;
    const kv = /^url\s*=\s*(.*)$/i.exec(line);
    if (kv) {
      let value = kv[1]!.trim();
      if (value.startsWith("\"") && value.endsWith("\"") && value.length >= 2) value = value.slice(1, -1);
      return value || undefined;
    }
  }
  return undefined;
}

async function readText(file: string): Promise<string | undefined> {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * The repository's common git directory for a folder: the `.git` folder,
 * or for a linked worktree or submodule the directory its `.git` file
 * names, followed to the shared directory that holds `config`.
 */
async function commonGitDir(start: string): Promise<string | undefined> {
  let dir = path.resolve(start);
  for (let i = 0; i < MAX_DEPTH; i++) {
    const dotGit = path.join(dir, ".git");
    let stat;
    try {
      stat = await fs.stat(dotGit);
    } catch {
      stat = undefined;
    }
    if (stat?.isDirectory()) return dotGit;
    if (stat?.isFile()) {
      const pointer = /^gitdir:\s*(.+)$/m.exec((await readText(dotGit)) ?? "");
      if (!pointer) return undefined;
      const gitDir = path.resolve(dir, pointer[1]!.trim());
      const common = (await readText(path.join(gitDir, "commondir")))?.trim();
      return common ? path.resolve(gitDir, common) : gitDir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
  return undefined;
}

/** The normalized `origin` remote for a project folder, if it has one. */
export async function readProjectRemote(projectPath: string | undefined): Promise<string | undefined> {
  if (!projectPath || projectPath === "unknown") return undefined;
  try {
    const gitDir = await commonGitDir(projectPath);
    if (!gitDir) return undefined;
    const config = await readText(path.join(gitDir, "config"));
    const url = config ? originUrlFromConfig(config) : undefined;
    return url ? normalizeGitRemote(url) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The events with `project_remote` set on each `session.started` whose
 * project folder has an `origin` remote. Other events pass through.
 */
export async function withProjectRemote(events: TraceEvent[]): Promise<TraceEvent[]> {
  if (!events.some((e) => e.event_type === "session.started")) return events;
  return Promise.all(
    events.map(async (e) => {
      if (e.event_type !== "session.started" || e.project_remote) return e;
      const remote = await readProjectRemote(e.project_path);
      return remote ? { ...e, project_remote: remote } : e;
    }),
  );
}
