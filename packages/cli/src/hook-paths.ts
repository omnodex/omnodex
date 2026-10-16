// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * hook-paths.ts
 *
 * Finds Omnodex hook commands that name a path this machine does not have.
 *
 * A project hooks file can arrive from another machine: committed to a shared
 * repo, or carried by a folder sync. When its command names that machine's
 * launcher or OMNODEX_HOME (say /Users/<name>/.omnodex on a Linux host), the
 * hook fails on every call, and an agent that sees the failure may try to
 * repair the filesystem itself, for example by asking to create the missing
 * directory with sudo. `omnodex status` reports these so the fix is a
 * reinstall instead.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";

export interface MissingHookPath {
  /** What the path is for in the command. */
  kind: "launcher" | "omnodex-home" | "node";
  /** The path as this machine would resolve it. */
  path: string;
}

/** True for a POSIX absolute path or a Windows drive or UNC path. */
function isAbsoluteAnywhere(p: string): boolean {
  return p.startsWith("/") || /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\");
}

/** Replaces the home references a hook command may use with this machine's home. */
function expandHome(p: string, home: string): string {
  return p
    .replace(/^~(?=[\\/]|$)/, home)
    .replace(/\$\{HOME\}|\$HOME\b/g, home)
    .replace(/%USERPROFILE%/gi, home);
}

/**
 * Splits a shell or cmd.exe command into words, joining quoted pieces with
 * their neighbors the way a shell would, and drops the quotes.
 */
function words(command: string): string[] {
  const out: string[] = [];
  for (const match of command.matchAll(/(?:[^\s'"]+|'[^']*'|"[^"]*")+/g)) {
    out.push(match[0].replace(/'([^']*)'|"([^"]*)"/g, (_m, single, double) => single ?? double ?? ""));
  }
  return out;
}

/**
 * The paths an Omnodex hook command depends on: OMNODEX_HOME, the launcher
 * or shim script, and an absolute node binary. Relative paths and bare
 * `node` are left out; they resolve wherever the command runs.
 */
export function hookCommandPaths(command: string, home: string): MissingHookPath[] {
  const found: MissingHookPath[] = [];
  for (const word of words(command)) {
    const env = /^OMNODEX_HOME=(.*)$/.exec(word);
    if (env) {
      found.push({ kind: "omnodex-home", path: expandHome(env[1], home) });
      continue;
    }
    const expanded = expandHome(word, home);
    if (!isAbsoluteAnywhere(expanded)) continue;
    if (/\.[cm]?js$/i.test(expanded)) {
      found.push({ kind: "launcher", path: expanded });
    } else if (/^node(\.exe)?$/i.test(path.basename(expanded.replace(/\\/g, "/")))) {
      found.push({ kind: "node", path: expanded });
    }
  }
  return found.filter((p) => isAbsoluteAnywhere(p.path));
}

/** Every string under a "command" key whose value mentions Omnodex. */
function omnodexCommands(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) omnodexCommands(item, out);
  } else if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "command" && typeof child === "string" && /omnodex/i.test(child)) out.push(child);
      else omnodexCommands(child, out);
    }
  }
  return out;
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * The paths named by the Omnodex hook commands in a hooks or settings file
 * that do not exist on this machine, each listed once. Empty when the file
 * is not JSON or every path resolves.
 */
export async function findMissingHookPaths(
  fileContent: string,
  options: { home: string; exists?: (p: string) => Promise<boolean> },
): Promise<MissingHookPath[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fileContent);
  } catch {
    return [];
  }
  const exists = options.exists ?? pathExists;
  const seen = new Set<string>();
  const missing: MissingHookPath[] = [];
  for (const command of omnodexCommands(parsed)) {
    for (const entry of hookCommandPaths(command, options.home)) {
      if (seen.has(entry.path)) continue;
      seen.add(entry.path);
      if (!(await exists(entry.path))) missing.push(entry);
    }
  }
  return missing;
}
