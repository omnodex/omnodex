// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The files a tool call writes to.
 *
 * For file-writing tools that is the file they name (every file, for an
 * apply_patch). For shell tools it is read from the command, heuristically:
 * output redirections (> and >>, including 2> and &>), tee arguments, and
 * the destination of cp and mv. Paths that are variables or relative are
 * returned as written; the caller decides what to do with them. /dev paths
 * (/dev/null, /dev/stderr) are never write targets.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { bareToolName, extractExecText, isWriteTool, patchTargets } from "./scope.js";

const PATH_KEYS = ["file_path", "path", "filePath", "filename", "notebook_path", "TargetFile", "Path"];

function unquote(token: string): string {
  return token.replace(/^['"]|['"]$/g, "");
}

/**
 * The command with heredoc bodies and quoted text removed, so a ">" in a
 * sed expression, a Python snippet or a heredoc's text is not read as a
 * redirection. The heredoc's own redirect (cat > file <<EOF) survives.
 */
function shellSkeleton(command: string): string {
  const lines = command.split("\n");
  const kept: string[] = [];
  let terminator: string | null = null;
  for (const line of lines) {
    if (terminator !== null) {
      if (line.trim() === terminator) terminator = null;
      continue;
    }
    kept.push(line);
    const heredoc = /<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1/.exec(line);
    if (heredoc) terminator = heredoc[2];
  }
  // A quoted word that could be a single path ("$HOME/.bashrc") is kept;
  // one with spaces or shell metacharacters is text, and is blanked.
  const blank = (quoted: string, inner: string): string =>
    /^[^\s<>|;&]*$/.test(inner) ? quoted : quoted[0] + quoted[0];
  return kept
    .join("\n")
    .replace(/'([^']*)'/g, blank)
    .replace(/"((?:[^"\\]|\\.)*)"/g, blank);
}

/** The files a shell command writes to: redirections, tee, and cp/mv destinations. */
export function commandTargets(command: string): string[] {
  const out: string[] = [];
  command = shellSkeleton(command);

  // Redirections: > file, >> file, 2> file, &> file. Not >&2 or <.
  const redirect = /(?:^|[^<>&\d])(?:\d|&)?>{1,2}(?!&)\s*([^\s;&|<>()]+)/g;
  let m;
  while ((m = redirect.exec(command)) !== null) out.push(unquote(m[1]));

  // Segment by command separators, then look at tee, cp and mv.
  for (const segment of command.split(/&&|\|\||[;|\n]/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    while (tokens[0] === "sudo" || tokens[0] === "command") tokens.shift();
    const [cmd, ...rest] = tokens;
    if (!cmd) continue;
    const args = rest.filter((t) => !t.startsWith("-") && !/^\d?>/.test(t)).map(unquote);
    if (cmd === "tee") {
      out.push(...args);
    } else if (cmd === "cp" || cmd === "mv") {
      const t = rest.indexOf("-t");
      if (t !== -1 && rest[t + 1]) out.push(unquote(rest[t + 1]));
      else if (args.length >= 2) out.push(args[args.length - 1]);
    }
  }

  return out.filter((p) => p.length > 0 && !p.startsWith("/dev/"));
}

export function extractWriteTargets(event: ToolInvokedEvent): string[] {
  const params = (event.parameters ?? {}) as Record<string, unknown>;
  if (isWriteTool(event)) {
    const patch = [params.command, params.input, params.patch].find(
      (v): v is string => typeof v === "string" && v.includes("*** "),
    );
    if (patch) return patchTargets(patch);
    return PATH_KEYS.map((k) => params[k]).filter((v): v is string => typeof v === "string");
  }
  const command = extractExecText(event);
  return command ? commandTargets(command) : [];
}

/** What a call changes on disk: everything it writes, moves or deletes. */
export interface ChangeTargets {
  /** Files and folders it writes, changes, moves or deletes, as written in the call. */
  changed: string[];
  /** Those it moves away or deletes, which takes everything under them too. */
  removed: string[];
}

const REMOVERS = new Set(["rm", "rmdir", "unlink", "shred", "del", "erase", "rd", "remove-item", "ri"]);
const MOVERS = new Set(["mv", "move", "move-item", "mi", "rename-item", "ren", "rename"]);
const TOUCHERS = new Set(["truncate", "touch", "set-content", "sc", "add-content", "ac", "clear-content", "clc", "out-file", "new-item", "ni"]);
const OWNERS = new Set(["chmod", "chown", "chgrp"]);
const LAST_ARG = new Set(["ln", "install", "rsync"]);
/** Inline code that writes: its quoted paths count as changed. */
const WRITING_CODE =
  /open\([^)]*,\s*['"][^'"]*[wax+]|write_text|write_bytes|writeFile|appendFile|\.unlink|unlinkSync|os\.remove|os\.rename|os\.replace|shutil\.|rmSync|renameSync|\bFile\.(?:write|delete|rename)|\bunlink\b/;

/** Moved or deleted through a file tool rather than a shell. */
const MOVE_TOOLS = new Set(["move_file", "rename_file"]);
const DELETE_TOOLS = new Set(["delete_file", "remove_file"]);

function inlineCodeTargets(command: string): string[] {
  const out: string[] = [];
  const inline = /\b(?:python[\d.]*|node|perl|ruby|php)\s+(?:-\w+\s+)*-[ce]\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/g;
  let m;
  while ((m = inline.exec(command)) !== null) {
    const code = m[1] ?? m[2] ?? "";
    if (!WRITING_CODE.test(code)) continue;
    for (const q of code.matchAll(/\\?(['"])([^'"]*?)\\?\1/g)) {
      if (/^[^\s\\]*[/.][^\s\\]*$/.test(q[2]!)) out.push(q[2]!);
    }
  }
  return out;
}

/** The files a shell command changes, beyond the writes commandTargets reads. */
export function commandChanges(command: string): ChangeTargets {
  const changed = commandTargets(command);
  const removed: string[] = [];
  changed.push(...inlineCodeTargets(command));

  for (const segment of shellSkeleton(command).split(/&&|\|\||[;|\n]/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    while (tokens[0] === "sudo" || tokens[0] === "command" || tokens[0] === "exec" || /^[A-Za-z_]\w*=/.test(tokens[0] ?? "")) tokens.shift();
    const first = tokens.shift();
    if (!first) continue;
    const cmd = first.replace(/^.*[/\\]/, "").replace(/\.exe$/i, "").toLowerCase();
    const flagged = tokens.filter((t) => !/^\d?[<>]/.test(t));
    const args = flagged.filter((t) => !t.startsWith("-")).map(unquote).filter(Boolean);

    if (REMOVERS.has(cmd)) {
      changed.push(...args);
      removed.push(...args);
    } else if (MOVERS.has(cmd)) {
      changed.push(...args);
      removed.push(...args.slice(0, -1));
    } else if (TOUCHERS.has(cmd)) {
      changed.push(...args);
    } else if (OWNERS.has(cmd)) {
      changed.push(...args.slice(1));
    } else if (LAST_ARG.has(cmd)) {
      if (args.length >= 2) changed.push(args[args.length - 1]!);
    } else if ((cmd === "sed" || cmd === "gsed" || cmd === "perl") && flagged.some((t) => /^(?:-[a-zA-Z]*i|--in-place)/.test(t))) {
      changed.push(...args);
    } else if (cmd === "patch" && args[0]) {
      changed.push(args[0]);
    } else if (cmd === "dd") {
      for (const a of args) if (a.startsWith("of=")) changed.push(a.slice(3));
    } else if (cmd === "find" && flagged.some((t) => t === "-delete" || t === "-exec" || t === "-execdir") && flagged.some((t) => t === "-delete" || t === "rm")) {
      if (args[0]) {
        changed.push(args[0]);
        removed.push(args[0]);
      }
    } else if (cmd === "git") {
      const [sub, ...rest] = args;
      if (sub === "rm" || sub === "mv") {
        changed.push(...rest);
        removed.push(...(sub === "rm" ? rest : rest.slice(0, -1)));
      } else if (sub === "restore" || (sub === "checkout" && flagged.includes("--"))) {
        // After a bare "--" every word is a path; restore takes only paths.
        const after = sub === "checkout" ? flagged.slice(flagged.indexOf("--") + 1).map(unquote) : rest;
        changed.push(...after);
      }
    }
  }
  const usable = (p: string): boolean => p.length > 0 && !p.startsWith("/dev/");
  return { changed: [...new Set(changed)].filter(usable), removed: [...new Set(removed)].filter(usable) };
}

/** What a tool call changes on disk: for a file tool, what it writes, moves or deletes; for a shell, commandChanges. */
export function extractChangeTargets(event: ToolInvokedEvent): ChangeTargets {
  const params = (event.parameters ?? {}) as Record<string, unknown>;
  const name = bareToolName(event.tool_name);
  const text = (...keys: string[]): string[] => keys.map((k) => params[k]).filter((v): v is string => typeof v === "string");
  if (MOVE_TOOLS.has(name)) {
    const from = text("source", "from", "old_path", "Source");
    return { changed: [...from, ...text("destination", "to", "new_path", "Destination")], removed: from };
  }
  if (DELETE_TOOLS.has(name)) {
    const gone = PATH_KEYS.map((k) => params[k]).filter((v): v is string => typeof v === "string");
    return { changed: gone, removed: gone };
  }
  if (isWriteTool(event)) {
    const patch = [params.command, params.input, params.patch].find(
      (v): v is string => typeof v === "string" && v.includes("*** "),
    );
    const removed = patch ? [...patch.matchAll(/^\*\*\* Delete File: (.+)$/gm)].map((m) => m[1]!.trim()) : [];
    return { changed: extractWriteTargets(event), removed };
  }
  const command = extractExecText(event);
  return command ? commandChanges(command) : { changed: [], removed: [] };
}
