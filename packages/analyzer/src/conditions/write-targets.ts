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
import { extractExecText, isWriteTool, patchTargets } from "./scope.js";

const PATH_KEYS = ["file_path", "path", "filePath", "filename", "notebook_path"];

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

function commandTargets(command: string): string[] {
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
