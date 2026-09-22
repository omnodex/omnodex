// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Which part of a tool call a content pattern should look at.
 *
 * A command pattern (rm -rf, a reverse shell, an uninstall of Omnodex) is a
 * risk when the agent runs it, not when it writes about it in a document or
 * a ticket. These helpers pull out the two texts that matter:
 *
 *   exec    -- the command a shell tool is about to run: Bash and its
 *              equivalents on other platforms, and MCP tools that execute
 *              shell commands
 *   staged  -- content written into a file that will run or be loaded later:
 *              scripts, shell start-up files, git hooks, CI workflows, agent
 *              and package-manager config, environment files
 *
 * Tool names are matched on the bare name, so "mcp__desktop__execute_command"
 * counts as "execute_command". The field a tool uses is not enough on its
 * own: Codex's apply_patch carries its patch in a field named "command".
 */

import type { ToolInvokedEvent } from "@omnodex/shared";

/** Bare tool names whose parameters hold a command that is executed. */
const EXEC_TOOLS = new Set([
  "bash",
  "shell",
  "local_shell",
  "shell_command",
  "run_shell_command",
  "exec",
  "exec_command",
  "execute_command",
  "run_command",
  "run_terminal_cmd",
  "terminal",
  "powershell",
]);

/** Bare tool names that write file content. */
const WRITE_TOOLS = new Set([
  "write",
  "edit",
  "multiedit",
  "notebookedit",
  "create_file",
  "write_file",
  "edit_file",
  "apply_patch",
]);

/**
 * Files whose content is executed or loaded as configuration. Matched
 * against the full path with forward slashes, case-insensitively.
 */
const STAGED_TARGETS: readonly RegExp[] = [
  // Scripts and executable sources.
  /\.(?:sh|bash|zsh|fish|ksh|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|rb|pl|php)$/i,
  // Build and container entry points.
  /(?:^|\/)(?:makefile|justfile|dockerfile|containerfile)$/i,
  // Shell start-up files.
  /(?:^|\/)\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|profile|login)$/i,
  // Environment files.
  /(?:^|\/)\.env(?:\.[^/]*)?$/i,
  // Package-manager configuration.
  /(?:^|\/)(?:package\.json|\.npmrc|\.yarnrc(?:\.yml)?|\.pypirc|pip\.conf|pyproject\.toml)$/i,
  // Git hooks, husky hooks and CI workflows.
  /(?:^|\/)\.git\/hooks\//i,
  /(?:^|\/)\.husky\//i,
  /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i,
  // Agent configuration: settings, hooks and MCP server lists.
  /(?:^|\/)\.(?:claude|codex|gemini|cursor)\/[^/]*\.(?:json|toml)$/i,
  /(?:^|\/)\.claude\.json$/i,
  /(?:^|\/)\.?mcp\.json$/i,
  /(?:^|\/)hooks\.json$/i,
];

function bareToolName(toolName: string): string {
  const i = toolName.lastIndexOf("__");
  return (i === -1 ? toolName : toolName.slice(i + 2)).toLowerCase();
}

function asText(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
    return value.join(" ");
  }
  return null;
}

/** True when the tool writes file content (Write, Edit, apply_patch and similar). */
export function isWriteTool(event: ToolInvokedEvent): boolean {
  return WRITE_TOOLS.has(bareToolName(event.tool_name));
}

/** True when the tool runs a shell command. */
export function isExecTool(event: ToolInvokedEvent): boolean {
  return EXEC_TOOLS.has(bareToolName(event.tool_name));
}

/** Every file an apply_patch body adds, updates, deletes or moves to. */
export function patchTargets(patch: string): string[] {
  const out: string[] = [];
  const re = /^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$/gm;
  let m;
  while ((m = re.exec(patch)) !== null) out.push(m[1].trim());
  return out;
}

/** True when a path's content runs or is loaded as configuration. */
export function isStagedTarget(filePath: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  return STAGED_TARGETS.some((re) => re.test(p));
}

/** The command a shell tool is about to run, or null for any other tool. */
export function extractExecText(event: ToolInvokedEvent): string | null {
  if (!isExecTool(event)) return null;
  const params = (event.parameters ?? {}) as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of ["command", "cmd", "script", "args", "input"]) {
    const text = asText(params[key]);
    if (text) parts.push(text);
  }
  return parts.length > 0 ? parts.join("\n") : null;
}

export interface StagedContent {
  path: string;
  text: string;
}

/**
 * Content written into files that run or are loaded later. Empty for tools
 * that do not write, and for writes to any other kind of file.
 */
export function extractStagedContent(event: ToolInvokedEvent): StagedContent[] {
  const name = bareToolName(event.tool_name);
  if (!WRITE_TOOLS.has(name)) return [];
  const params = (event.parameters ?? {}) as Record<string, unknown>;

  if (name === "apply_patch") {
    const patch = asText(params.command) ?? asText(params.input) ?? asText(params.patch);
    return patch ? stagedFromPatch(patch) : [];
  }

  const path = ["file_path", "path", "filePath", "filename", "notebook_path"]
    .map((k) => params[k])
    .find((v): v is string => typeof v === "string");
  if (!path || !isStagedTarget(path)) return [];

  const parts: string[] = [];
  for (const key of ["content", "new_string", "new_source", "text"]) {
    const text = asText(params[key]);
    if (text) parts.push(text);
  }
  if (Array.isArray(params.edits)) {
    for (const edit of params.edits) {
      const text = asText((edit as Record<string, unknown> | null)?.new_string);
      if (text) parts.push(text);
    }
  }
  return parts.length > 0 ? [{ path, text: parts.join("\n") }] : [];
}

/** Added lines per file from an apply_patch body, for staged targets only. */
function stagedFromPatch(patch: string): StagedContent[] {
  const out: StagedContent[] = [];
  let current: StagedContent | null = null;
  for (const line of patch.split("\n")) {
    const header = /^\*\*\* (?:Add|Update) File: (.+)$/.exec(line);
    if (header) {
      const path = header[1].trim();
      current = isStagedTarget(path) ? { path, text: "" } : null;
      if (current) out.push(current);
      continue;
    }
    if (/^\*\*\* /.test(line)) {
      current = null;
      continue;
    }
    if (current && line.startsWith("+")) current.text += line.slice(1) + "\n";
  }
  return out.filter((c) => c.text.length > 0);
}
