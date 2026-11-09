// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * CopilotInterceptor
 *
 * Installs and removes the Omnodex hook shim for GitHub Copilot (the CLI and
 * the VS Code agent share one hook format). Copilot reads every JSON file in
 * `~/.copilot/hooks/` (or `$COPILOT_HOME/hooks/`) for all projects and in
 * `<project>/.github/hooks/` for one, so Omnodex owns a file of its own,
 * `omnodex.json`, in whichever folder applies and never edits a user's files.
 *
 * Events are registered under PascalCase names, which makes Copilot send the
 * VS Code compatible payload (snake_case fields, Claude Code's tool names).
 * Subscribed: SessionStart, SessionEnd, UserPromptSubmit, PreToolUse,
 * PostToolUse, PostToolUseFailure, PermissionRequest, SubagentStart and
 * SubagentStop.
 *
 * Copilot denies a tool call when a preToolUse hook crashes or exits
 * non-zero, so the shim always exits 0.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { EmitFn, Interceptor, StopFn } from "@omnodex/shared";

export interface CopilotInterceptorOptions {
  /** Absolute path to the project whose `.github/hooks/` gets the file. */
  projectPath: string;
  /** Absolute path to the compiled copilot-hook-shim.js (or the launcher). */
  shimPath: string;
  /** Where Omnodex writes the event log. Passed to the shim as env. */
  omnodexHome: string;
  /** Per-hook timeout in seconds. Default: 30. */
  timeoutSeconds?: number;
  /** Enable debug logging in the shim (sets OMNODEX_DEBUG=1). */
  debug?: boolean;
  /** Absolute path to the Node.js binary used in hook commands. Defaults to "node". */
  nodePath?: string;
  /**
   * Shim path relative to the user's home directory, with forward slashes.
   * The hook then runs `node "$HOME/<path>"` on every host that reads the
   * file, with no env prefix.
   */
  homeRelativeShimPath?: string;
  /** Absolute hooks file to write instead of `<project>/.github/hooks/omnodex.json`. */
  hooksPath?: string;
  /** Arguments for the launcher, right after its path. User-level installs pass the user-scope marker. */
  launcherArgs?: string[];
}

/** One entry of a Copilot hooks file. */
interface HookEntry {
  type: "command";
  command?: string;
  bash?: string;
  powershell?: string;
  timeoutSec?: number;
  [key: string]: unknown;
}

interface HooksFile {
  version?: number;
  hooks?: Record<string, HookEntry[]>;
  [key: string]: unknown;
}

export const COPILOT_EVENT_NAMES = [
  "SessionStart",
  "SessionEnd",
  "UserPromptSubmit",
  "PreToolUse",
  "PostToolUse",
  "PostToolUseFailure",
  "PermissionRequest",
  "SubagentStart",
  "SubagentStop",
] as const;

/** Our hook commands name the launcher or the shim; nothing else in the file does. */
const MANAGED = /copilot-hook-(?:launcher|shim)/;

const isManaged = (entry: HookEntry): boolean =>
  [entry.command, entry.bash, entry.powershell].some((c) => typeof c === "string" && MANAGED.test(c));

export class CopilotInterceptor implements Interceptor {
  readonly name = "copilot-hooks";
  readonly kind = "copilot-hook" as const;
  readonly options: CopilotInterceptorOptions & { timeoutSeconds: number; debug: boolean };

  constructor(options: CopilotInterceptorOptions) {
    this.options = { ...options, timeoutSeconds: options.timeoutSeconds ?? 30, debug: options.debug ?? false };
  }

  async start(_emit: EmitFn): Promise<StopFn> {
    await this.install();
    return async () => {
      await this.uninstall();
    };
  }

  hooksFilePath(): string {
    return this.options.hooksPath ?? path.join(this.options.projectPath, ".github", "hooks", "omnodex.json");
  }

  async install(): Promise<void> {
    const file = this.hooksFilePath();
    await fs.mkdir(path.dirname(file), { recursive: true });
    const existing = await this.read(file);
    const hooks: Record<string, HookEntry[]> = {};
    for (const [name, entries] of Object.entries(existing.hooks ?? {})) {
      const kept = (entries ?? []).filter((e) => !isManaged(e));
      if (kept.length > 0) hooks[name] = kept;
    }
    for (const name of COPILOT_EVENT_NAMES) hooks[name] = [...(hooks[name] ?? []), this.entry(name)];
    await this.write(file, { ...existing, version: 1, hooks });
  }

  async uninstall(): Promise<void> {
    const file = this.hooksFilePath();
    const existing = await this.read(file);
    if (!existing.hooks) return;
    const hooks: Record<string, HookEntry[]> = {};
    for (const [name, entries] of Object.entries(existing.hooks)) {
      const kept = (entries ?? []).filter((e) => !isManaged(e));
      if (kept.length > 0) hooks[name] = kept;
    }
    if (Object.keys(hooks).length === 0) {
      const { hooks: _gone, version: _version, ...rest } = existing;
      if (Object.keys(rest).length === 0) await fs.rm(file, { force: true });
      else await this.write(file, rest);
      return;
    }
    await this.write(file, { ...existing, hooks });
  }

  private entry(eventName: (typeof COPILOT_EVENT_NAMES)[number]): HookEntry {
    const timeoutSec = eventName === "SessionEnd" ? Math.min(this.options.timeoutSeconds, 10) : this.options.timeoutSeconds;
    const args = this.options.launcherArgs ?? [];
    if (this.options.homeRelativeShimPath !== undefined) {
      return { type: "command", command: `node "$HOME/${this.options.homeRelativeShimPath}"` + args.map((a) => ` ${shellQuote(a)}`).join(""), timeoutSec };
    }
    const node = this.options.nodePath ?? "node";
    const env = [["OMNODEX_HOME", this.options.omnodexHome], ...(this.options.debug ? [["OMNODEX_DEBUG", "1"]] : [])];
    const bash = `${env.map(([k, v]) => `${k}=${shellQuote(v!)}`).join(" ")} ${shellQuote(node)} ${shellQuote(this.options.shimPath)}` + args.map((a) => ` ${shellQuote(a)}`).join("");
    const powershell = `${env.map(([k, v]) => `$env:${k}=${psQuote(v!)};`).join(" ")} & ${psQuote(node)} ${psQuote(this.options.shimPath)}` + args.map((a) => ` ${psQuote(a)}`).join("");
    return { type: "command", bash, powershell, timeoutSec };
  }

  private async read(file: string): Promise<HooksFile> {
    try {
      const raw = await fs.readFile(file, "utf8");
      return raw.trim() ? (JSON.parse(raw) as HooksFile) : {};
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  private async write(file: string, content: HooksFile): Promise<void> {
    await fs.writeFile(file, JSON.stringify(content, null, 2) + "\n", "utf8");
  }
}

function shellQuote(value: string): string {
  if (value === "") return `""`;
  if (/^[A-Za-z0-9_\-./:=]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
