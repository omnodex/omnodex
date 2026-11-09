// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * CursorInterceptor
 *
 * Installs and removes the Omnodex hook shim for Cursor. Cursor reads
 * `~/.cursor/hooks.json` for every project and `<project>/.cursor/hooks.json`
 * for one, in the version 1 schema: `{ version: 1, hooks: { <event>: [{
 * command, timeout }] } }`. A hook has a `command` and a `timeout` and
 * nothing else that carries an environment or a working directory, so the
 * command itself sets OMNODEX_HOME where the host's shell allows it.
 *
 * Subscribed: sessionStart, sessionEnd, beforeSubmitPrompt, preToolUse,
 * postToolUse, postToolUseFailure, subagentStart, subagentStop,
 * beforeShellExecution, beforeMCPExecution and beforeReadFile. Cursor fails
 * open when a hook crashes or times out, but blocks on a permission hook
 * that prints invalid JSON, so the shim always exits 0 with one valid JSON
 * document.
 *
 * Other hooks in the file are never touched: Omnodex's entries are the ones
 * whose command names the launcher or the shim.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { EmitFn, Interceptor, StopFn } from "@omnodex/shared";

export interface CursorInterceptorOptions {
  /** Absolute path to the project whose `.cursor/hooks.json` gets the entries. */
  projectPath: string;
  /** Absolute path to the compiled cursor-hook-shim.js (or the launcher). */
  shimPath: string;
  /** Where Omnodex writes the event log. Set for the shim where the shell allows it. */
  omnodexHome: string;
  /** Per-hook timeout in seconds. Default: 30. */
  timeoutSeconds?: number;
  /** Enable debug logging in the shim (sets OMNODEX_DEBUG=1). */
  debug?: boolean;
  /** Absolute path to the Node.js binary used in hook commands. Defaults to "node". */
  nodePath?: string;
  /** Absolute hooks file to write instead of `<project>/.cursor/hooks.json`. */
  hooksPath?: string;
  /** Arguments for the launcher, right after its path. User-level installs pass the user-scope marker. */
  launcherArgs?: string[];
  /** The platform the command is written for; defaults to this one. For tests. */
  platform?: NodeJS.Platform;
}

interface HookEntry {
  command?: string;
  timeout?: number;
  [key: string]: unknown;
}

interface HooksFile {
  version?: number;
  hooks?: Record<string, HookEntry[]>;
  [key: string]: unknown;
}

export const CURSOR_EVENT_NAMES = [
  "sessionStart",
  "sessionEnd",
  "beforeSubmitPrompt",
  "preToolUse",
  "postToolUse",
  "postToolUseFailure",
  "subagentStart",
  "subagentStop",
  "beforeShellExecution",
  "beforeMCPExecution",
  "beforeReadFile",
] as const;

/** Our hook commands name the launcher or the shim; nothing else in the file does. */
const MANAGED = /cursor-hook-(?:launcher|shim)/;

const isManaged = (entry: HookEntry): boolean => typeof entry.command === "string" && MANAGED.test(entry.command);

export class CursorInterceptor implements Interceptor {
  readonly name = "cursor-hooks";
  readonly kind = "cursor-hook" as const;
  readonly options: CursorInterceptorOptions & { timeoutSeconds: number; debug: boolean };

  constructor(options: CursorInterceptorOptions) {
    this.options = { ...options, timeoutSeconds: options.timeoutSeconds ?? 30, debug: options.debug ?? false };
  }

  async start(_emit: EmitFn): Promise<StopFn> {
    await this.install();
    return async () => {
      await this.uninstall();
    };
  }

  hooksFilePath(): string {
    return this.options.hooksPath ?? path.join(this.options.projectPath, ".cursor", "hooks.json");
  }

  async install(): Promise<void> {
    const file = this.hooksFilePath();
    await fs.mkdir(path.dirname(file), { recursive: true });
    const existing = await this.read(file);
    const hooks = withoutManaged(existing.hooks);
    for (const name of CURSOR_EVENT_NAMES) hooks[name] = [...(hooks[name] ?? []), this.entry(name)];
    await this.write(file, { ...existing, version: 1, hooks });
  }

  async uninstall(): Promise<void> {
    const file = this.hooksFilePath();
    const existing = await this.read(file);
    if (!existing.hooks) return;
    const hooks = withoutManaged(existing.hooks);
    if (Object.keys(hooks).length === 0) {
      const { hooks: _gone, version: _version, ...rest } = existing;
      if (Object.keys(rest).length === 0) await fs.rm(file, { force: true });
      else await this.write(file, rest);
      return;
    }
    await this.write(file, { ...existing, hooks });
  }

  /** The command line for one event. */
  private entry(eventName: (typeof CURSOR_EVENT_NAMES)[number]): HookEntry {
    const timeout = eventName === "sessionEnd" ? Math.min(this.options.timeoutSeconds, 10) : this.options.timeoutSeconds;
    const args = this.options.launcherArgs ?? [];
    const node = this.options.nodePath ?? "node";
    if ((this.options.platform ?? process.platform) === "win32") {
      // cmd.exe has no inline environment assignment that PowerShell shares,
      // so the shim finds the event log from the home it runs with.
      return { command: [node, this.options.shimPath, ...args].map(winQuote).join(" "), timeout };
    }
    const env = [["OMNODEX_HOME", this.options.omnodexHome], ...(this.options.debug ? [["OMNODEX_DEBUG", "1"]] : [])];
    const command = `${env.map(([k, v]) => `${k}=${shellQuote(v!)}`).join(" ")} ${[node, this.options.shimPath, ...args].map(shellQuote).join(" ")}`;
    return { command, timeout };
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

function withoutManaged(hooks: Record<string, HookEntry[]> | undefined): Record<string, HookEntry[]> {
  const out: Record<string, HookEntry[]> = {};
  for (const [name, entries] of Object.entries(hooks ?? {})) {
    const kept = (entries ?? []).filter((e) => !isManaged(e));
    if (kept.length > 0) out[name] = kept;
  }
  return out;
}

function shellQuote(value: string): string {
  if (value === "") return `""`;
  if (/^[A-Za-z0-9_\-./:=]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function winQuote(value: string): string {
  return /^[A-Za-z0-9_\-./:\\]+$/.test(value) ? value : `"${value.replace(/"/g, '\\"')}"`;
}
