// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * CodexInterceptor
 *
 * Installs and removes the Omnodex hook shim in a Codex project by editing
 * `<projectPath>/.codex/hooks.json`. On start() it writes the hook entries;
 * the returned stop function removes only the Omnodex-managed entries.
 *
 * Events subscribed:
 *
 *   SessionStart
 *   PreToolUse   (matcher "*")
 *   PostToolUse  (matcher "*")
 *   Stop
 *
 * Note: Codex hooks require the user to have `hooks = true` set in
 * their `~/.codex/config.toml` (or the project-local equivalent). The
 * interceptor cannot set this flag automatically because config.toml uses
 * TOML format and is outside our managed JSON scope.
 *
 * Note: Codex does not support `async: true` on hook handlers. All hooks
 * run synchronously. The shim is designed to be fast (<50ms typical).
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { EmitFn, Interceptor, StopFn } from "@omnodex/shared";

export interface CodexInterceptorOptions {
  /** Absolute path to the Codex project whose hooks we are wiring. */
  projectPath: string;
  /** Absolute path to the compiled codex-hook-shim.js. */
  shimPath: string;
  /** Where Omnodex should write the event log. Passed to the shim as env. */
  omnodexHome: string;
  /** Per-handler timeout in seconds. Default: 30. */
  timeoutSeconds?: number;
  /** Enable debug logging in the shim (sets OMNODEX_DEBUG=1). */
  debug?: boolean;
  /**
   * Absolute path to the Node.js binary to use in hook commands.
   * Defaults to process.execPath at install time. Needed because
   * non-interactive shells (e.g. Codex WSL agent) may not have
   * nvm/fnm/volta in PATH.
   */
  nodePath?: string;
  /**
   * Target platform for hook command syntax. Defaults to process.platform.
   * Set explicitly in tests or when cross-compiling hooks for a different OS.
   */
  platform?: NodeJS.Platform;
}

interface HooksFile {
  hooks?: {
    [eventName: string]: HookMatcherGroup[];
  };
  [key: string]: unknown;
}

interface HookMatcherGroup {
  matcher?: string;
  hooks: HookHandler[];
}

interface HookHandler {
  type: "command";
  command: string;
  timeout?: number;
  statusMessage?: string;
  [key: string]: unknown;
}

const OMNODEX_TAG = "omnodex-managed";

const EVENT_NAMES = [
  "SessionStart",
  "PreToolUse",
  "PostToolUse",
  "Stop",
] as const;

export class CodexInterceptor implements Interceptor {
  readonly name = "codex-hooks";
  readonly kind = "codex-hook" as const;
  readonly options: Required<
    Pick<CodexInterceptorOptions, "timeoutSeconds" | "debug" | "platform">
  > &
    CodexInterceptorOptions;

  constructor(options: CodexInterceptorOptions) {
    this.options = {
      ...options,
      timeoutSeconds: options.timeoutSeconds ?? 30,
      debug: options.debug ?? false,
      platform: options.platform ?? process.platform,
    };
  }

  async start(_emit: EmitFn): Promise<StopFn> {
    await this.install();
    return async () => {
      await this.uninstall();
    };
  }

  hooksFilePath(): string {
    return path.join(this.options.projectPath, ".codex", "hooks.json");
  }

  async install(): Promise<void> {
    const hooksPath = this.hooksFilePath();
    const dir = path.dirname(hooksPath);
    await fs.mkdir(dir, { recursive: true });

    const existing = await this.readHooks(hooksPath);
    const next: HooksFile = { ...existing };
    next.hooks = { ...(existing.hooks ?? {}) };

    for (const eventName of EVENT_NAMES) {
      const groups = [...(next.hooks[eventName] ?? [])];
      // Strip any prior Omnodex handlers to keep install idempotent.
      const filtered = groups
        .map((g) => ({
          ...g,
          hooks: (g.hooks ?? []).filter((h) => h[OMNODEX_TAG] !== true),
        }))
        .filter((g) => g.hooks.length > 0);
      filtered.push(this.makeMatcherGroup());
      next.hooks[eventName] = filtered;
    }

    await this.writeHooks(hooksPath, next);
  }

  async uninstall(): Promise<void> {
    const hooksPath = this.hooksFilePath();
    const existing = await this.readHooks(hooksPath);
    if (!existing.hooks) return;

    const nextHooks: Record<string, HookMatcherGroup[]> = {};
    for (const [eventName, groups] of Object.entries(existing.hooks)) {
      const cleaned = (groups ?? [])
        .map((g) => ({
          ...g,
          hooks: (g.hooks ?? []).filter((h) => h[OMNODEX_TAG] !== true),
        }))
        .filter((g) => g.hooks.length > 0);
      if (cleaned.length > 0) {
        nextHooks[eventName] = cleaned;
      }
    }

    const next: HooksFile = { ...existing, hooks: nextHooks };
    if (Object.keys(nextHooks).length === 0) {
      delete next.hooks;
    }
    await this.writeHooks(hooksPath, next);
  }

  private makeMatcherGroup(): HookMatcherGroup {
    return {
      matcher: "*",
      hooks: [
        {
          type: "command",
          command: this.shimCommand(),
          timeout: this.options.timeoutSeconds,
          [OMNODEX_TAG]: true,
        },
      ],
    };
  }

  private shimCommand(): string {
    if (this.options.platform === "win32") {
      return this.shimCommandWindows();
    }
    return this.shimCommandPosix();
  }

  private shimCommandPosix(): string {
    const envPrefix =
      `OMNODEX_HOME=${shellQuote(this.options.omnodexHome)}` +
      (this.options.debug ? " OMNODEX_DEBUG=1" : "");
    const nodeBin = this.options.nodePath ?? "node";
    return `${envPrefix} ${shellQuote(nodeBin)} ${shellQuote(this.options.shimPath)}`;
  }

  private shimCommandWindows(): string {
    const envParts = [`set "OMNODEX_HOME=${this.options.omnodexHome}"`];
    if (this.options.debug) {
      envParts.push(`set "OMNODEX_DEBUG=1"`);
    }
    const nodeBin = this.options.nodePath ?? "node";
    return `${envParts.join(" && ")} && ${cmdQuote(nodeBin)} ${cmdQuote(this.options.shimPath)}`;
  }

  private async readHooks(hooksPath: string): Promise<HooksFile> {
    try {
      const raw = await fs.readFile(hooksPath, "utf8");
      if (!raw.trim()) return {};
      return JSON.parse(raw) as HooksFile;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  private async writeHooks(hooksPath: string, hooks: HooksFile): Promise<void> {
    await fs.writeFile(hooksPath, JSON.stringify(hooks, null, 2) + "\n", "utf8");
  }
}

function shellQuote(value: string): string {
  if (value === "") return `""`;
  if (/^[A-Za-z0-9_\-./]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\'\'")}'`;
}

/** Quote a value for cmd.exe. Double-quotes paths containing spaces or special characters. */
function cmdQuote(value: string): string {
  if (value === "") return '""';
  if (/[ &|<>^()"%!]/.test(value)) return `"${value}"`;
  return value;
}
