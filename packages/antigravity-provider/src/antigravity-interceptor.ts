// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * AntigravityInterceptor
 *
 * Installs and removes the Omnodex hook shim in an Antigravity project by
 * editing `<projectPath>/.agents/hooks.json`. On start() it writes the hook
 * entries; the returned stop function removes only the Omnodex-managed entries.
 *
 * Events subscribed:
 *
 *   PreToolUse   (matcher "*")
 *   PostToolUse  (matcher "*")
 *   Stop
 *
 * Antigravity 2.0 hooks.json uses a named-hook format where each top-level
 * key is a hook name (e.g. "omnodex") containing event definitions. This
 * differs from Codex which wraps events under a `hooks` key.
 *
 * File format (https://antigravity.google/docs/hooks):
 *
 *   {
 *     "omnodex": {
 *       "PreToolUse": [{ matcher, hooks: [handler] }],
 *       "PostToolUse": [{ matcher, hooks: [handler] }],
 *       "Stop": [handler]
 *     }
 *   }
 *
 * Note: PreToolUse/PostToolUse use matcher groups; Stop/PreInvocation/
 * PostInvocation use a flat handler list (matcher is ignored).
 *
 * Antigravity 2.0 shares a "Shared Agent Harness" across CLI (`agy`),
 * Desktop App, and IDE extensions. Hooks registered in `.agents/hooks.json`
 * apply to all surfaces, so this single interceptor covers all three.
 *
 * Config directory: `.agents/` (project-level).
 * Global hooks: `~/.gemini/config/hooks.json` (not managed by this interceptor).
 * MCP config: `.agents/mcp_config.json` (separate file, not touched here).
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { EmitFn, Interceptor, StopFn } from "@omnodex/shared";

export interface AntigravityInterceptorOptions {
  /** Absolute path to the Antigravity project whose hooks we are wiring. */
  projectPath: string;
  /** Absolute path to the compiled antigravity-hook-shim.js. */
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
   * non-interactive shells (e.g. WSL agy) may not have
   * nvm/fnm/volta in PATH.
   */
  nodePath?: string;
  /**
   * Target platform for hook command syntax. Defaults to process.platform.
   * Set explicitly in tests or when cross-compiling hooks for a different OS.
   */
  platform?: NodeJS.Platform;
}

/** Top-level hooks.json: each key is a named hook containing event defs. */
interface HooksFile {
  [hookName: string]: NamedHookDef;
}

/** A named hook definition with optional `enabled` flag and event arrays. */
interface NamedHookDef {
  enabled?: boolean;
  PreToolUse?: MatcherGroup[];
  PostToolUse?: MatcherGroup[];
  /** Stop uses a flat handler list (no matcher groups). */
  Stop?: HookHandler[];
  PreInvocation?: HookHandler[];
  PostInvocation?: HookHandler[];
  [key: string]: unknown;
}

interface MatcherGroup {
  matcher?: string;
  hooks: HookHandler[];
}

interface HookHandler {
  type: "command";
  command: string;
  timeout?: number;
  [key: string]: unknown;
}

const HOOK_NAME = "omnodex";

/** Events that use matcher groups (PreToolUse, PostToolUse). */
const TOOL_EVENTS = ["PreToolUse", "PostToolUse"] as const;

/** Events that use flat handler lists (Stop). */
const FLAT_EVENTS = ["Stop"] as const;

export class AntigravityInterceptor implements Interceptor {
  readonly name = "antigravity-hooks";
  readonly kind = "antigravity-hook" as const;
  readonly options: Required<
    Pick<AntigravityInterceptorOptions, "timeoutSeconds" | "debug" | "platform">
  > &
    AntigravityInterceptorOptions;

  constructor(options: AntigravityInterceptorOptions) {
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
    return path.join(this.options.projectPath, ".agents", "hooks.json");
  }

  async install(): Promise<void> {
    const hooksPath = this.hooksFilePath();
    const dir = path.dirname(hooksPath);
    await fs.mkdir(dir, { recursive: true });

    const existing = await this.readHooks(hooksPath);

    // Build the Omnodex named hook definition.
    const omnodexDef: NamedHookDef = {};

    for (const eventName of TOOL_EVENTS) {
      omnodexDef[eventName] = [
        {
          matcher: "*",
          hooks: [this.makeHandler(eventName)],
        },
      ];
    }

    for (const eventName of FLAT_EVENTS) {
      omnodexDef[eventName] = [this.makeHandler(eventName)];
    }

    // Replace the "omnodex" key; preserve all other named hooks.
    const next: HooksFile = { ...existing, [HOOK_NAME]: omnodexDef };
    await this.writeHooks(hooksPath, next);
  }

  async uninstall(): Promise<void> {
    const hooksPath = this.hooksFilePath();
    const existing = await this.readHooks(hooksPath);
    if (!(HOOK_NAME in existing)) return;

    const next = { ...existing };
    delete next[HOOK_NAME];

    await this.writeHooks(hooksPath, next);
  }

  private makeHandler(eventName: string): HookHandler {
    return {
      type: "command",
      command: this.shimCommand(eventName),
      timeout: this.options.timeoutSeconds,
    };
  }

  private shimCommand(eventName: string): string {
    if (this.options.platform === "win32") {
      return this.shimCommandWindows(eventName);
    }
    return this.shimCommandPosix(eventName);
  }

  private shimCommandPosix(eventName: string): string {
    const envPrefix =
      `OMNODEX_HOME=${shellQuote(this.options.omnodexHome)}` +
      (this.options.debug ? " OMNODEX_DEBUG=1" : "");
    const nodeBin = this.options.nodePath ?? "node";
    return `${envPrefix} ${shellQuote(nodeBin)} ${shellQuote(this.options.shimPath)} ${eventName}`;
  }

  private shimCommandWindows(eventName: string): string {
    const envParts = [`set "OMNODEX_HOME=${this.options.omnodexHome}"`];
    if (this.options.debug) {
      envParts.push(`set "OMNODEX_DEBUG=1"`);
    }
    const nodeBin = this.options.nodePath ?? "node";
    return `${envParts.join(" && ")} && ${cmdQuote(nodeBin)} ${cmdQuote(this.options.shimPath)} ${eventName}`;
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
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** Quote a value for cmd.exe. Double-quotes paths containing spaces or special characters. */
function cmdQuote(value: string): string {
  if (value === "") return '""';
  if (/[ &|<>^()"%!]/.test(value)) return `"${value}"`;
  return value;
}
