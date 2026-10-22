// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * ClaudeCodeInterceptor
 *
 * Real implementation of the Omnodex interceptor for Claude Code. Edits
 * the project's `.claude/settings.json` to register the shim at
 * `@omnodex/hooks-provider/dist/bin/claude-hook-shim.js` for the hook
 * events we care about, and can restore the original settings on stop.
 *
 * Events subscribed:
 *
 *   SessionStart
 *   SessionEnd
 *   PreToolUse          (matcher "*")
 *   PostToolUse         (matcher "*")
 *   PostToolUseFailure  (matcher "*")
 *   SubagentStart
 *   SubagentStop
 *   UserPromptSubmit
 *   PermissionRequest   (matcher "*")
 *   PermissionDenied    (matcher "*")
 *
 * An install made before an event was added lacks it until install runs
 * again; missingEvents() names what is missing, for `omnodex status`.
 *
 * Monitor handlers hand work to a detached process. PreToolUse and session
 * boundaries wait only for the local receipt, so a fast CLI cannot cancel
 * capture before it starts. Other events remain async. In guardrails mode
 * PreToolUse instead waits for its decision, with a short timeout after
 * which the call proceeds. setPreToolUseSync() switches between the two
 * when the mode changes. A settings file shared by several Omnodex homes
 * (a project used from Windows and WSL) keeps PreToolUse synchronous while
 * any of them is in guardrails; see @omnodex/shared/guardrails-hooks.
 *
 * The design explicitly does NOT require Omnodex to be running as a
 * daemon. The shim is a short-lived subprocess that appends to the
 * event log and exits; the projector is invoked separately via
 * `omnodex replay`. This keeps the interception surface as thin as it
 * can reasonably be.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { setGuardrailsHome, syncGuardrailsHome } from "@omnodex/shared/guardrails-hooks";
import type {
  EmitFn,
  Interceptor,
  StopFn,
} from "@omnodex/shared";

export interface ClaudeCodeInterceptorOptions {
  /** Absolute path to the Claude Code project whose hooks we are wiring. */
  projectPath: string;
  /** Absolute path to the shim script that should run on each hook event. */
  shimPath: string;
  /** Where Omnodex should write the event log. Passed to the shim as env. */
  omnodexHome: string;
  /** Which settings file to edit. Default: .claude/settings.local.json. */
  settingsFile?: "settings.json" | "settings.local.json";
  /** Per-handler timeout in seconds. Default: 30. */
  timeoutSeconds?: number;
  /**
   * Register PreToolUse synchronously, so its decision is honored. Defaults
   * to whether OMNODEX_HOME, or another home sharing the settings file, is
   * in guardrails.
   */
  syncPreToolUse?: boolean;
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
   * Shim path relative to the user's home directory, with forward slashes.
   * When set, the hook command is `node "$HOME/<path>"` with no env prefix,
   * so one settings file resolves on every host that reads it: bash in WSL
   * or Linux, Git Bash on Windows, and PowerShell. `shimPath`, `nodePath`,
   * `omnodexHome` and `debug` are then not written into the command, so
   * only use it when the shim's default OMNODEX_HOME is the right one.
   */
  homeRelativeShimPath?: string;
  /**
   * Absolute settings file to edit instead of
   * `<projectPath>/.claude/<settingsFile>`, such as the user-level
   * `~/.claude/settings.json` that applies to every project.
   */
  settingsPath?: string;
  /**
   * Arguments for the launcher, placed right after its path (before an
   * event name). User-level installs pass the launcher's user-scope marker.
   */
  launcherArgs?: string[];
}

/**
 * Node of the Claude Code settings file we care about. We deliberately
 * leave the type loose with index signatures so unknown fields in the
 * user's settings are preserved through install/uninstall.
 */
interface SettingsFile {
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
  type: "command" | "http" | "prompt" | "agent";
  command?: string;
  url?: string;
  async?: boolean;
  timeout?: number;
  /** Omnodex tags its own handlers so uninstall is surgical. */
  [key: string]: unknown;
}

const OMNODEX_TAG = "omnodex-managed";
/**
 * Seconds Claude Code waits for a synchronous PreToolUse handler before the
 * call proceeds without its decision. The shim caps rule evaluation well
 * below this; it is the backstop for a process that hangs.
 */
export const SYNC_PRE_TOOL_USE_TIMEOUT_SECONDS = 5;
/**
 * Matches a command that runs the Omnodex launcher or shim script. Claude
 * Code drops keys it does not know when it rewrites a settings file, so
 * the tag above cannot be relied on alone to find our handlers.
 */
const OMNODEX_COMMAND = /(?:^|[\s"'/\\])claude-hook-(?:launcher|shim)\.js(?:["']|\s|$)/;
const EVENT_NAMES = [
  "SessionStart",
  "SessionEnd",
  "PreToolUse",
  "PostToolUse",
  "PostToolUseFailure",
  "SubagentStart",
  "SubagentStop",
  "UserPromptSubmit",
  "PermissionRequest",
  "PermissionDenied",
] as const;

export class ClaudeCodeInterceptor implements Interceptor {
  readonly name = "claude-code-hooks";
  readonly kind = "claude-code-hook" as const;
  readonly options: Required<Pick<ClaudeCodeInterceptorOptions, "settingsFile" | "timeoutSeconds" | "debug">> &
    ClaudeCodeInterceptorOptions;

  constructor(options: ClaudeCodeInterceptorOptions) {
    this.options = {
      ...options,
      settingsFile: options.settingsFile ?? "settings.local.json",
      timeoutSeconds: options.timeoutSeconds ?? 30,
      debug: options.debug ?? false,
    };
  }

  /**
   * `start()` installs the hooks. The returned stop function removes
   * them again. Emitted events are produced by the shim, not by this
   * object, so the `emit` parameter is not used today. It is part of
   * the Interceptor contract so future in-process interceptors can
   * conform without a wrapper.
   */
  async start(_emit: EmitFn): Promise<StopFn> {
    await this.install();
    return async () => {
      await this.uninstall();
    };
  }

  /** Absolute path to the settings file we edit. */
  settingsFilePath(): string {
    return this.options.settingsPath ?? path.join(this.options.projectPath, ".claude", this.options.settingsFile);
  }

  /** Write our hook handlers into the project's settings file. */
  async install(): Promise<void> {
    const settingsPath = this.settingsFilePath();
    const dir = path.dirname(settingsPath);
    await fs.mkdir(dir, { recursive: true });

    const existing = await this.readSettings(settingsPath);
    const next: SettingsFile = { ...existing };
    next.hooks = { ...(existing.hooks ?? {}) };
    const sync = this.options.syncPreToolUse ?? (await syncGuardrailsHome(settingsPath, this.options.omnodexHome));

    for (const eventName of EVENT_NAMES) {
      const groups = [...(next.hooks[eventName] ?? [])];
      // Strip any prior Omnodex handlers to keep install idempotent.
      const filtered = groups
        .map((g) => ({
          ...g,
          hooks: (g.hooks ?? []).filter((h) => !this.isOmnodexHandler(h)),
        }))
        .filter((g) => g.hooks.length > 0);
      filtered.push(this.makeMatcherGroup(eventName, sync));
      next.hooks[eventName] = filtered;
    }

    await this.writeSettings(settingsPath, next);
  }

  /** Remove only the Omnodex-managed handlers from the settings file. */
  async uninstall(): Promise<void> {
    const settingsPath = this.settingsFilePath();
    await setGuardrailsHome(settingsPath, this.options.omnodexHome, false);
    const existing = await this.readSettings(settingsPath);
    if (!existing.hooks) return;

    const nextHooks: Record<string, HookMatcherGroup[]> = {};
    for (const [eventName, groups] of Object.entries(existing.hooks)) {
      const cleaned = (groups ?? [])
        .map((g) => ({
          ...g,
          hooks: (g.hooks ?? []).filter((h) => !this.isOmnodexHandler(h)),
        }))
        .filter((g) => g.hooks.length > 0);
      if (cleaned.length > 0) {
        nextHooks[eventName] = cleaned;
      }
    }

    const next: SettingsFile = { ...existing, hooks: nextHooks };
    if (Object.keys(nextHooks).length === 0) {
      delete next.hooks;
    }
    await this.writeSettings(settingsPath, next);
  }

  /**
   * Returns true if any Omnodex-managed handlers are currently present in
   * the target settings file. Useful for detecting duplicate installations
   * across settings.json and settings.local.json before running install().
   */
  async isInstalled(): Promise<boolean> {
    const settingsPath = this.settingsFilePath();
    const existing = await this.readSettings(settingsPath);
    if (!existing.hooks) return false;
    return Object.values(existing.hooks).some((groups) =>
      (groups ?? []).some((g) =>
        (g.hooks ?? []).some((h) => this.isOmnodexHandler(h)),
      ),
    );
  }

  /**
   * True for a handler Omnodex wrote: it carries our tag, runs exactly the
   * command this interceptor would write, or runs the launcher or shim.
   */
  /**
   * The events this version subscribes to that the installed hooks lack:
   * empty when up to date, or when nothing is installed. Re-running install
   * adds them and leaves other handlers alone.
   */
  async missingEvents(): Promise<string[]> {
    const existing = await this.readSettings(this.settingsFilePath());
    const hooks = existing.hooks ?? {};
    const has = (eventName: string) =>
      (hooks[eventName] ?? []).some((g) => (g.hooks ?? []).some((h) => this.isOmnodexHandler(h)));
    if (!EVENT_NAMES.some(has)) return [];
    return EVENT_NAMES.filter((eventName) => !has(eventName));
  }

  private isOmnodexHandler(handler: HookHandler): boolean {
    if (handler[OMNODEX_TAG] === true) return true;
    const command = handler.command;
    if (typeof command !== "string") return false;
    return command.replace(/ --background$/, "") === this.shimCommand() || OMNODEX_COMMAND.test(command);
  }

  private makeMatcherGroup(eventName: string, syncPreToolUse: boolean): HookMatcherGroup {
    const sync = eventName === "PreToolUse" && syncPreToolUse;
    const receipt = ["PreToolUse", "SessionStart", "SessionEnd"].includes(eventName);
    return {
      matcher: "*",
      hooks: [
        {
          type: "command",
          command: this.shimCommand() + (sync ? "" : " --background"),
          ...(sync || receipt ? { timeout: SYNC_PRE_TOOL_USE_TIMEOUT_SECONDS } : { async: true, timeout: this.options.timeoutSeconds }),
          [OMNODEX_TAG]: true,
        },
      ],
    };
  }

  /**
   * Record whether this home needs the installed Omnodex PreToolUse handler
   * synchronous (guardrails) or not (monitor, shadow), and make it
   * synchronous while this or any other home sharing the file needs it.
   * Touches nothing else in the file. Returns whether the file changed.
   */
  async setPreToolUseSync(needSync: boolean): Promise<boolean> {
    const settingsPath = this.settingsFilePath();
    const existing = await this.readSettings(settingsPath);
    const groups = existing.hooks?.PreToolUse;
    if (!groups?.some((g) => (g.hooks ?? []).some((h) => this.isOmnodexHandler(h)))) return false;
    const sync = (await setGuardrailsHome(settingsPath, this.options.omnodexHome, needSync)).length > 0;
    let changed = false;
    const next = groups.map((g) => ({
      ...g,
      hooks: (g.hooks ?? []).map((h) => {
        if (!this.isOmnodexHandler(h)) return h;
        const command = (h.command ?? "").replace(/ --background$/, "");
        const nextCommand = command + (sync ? "" : " --background");
        if (h.async !== true && h.command === nextCommand && h.timeout === SYNC_PRE_TOOL_USE_TIMEOUT_SECONDS) return h;
        changed = true;
        const { async: _async, ...rest } = h;
        return { ...rest, command: nextCommand, timeout: SYNC_PRE_TOOL_USE_TIMEOUT_SECONDS };
      }),
    }));
    if (!changed) return false;
    await this.writeSettings(settingsPath, { ...existing, hooks: { ...existing.hooks, PreToolUse: next } });
    return true;
  }

  private shimCommand(): string {
    const extra = (this.options.launcherArgs ?? []).map((a) => ` ${shellQuote(a)}`).join("");
    if (this.options.homeRelativeShimPath !== undefined) {
      return portableCommand(this.options.homeRelativeShimPath) + extra;
    }
    // We pass OMNODEX_HOME and OMNODEX_DEBUG via `env` so the shim has
    // everything it needs without touching Claude Code's own env file
    // contract. The quoting keeps shell semantics sane even if paths
    // contain spaces.
    const envPrefix =
      `OMNODEX_HOME=${shellQuote(this.options.omnodexHome)}` +
      (this.options.debug ? ` OMNODEX_DEBUG=1` : "");
    const nodeBin = this.options.nodePath ?? "node";
    return `${envPrefix} ${shellQuote(nodeBin)} ${shellQuote(this.options.shimPath)}${extra}`;
  }

  private async readSettings(settingsPath: string): Promise<SettingsFile> {
    try {
      const raw = await fs.readFile(settingsPath, "utf8");
      if (!raw.trim()) return {};
      return JSON.parse(raw) as SettingsFile;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  private async writeSettings(
    settingsPath: string,
    settings: SettingsFile,
  ): Promise<void> {
    const serialized = JSON.stringify(settings, null, 2) + "\n";
    await fs.writeFile(settingsPath, serialized, "utf8");
  }
}

/**
 * `node "$HOME/<path>"`. Double quotes let bash, Git Bash and PowerShell
 * all expand $HOME while keeping a home directory with spaces intact.
 */
function portableCommand(homeRelativePath: string): string {
  return `node "$HOME/${homeRelativePath}"`;
}

function shellQuote(value: string): string {
  if (value === "") return `""`;
  if (/^[A-Za-z0-9_\-./]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\''`)}'`;
}
