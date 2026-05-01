// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
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
 *   PreToolUse  (matcher "*")
 *   PostToolUse (matcher "*")
 *   PostToolUseFailure (matcher "*")
 *
 * All handlers are registered with `async: true` so the agent's
 * execution path is never blocked.
 *
 * The design explicitly does NOT require Omnodex to be running as a
 * daemon. The shim is a short-lived subprocess that appends to the
 * event log and exits; the projector is invoked separately via
 * `omnodex replay`. This keeps the interception surface as thin as it
 * can reasonably be.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
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
  /** Enable debug logging in the shim (sets OMNODEX_DEBUG=1). */
  debug?: boolean;
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
const EVENT_NAMES = [
  "SessionStart",
  "SessionEnd",
  "PreToolUse",
  "PostToolUse",
  "PostToolUseFailure",
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
    return path.join(this.options.projectPath, ".claude", this.options.settingsFile);
  }

  /** Write our hook handlers into the project's settings file. */
  async install(): Promise<void> {
    const settingsPath = this.settingsFilePath();
    const dir = path.dirname(settingsPath);
    await fs.mkdir(dir, { recursive: true });

    const existing = await this.readSettings(settingsPath);
    const next: SettingsFile = { ...existing };
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

    await this.writeSettings(settingsPath, next);
  }

  /** Remove only the Omnodex-managed handlers from the settings file. */
  async uninstall(): Promise<void> {
    const settingsPath = this.settingsFilePath();
    const existing = await this.readSettings(settingsPath);
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

    const next: SettingsFile = { ...existing, hooks: nextHooks };
    if (Object.keys(nextHooks).length === 0) {
      delete next.hooks;
    }
    await this.writeSettings(settingsPath, next);
  }

  private makeMatcherGroup(): HookMatcherGroup {
    return {
      matcher: "*",
      hooks: [
        {
          type: "command",
          command: this.shimCommand(),
          async: true,
          timeout: this.options.timeoutSeconds,
          [OMNODEX_TAG]: true,
        },
      ],
    };
  }

  private shimCommand(): string {
    // We pass OMNODEX_HOME and OMNODEX_DEBUG via `env` so the shim has
    // everything it needs without touching Claude Code's own env file
    // contract. The quoting keeps shell semantics sane even if paths
    // contain spaces.
    const envPrefix =
      `OMNODEX_HOME=${shellQuote(this.options.omnodexHome)}` +
      (this.options.debug ? ` OMNODEX_DEBUG=1` : "");
    return `${envPrefix} node ${shellQuote(this.options.shimPath)}`;
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
    const serialized = JSON.stringify(settings, null, 2) + "
";
    await fs.writeFile(settingsPath, serialized, "utf8");
  }
}

function shellQuote(value: string): string {
  if (value === "") return `""`;
  if (/^[A-Za-z0-9_\-./]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\''`)}'`;
}
