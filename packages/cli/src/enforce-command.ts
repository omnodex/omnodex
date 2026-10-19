// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex enforce <mode>` and `omnodex enforce status`.
 *
 *   monitor     record and flag, never act (the default)
 *   shadow      also record, on each finding, what enforcement would have
 *               done; the agent is never stopped
 *   guardrails  stop or hold calls your settings say to (Pro: the code that
 *               decides is a sealed module fetched for entitled accounts)
 *
 * The mode lives in OMNODEX_HOME/omnodex-config.json, section `enforcement`,
 * which the hook shims and the MCP proxy read on every finding, so a change
 * applies to the next tool call without restarting anything. Switching to or
 * from guardrails also rewrites the installed hooks that must answer before
 * a call runs, and only those: Claude Code's Omnodex PreToolUse entries run
 * synchronously (it ignores a background hook's decision), and Antigravity
 * gets an Omnodex PreToolUse entry (installs observe PostToolUse otherwise).
 *
 * Leaving a mode that acts on calls switches protection down, which is for
 * a person, not an agent: like pausing, it needs an interactive terminal and
 * a typed confirmation. Moving between modes that never act needs neither.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { parseEnforcementConfig, type EnforcementMode } from "@omnodex/shared";
import type { ControlIo } from "./capture-controls.js";

export const USER_CONFIG_FILE = "omnodex-config.json";

/** The modes this command can set. */
const SETTABLE: readonly EnforcementMode[] = ["monitor", "shadow", "guardrails"];

/** Modes that stop or hold calls; leaving one needs a person to confirm. */
const ACTING: ReadonlySet<EnforcementMode> = new Set(["guardrails"]);

/** What each mode does, in one clause each. */
export const MODE_EFFECT: Record<EnforcementMode, string> = {
  monitor: "Omnodex records and flags tool calls, and never stops one",
  shadow:
    "Omnodex also records, on each finding, whether it would have stopped the call; " +
    "your agents are never stopped",
  guardrails: "Omnodex stops or holds tool calls that your rules and settings say to",
};

const USAGE = "omnodex enforce monitor | shadow | guardrails | status";

async function readConfig(file: string): Promise<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new Error(`cannot read ${file}: ${(err as Error).message}`);
  }
}

async function writeConfig(file: string, config: Record<string, unknown>): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  // Write then rename, so a crash mid-write never leaves a torn file.
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(config, null, 2) + "\n");
  await fs.rename(tmp, file);
}

/** The mode the user chose for an OMNODEX_HOME, or undefined if none was ever set. */
export async function configuredMode(home: string): Promise<EnforcementMode | undefined> {
  const config = await readConfig(path.join(home, USER_CONFIG_FILE)).catch(() => ({}));
  return parseEnforcementConfig((config as { enforcement?: unknown }).enforcement).mode;
}

/** The mode in force for an OMNODEX_HOME. */
export async function currentMode(home: string): Promise<EnforcementMode> {
  return (await configuredMode(home)) ?? "monitor";
}

export interface OfferShadowOptions {
  home: string;
  io: ControlIo;
  /** --yes was given: take the default answer without asking. */
  yes: boolean;
}

/**
 * On a first install, offer shadow mode, defaulting to yes. Never changes a
 * mode the user already chose, and without a terminal or --yes leaves the
 * default (monitor) alone. Returns the mode now in force.
 */
export async function offerShadowMode(opts: OfferShadowOptions): Promise<EnforcementMode> {
  const { home, io, yes } = opts;
  const chosen = await configuredMode(home);
  if (chosen !== undefined) return chosen;
  let accept = yes;
  if (!yes) {
    if (!io.stdinIsTTY || !io.stdoutIsTTY) return "monitor";
    io.log(`[install] Turn on shadow mode? ${MODE_EFFECT.shadow}.`);
    io.log(`[install] It shows what Omnodex would stop before you let it stop anything. Change it any time with \`omnodex enforce monitor\`.`);
    const answer = (await io.ask("[install] Turn on shadow mode? [Y/n]: ")).trim().toLowerCase();
    accept = answer === "" || answer === "y" || answer === "yes";
  }
  if (!accept) {
    await setMode(home, "monitor");
    return "monitor";
  }
  await setMode(home, "shadow");
  io.log(`[install] shadow mode on.`);
  return "shadow";
}

/**
 * Set the mode, keeping every other key in the file. Returns the previous
 * mode. A malformed file is an error rather than something to overwrite.
 */
export async function setMode(home: string, mode: EnforcementMode): Promise<EnforcementMode> {
  const file = path.join(home, USER_CONFIG_FILE);
  const config = await readConfig(file);
  const section =
    typeof config.enforcement === "object" && config.enforcement !== null && !Array.isArray(config.enforcement)
      ? (config.enforcement as Record<string, unknown>)
      : {};
  const previous = parseEnforcementConfig(section).mode ?? "monitor";
  await writeConfig(file, { ...config, enforcement: { ...section, mode } });
  return previous;
}

export interface EnforceOptions {
  home: string;
  io: ControlIo;
  /**
   * Make the installed hooks that must wait for a decision synchronous, or
   * put them back in the background. Returns the files it changed.
   */
  applyHookTiming?: (sync: boolean) => Promise<string[]>;
  /**
   * Before switching to guardrails: whether this account may, and whether
   * the guardrails module is installed and opens (fetching it if needed).
   */
  prepareGuardrails?: () => Promise<GuardrailsReadiness>;
  /** One line on the guardrails module, for status. */
  describeGuardrails?: () => Promise<string>;
}

export interface GuardrailsReadiness {
  entitled: boolean;
  ready: boolean;
  /** What the module's state is, in a few words. */
  detail: string;
}

/** Run `omnodex enforce <sub>`. Returns the exit code. */
export async function runEnforce(args: string[], opts: EnforceOptions): Promise<number> {
  const { home, io } = opts;
  const sub = args.find((a) => !a.startsWith("--")) ?? "status";
  const tag = "[enforce]";

  if (sub === "status") {
    const mode = await currentMode(home);
    io.log(`${tag} ${home}: ${mode}: ${MODE_EFFECT[mode]}.`);
    if (mode === "guardrails" && opts.describeGuardrails) io.log(`${tag} ${await opts.describeGuardrails()}.`);
    return 0;
  }

  if (!SETTABLE.includes(sub as EnforcementMode)) {
    io.error(`${tag} unknown mode '${sub}'. Usage: ${USAGE}`);
    return 1;
  }
  const mode = sub as EnforcementMode;

  let previous: EnforcementMode;
  try {
    previous = await currentMode(home);
    if (previous === mode) {
      io.log(`${tag} already ${mode} in ${home}.`);
      return 0;
    }
    if (mode === "guardrails" && opts.prepareGuardrails) {
      const readiness = await opts.prepareGuardrails();
      if (!readiness.entitled) {
        io.error(
          `${tag} guardrails are part of Omnodex Pro. Shadow mode is free and shows what they would stop: ` +
            `\`omnodex enforce shadow\`.`,
        );
        return 1;
      }
      if (!readiness.ready) {
        io.log(`${tag} ${readiness.detail}; until it is, calls are recorded as in shadow mode and nothing is stopped.`);
      }
    }
    if (ACTING.has(previous)) {
      // Human only: an agent running this through a shell has no terminal.
      if (!io.stdinIsTTY || !io.stdoutIsTTY) {
        io.error(
          `${tag} leaving ${previous} switches protection down, which needs a person at an interactive ` +
            `terminal, so an agent cannot do it. Run \`omnodex enforce ${mode}\` yourself in a terminal.`,
        );
        return 1;
      }
      io.log(`${tag} switching from ${previous} to ${mode}: ${MODE_EFFECT[mode]}.`);
      const answer = (await io.ask(`${tag} type "${mode}" to confirm: `)).trim().toLowerCase();
      if (answer !== mode) {
        io.log(`${tag} unchanged: still ${previous}.`);
        return 1;
      }
    }
    await setMode(home, mode);
  } catch (err) {
    io.error(`${tag} ${(err as Error).message}`);
    return 1;
  }
  io.log(`${tag} ${mode} in ${home}: ${MODE_EFFECT[mode]}.`);
  if (opts.applyHookTiming && (mode === "guardrails" || previous === "guardrails")) {
    try {
      for (const file of await opts.applyHookTiming(mode === "guardrails")) {
        io.log(`${tag} ${mode === "guardrails" ? "hooks now answer before each call" : "hooks no longer hold calls"}: ${file}`);
      }
    } catch (err) {
      io.error(`${tag} could not update the Claude Code hooks: ${(err as Error).message}`);
      return 1;
    }
  }
  if (mode === "guardrails") {
    io.log(`${tag} a rule stops or holds a call only where your settings say so, or once the rule has a safer alternative to offer.`);
  }
  if (mode === "shadow") {
    io.log(`${tag} each finding that would have stopped a call is marked in the hosted dashboard.`);
  }
  return 0;
}
