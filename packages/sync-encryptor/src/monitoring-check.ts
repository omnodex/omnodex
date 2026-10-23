// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- monitoring config check
 *
 * Notices the result of tampering, however it was done: compares each
 * installation in installations.json with the agent's real config. Our hook
 * entry present, hooks not switched off, the plugin still there and enabled,
 * the MCP entry present. Rules judge the tool calls that change these files;
 * this check also catches a helper script, another process or a person.
 *
 * A change from working to broken with no monitoring.changed marker since
 * the last check writes monitoring.unexplained_change and a HIGH finding,
 * once per change. Benign cases stay quiet:
 *   - an Omnodex command made the change (a marker explains it);
 *   - the project directory is gone (deleted or moved, not tampered with);
 *   - it was already broken when the check first ran on this machine, which
 *     is the baseline after an upgrade, not a change anyone just made.
 *
 * Runs at most every 15 minutes from the background pass (hook shims and
 * the proxy start it), and on every `omnodex status`. Reads only; never
 * repairs anything. Never throws.
 *
 * Files under OMNODEX_HOME:
 *   - monitoring-check.json   last run, and each installation's last state
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog } from "@omnodex/event-log";
import {
  CAPTURE_CONTROL_SESSION_ID,
  SCHEMA_VERSION,
  type MonitoringProblem,
  type MonitoringUnexplainedChangeEvent,
  type RiskDetectedEvent,
  type TraceEvent,
} from "@omnodex/shared";

/** Minimum gap between background checks. */
export const MONITORING_CHECK_INTERVAL_MS = 15 * 60 * 1000;

/** Rule id of the finding an unexplained change raises. */
export const UNEXPLAINED_CHANGE_RULE_ID = "RULE_SELF_PROTECTION_UNEXPLAINED_CHANGE";

const STATE_FILE = "monitoring-check.json";

/** An installation's state: working, its project gone, or what is wrong. */
export type InstallationState = "ok" | "project_gone" | MonitoringProblem;

export interface InstallationCheck {
  target: string;
  component: "hooks" | "plugin" | "mcp";
  scope: "project" | "user";
  project_path?: string;
  /** The agent config file or plugin directory checked. */
  file: string;
  state: InstallationState;
}

export interface MonitoringCheckOptions {
  /** Ignore the 15-minute gap (`omnodex status`). */
  force?: boolean;
  now?: number;
  /** The user's home, where agents keep their config. Defaults to os.homedir(). */
  userHome?: string;
  env?: NodeJS.ProcessEnv;
  /** Sends what the check writes to the live relay. */
  push?: (events: TraceEvent[], home: string) => Promise<unknown>;
}

export interface MonitoringCheckResult {
  /** False when skipped because the last check was too recent. */
  ran: boolean;
  checks: InstallationCheck[];
  /** Events written: an unexplained change and its finding, per change. */
  written: TraceEvent[];
}

interface CheckState {
  first_run_at: string;
  last_run_at: string;
  slots: Record<string, InstallationState>;
}

interface Entry {
  target: string;
  component: "hooks" | "plugin" | "mcp";
  scope: "project" | "user";
  projectPath?: string;
  settingsFile: string;
  installedAt?: string;
  pluginPath?: string;
}

/** Our hook command, on every platform, launcher or legacy shim. */
const OUR_HOOK = /(?:claude|codex|antigravity)-hook-(?:launcher|shim)|omnodex-managed/;

/**
 * Run the check: inspect every installation, compare with the last run, and
 * record each unexplained change. Never throws.
 */
export async function checkMonitoringConfig(
  home: string,
  opts: MonitoringCheckOptions = {},
): Promise<MonitoringCheckResult> {
  const now = opts.now ?? Date.now();
  try {
    const previous = await readState(home);
    if (!opts.force && previous && now - Date.parse(previous.last_run_at) < MONITORING_CHECK_INTERVAL_MS) {
      return { ran: false, checks: [], written: [] };
    }
    const entries = await readInstallations(home);
    const checks = await Promise.all(entries.map((e) => inspect(e, opts)));

    const changed: InstallationCheck[] = [];
    const slots: Record<string, InstallationState> = {};
    entries.forEach((entry, i) => {
      const check = checks[i]!;
      const key = slotKey(entry);
      slots[key] = check.state;
      if (!previous || check.state === "ok" || check.state === "project_gone") return;
      // Installed after the first run: it worked when we wrote it.
      const installedLater = entry.installedAt !== undefined && entry.installedAt > previous.first_run_at;
      const before = previous.slots[key] ?? (installedLater ? "ok" : undefined);
      if (before === "ok") changed.push(check);
    });

    const nowIso = new Date(now).toISOString();
    await writeState(home, {
      first_run_at: previous?.first_run_at ?? nowIso,
      last_run_at: nowIso,
      slots,
    });

    const unexplained = await withoutMarker(home, changed, previous?.last_run_at);
    // An uninstall still in progress removes the entry right after the files.
    const stillRegistered = new Set((await readInstallations(home)).map(slotKey));
    const written = unexplained
      .filter((c) => stillRegistered.has(slotKey({ ...c, projectPath: c.project_path })))
      .flatMap((c) => events(c, now));
    if (written.length > 0) {
      await append(home, written);
      await opts.push?.(written, home).catch(() => undefined);
    }
    return { ran: true, checks, written };
  } catch {
    return { ran: false, checks: [], written: [] };
  }
}

/** Inspect one installation against the agent's real config. */
async function inspect(entry: Entry, opts: MonitoringCheckOptions): Promise<InstallationCheck> {
  const env = opts.env ?? process.env;
  const userHome = opts.userHome ?? os.homedir();
  const project = entry.projectPath;
  const base = {
    target: entry.target,
    component: entry.component,
    scope: entry.scope,
    ...(project ? { project_path: project } : {}),
  };
  if (entry.scope === "project" && (!project || !(await exists(project)))) {
    return { ...base, file: project ?? "", state: "project_gone" };
  }
  const claudeUser = path.join(env.CLAUDE_CONFIG_DIR || path.join(userHome, ".claude"), "settings.json");
  const codexHome = env.CODEX_HOME || path.join(userHome, ".codex");

  if (entry.component === "plugin") {
    const dir = entry.pluginPath ?? "";
    if (!dir) return { ...base, file: entry.settingsFile, state: "ok" };
    if (!(await exists(dir))) return { ...base, file: dir, state: "plugin_missing" };
    if (entry.target === "claude-code") {
      const enabled = (await readJson(claudeUser))?.enabledPlugins;
      const off = enabled && typeof enabled === "object" &&
        Object.entries(enabled).some(([id, on]) => id.startsWith(`${entry.settingsFile}@`) && on === false);
      if (off) return { ...base, file: claudeUser, state: "plugin_disabled" };
    }
    return { ...base, file: dir, state: "ok" };
  }

  if (entry.component === "mcp") {
    const file = path.join(project ?? "", ".agents", "mcp_config.json");
    const server = (await readJson(file))?.mcpServers?.omnodex;
    const ok = server && typeof server === "object" && server.disabled !== true;
    return { ...base, file, state: ok ? "ok" : "mcp_missing" };
  }

  const file = hooksFile(entry);
  const text = await readText(file);
  if (text === null || !OUR_HOOK.test(text)) return { ...base, file, state: "hooks_missing" };

  let disabled = false;
  if (entry.target === "claude-code") {
    const files = [file, claudeUser];
    if (project) files.push(path.join(project, ".claude", "settings.json"), path.join(project, ".claude", "settings.local.json"));
    for (const f of files) if ((await readJson(f))?.disableAllHooks === true) disabled = true;
  } else if (entry.target === "codex") {
    const files = [path.join(codexHome, "config.toml")];
    if (project) files.push(path.join(project, ".codex", "config.toml"));
    for (const f of files) if (codexHooksOff((await readText(f)) ?? "")) disabled = true;
  } else if (entry.target === "antigravity") {
    disabled = parseJson(text)?.omnodex?.enabled === false;
  }
  return { ...base, file, state: disabled ? "hooks_disabled" : "ok" };
}

/** The hook file an entry was written to. */
function hooksFile(entry: Entry): string {
  if (entry.scope === "user") return entry.settingsFile;
  const project = entry.projectPath ?? "";
  switch (entry.target) {
    case "claude-code":
      return path.join(project, ".claude", entry.settingsFile);
    case "codex":
      return path.join(project, ".codex", "hooks.json");
    default:
      return path.join(project, ".agents", "hooks.json");
  }
}

/** Codex `[features] hooks = false` (or the older codex_hooks), or the dotted form. */
export function codexHooksOff(toml: string): boolean {
  let section = "";
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1]!.trim();
      continue;
    }
    if (section === "features" && /^(?:codex_)?hooks\s*=\s*false$/.test(line)) return true;
    if (section === "" && /^features\.(?:codex_)?hooks\s*=\s*false$/.test(line)) return true;
  }
  return false;
}

/** Drop changes a monitoring.changed marker for the same platform explains. */
async function withoutMarker(
  home: string,
  changed: InstallationCheck[],
  since: string | undefined,
): Promise<InstallationCheck[]> {
  if (changed.length === 0) return changed;
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  let markers: TraceEvent[];
  try {
    markers = (await log.readSession(CAPTURE_CONTROL_SESSION_ID)).filter(
      (e) => e.event_type === "monitoring.changed" && (!since || e.occurred_at >= since),
    );
  } finally {
    await log.close();
  }
  return changed.filter(
    (c) => !markers.some((m) => m.event_type === "monitoring.changed" && (m.target === undefined || m.target === c.target)),
  );
}

const PROBLEM_TEXT: Record<MonitoringProblem, string> = {
  hooks_missing: "hooks are no longer in",
  hooks_disabled: "hooks are switched off by",
  plugin_missing: "plugin is no longer at",
  plugin_disabled: "plugin is disabled in",
  mcp_missing: "MCP entry is no longer in",
};

function events(c: InstallationCheck, now: number): TraceEvent[] {
  const at = new Date(now).toISOString();
  const base = {
    schema_version: SCHEMA_VERSION,
    session_id: CAPTURE_CONTROL_SESSION_ID,
    occurred_at: at,
    recorded_at: at,
    interceptor: "analyzer" as const,
  };
  const problem = c.state as MonitoringProblem;
  const change: MonitoringUnexplainedChangeEvent = {
    ...base,
    event_id: randomUUID(),
    event_type: "monitoring.unexplained_change",
    problem,
    target: c.target,
    component: c.component,
    scope: c.scope,
    ...(c.project_path ? { project_path: c.project_path } : {}),
    file: c.file,
    machine_label: os.hostname(),
  };
  const finding: RiskDetectedEvent = {
    ...base,
    event_id: randomUUID(),
    event_type: "risk.detected",
    severity: "HIGH",
    category: "self_protection",
    description:
      `Omnodex's ${c.target} ${PROBLEM_TEXT[problem]} ${c.file}, and no Omnodex command made that change. ` +
      `Check whether an agent, a script or a person changed it, then run \`omnodex install ${c.target}\` to restore monitoring.`,
    related_event_id: change.event_id,
    rule_id: UNEXPLAINED_CHANGE_RULE_ID,
    rule_tier: "community",
  };
  return [change, finding];
}

function slotKey(e: Pick<Entry, "target" | "component" | "scope" | "projectPath">): string {
  const project = e.scope === "project" && e.projectPath ? path.resolve(e.projectPath) : "";
  return [e.target, e.component, e.scope, process.platform === "win32" ? project.toLowerCase() : project].join("|");
}

/** The registry's entries this check understands; anything else is skipped. */
async function readInstallations(home: string): Promise<Entry[]> {
  const parsed = await readJson(path.join(home, "installations.json"));
  const list: unknown[] = Array.isArray(parsed?.installations) ? parsed.installations : [];
  const entries: Entry[] = [];
  for (const raw of list) {
    if (!raw || typeof raw !== "object") continue;
    const e = raw as Record<string, unknown>;
    if (typeof e.target !== "string" || typeof e.settingsFile !== "string") continue;
    // Version 1 entries (project hooks) carry no component or scope.
    const component = e.component ?? (e.settingsFile === "mcp_config.json" ? "mcp" : "hooks");
    const scope = e.scope ?? "project";
    if (component !== "hooks" && component !== "plugin" && component !== "mcp") continue;
    if (scope !== "project" && scope !== "user") continue;
    if (scope === "project" && typeof e.projectPath !== "string") continue;
    entries.push({
      target: e.target,
      component,
      scope,
      settingsFile: e.settingsFile,
      ...(typeof e.projectPath === "string" ? { projectPath: e.projectPath } : {}),
      ...(typeof e.installedAt === "string" ? { installedAt: e.installedAt } : {}),
      ...(typeof e.pluginPath === "string" ? { pluginPath: e.pluginPath } : {}),
    });
  }
  return entries;
}

async function readState(home: string): Promise<CheckState | null> {
  const s = await readJson(path.join(home, STATE_FILE));
  if (!s || typeof s.first_run_at !== "string" || typeof s.last_run_at !== "string") return null;
  return { first_run_at: s.first_run_at, last_run_at: s.last_run_at, slots: s.slots && typeof s.slots === "object" ? s.slots : {} };
}

async function writeState(home: string, state: CheckState): Promise<void> {
  await fs.mkdir(home, { recursive: true });
  const dest = path.join(home, STATE_FILE);
  const tmp = `${dest}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2) + "\n", "utf8");
  await fs.rename(tmp, dest);
}

async function append(home: string, written: TraceEvent[]): Promise<void> {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  try {
    for (const e of written) await log.append(e);
  } finally {
    await log.close();
  }
}

async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function readText(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
}

function parseJson(text: string | null): any {
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function readJson(file: string): Promise<any> {
  return parseJson(await readText(file));
}
