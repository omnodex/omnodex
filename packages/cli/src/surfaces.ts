// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * surfaces.ts
 *
 * Detects which supported agent surfaces are present on this host, so
 * `omnodex install` with no target can set up all of them. Also notices
 * when it runs under WSL while the Windows side has surfaces of its own:
 * WSL and native Windows are separate hosts, and an install here never
 * covers the Windows side.
 *
 * Everything takes its environment as arguments so tests can describe a
 * machine without touching the real one.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import * as path from "node:path";

export type Surface = "claude-code" | "codex" | "antigravity";

export const SURFACE_LABELS: Record<Surface, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  antigravity: "Antigravity",
};

interface SurfaceSignals {
  /** Commands that mean the surface is installed when found on PATH. */
  commands: string[];
  /** Directories under the home directory the surface creates. */
  homeDirs: string[];
  /** macOS app bundles. */
  macApps: string[];
}

// ~/.gemini alone is not used: Gemini CLI creates it too. Antigravity
// keeps its own config under ~/.gemini/config and ~/.gemini/antigravity-cli.
const SIGNALS: Record<Surface, SurfaceSignals> = {
  "claude-code": { commands: ["claude"], homeDirs: [".claude"], macApps: [] },
  codex: { commands: ["codex"], homeDirs: [".codex"], macApps: ["ChatGPT.app", "Codex.app"] },
  antigravity: {
    commands: ["agy"],
    homeDirs: [path.join(".gemini", "config"), path.join(".gemini", "antigravity-cli")],
    macApps: ["Antigravity.app"],
  },
};

export const SURFACES: Surface[] = ["claude-code", "codex", "antigravity"];

export interface HostEnv {
  home: string;
  platform: NodeJS.Platform;
  env: Record<string, string | undefined>;
  /** Root for /Applications on macOS (tests point it elsewhere). */
  applicationsDir?: string;
}

export interface DetectedSurface {
  surface: Surface;
  /** How it was found, for the plan output: "claude on PATH", "~/.codex". */
  evidence: string;
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Find a command on PATH, honoring PATHEXT on Windows. */
export function findOnPath(command: string, host: Pick<HostEnv, "platform" | "env">): string | null {
  const pathVar = host.env.PATH ?? host.env.Path ?? "";
  const sep = host.platform === "win32" ? ";" : ":";
  const exts = host.platform === "win32"
    ? (host.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
    : [""];
  for (const dir of pathVar.split(sep)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = path.join(dir, command + ext);
      try {
        if (statSync(candidate).isFile()) return candidate;
      } catch {
        // not here
      }
    }
  }
  return null;
}

/** Which supported surfaces this host has, in a stable order. */
export function detectSurfaces(host: HostEnv): DetectedSurface[] {
  const found: DetectedSurface[] = [];
  for (const surface of SURFACES) {
    const signals = SIGNALS[surface];
    let evidence: string | null = null;
    for (const command of signals.commands) {
      if (findOnPath(command, host)) {
        evidence = `${command} on PATH`;
        break;
      }
    }
    if (!evidence) {
      for (const dir of signals.homeDirs) {
        if (isDir(path.join(host.home, dir))) {
          evidence = `~/${dir.split(path.sep).join("/")}`;
          break;
        }
      }
    }
    if (!evidence && host.platform === "darwin") {
      // OMNODEX_APPLICATIONS_DIR points elsewhere for tests and nonstandard installs.
      const apps = host.applicationsDir ?? host.env.OMNODEX_APPLICATIONS_DIR ?? "/Applications";
      for (const app of signals.macApps) {
        if (isDir(path.join(apps, app))) {
          evidence = app;
          break;
        }
      }
    }
    if (evidence) found.push({ surface, evidence });
  }
  return found;
}

export interface WslInfo {
  /** Surfaces found in Windows user profiles, which this install does not cover. */
  windowsSurfaces: Surface[];
  /** The project as a Windows path, when it lives on a Windows drive. */
  windowsProjectPath: string | null;
}

export interface WslProbe {
  platform: NodeJS.Platform;
  env: Record<string, string | undefined>;
  /** Contents of /proc/version, or null when unreadable. */
  procVersion: string | null;
  /** Where Windows drives are mounted (normally /mnt). */
  mountRoot: string;
}

export function defaultWslProbe(env: Record<string, string | undefined>): WslProbe {
  let procVersion: string | null = null;
  try {
    procVersion = readFileSync("/proc/version", "utf8");
  } catch {
    // not Linux, or not readable
  }
  // OMNODEX_WSL_MOUNT_ROOT points elsewhere for tests and nonstandard automount roots.
  return { platform: process.platform, env, procVersion, mountRoot: env.OMNODEX_WSL_MOUNT_ROOT || "/mnt" };
}

export function isWsl(probe: WslProbe): boolean {
  if (probe.platform !== "linux") return false;
  if (probe.env.WSL_DISTRO_NAME) return true;
  return /microsoft|wsl/i.test(probe.procVersion ?? "");
}

const SKIP_PROFILES = new Set(["All Users", "Default", "Default User", "Public", "desktop.ini"]);

/**
 * When running under WSL, report which surfaces the Windows side has (from
 * the config directories in each Windows user profile) and the project's
 * Windows path if it is on a Windows drive. Returns null outside WSL.
 * Reads only; never writes to Windows paths.
 */
export function detectWsl(probe: WslProbe, projectPath: string): WslInfo | null {
  if (!isWsl(probe)) return null;

  const windowsSurfaces = new Set<Surface>();
  const usersDir = path.posix.join(probe.mountRoot, "c", "Users");
  let profiles: string[] = [];
  try {
    profiles = readdirSync(usersDir).filter((name) => !SKIP_PROFILES.has(name));
  } catch {
    // C: not mounted
  }
  for (const profile of profiles) {
    const profileDir = path.posix.join(usersDir, profile);
    for (const surface of SURFACES) {
      if (SIGNALS[surface].homeDirs.some((dir) => existsSync(path.posix.join(profileDir, ...dir.split(path.sep))))) {
        windowsSurfaces.add(surface);
      }
    }
  }

  const prefix = probe.mountRoot.endsWith("/") ? probe.mountRoot : probe.mountRoot + "/";
  let windowsProjectPath: string | null = null;
  const match = projectPath.startsWith(prefix) ? /^([a-z])(?:\/(.*))?$/.exec(projectPath.slice(prefix.length)) : null;
  if (match) {
    const rest = (match[2] ?? "").split("/").filter(Boolean).join("\\");
    windowsProjectPath = `${match[1].toUpperCase()}:\\${rest}`;
  }

  return {
    windowsSurfaces: SURFACES.filter((s) => windowsSurfaces.has(s)),
    windowsProjectPath,
  };
}

/**
 * The note printed under WSL when the Windows side has surfaces too.
 * Returns no lines when there is nothing to say.
 */
export function wslNote(info: WslInfo | null): string[] {
  if (!info || info.windowsSurfaces.length === 0) return [];
  const names = info.windowsSurfaces.map((s) => SURFACE_LABELS[s]).join(", ");
  const lines = [
    `Native Windows also has ${names}. This install covers WSL only; Windows is a separate host`,
    `with its own Omnodex install. To cover it, run this in PowerShell on Windows:`,
    "",
    info.windowsProjectPath
      ? `  cd "${info.windowsProjectPath}"; npm i -g omnodex; omnodex install`
      : `  npm i -g omnodex; omnodex install    (from the Windows project folder)`,
  ];
  if (info.windowsProjectPath) {
    lines.push(
      "",
      "This project is on a Windows drive. Hooks written by one host replace the other's, so",
      "use each project folder from one host only.",
    );
  }
  return lines;
}
