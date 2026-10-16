// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * plugin-refresh.ts
 *
 * Brings every installed agent plugin to the version this CLI pins, after
 * `omnodex update`. The registry says which plugins are installed; each is
 * replaced in place through the same steps as `omnodex install --plugin`.
 * A version the user chose with --plugin-version is kept until this CLI
 * pins a newer one. One plugin failing does not stop the others.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { LauncherPlatform } from "./launcher-template.js";
import { PLUGIN_PINS, type PluginPin } from "./plugin-pins.js";
import { SURFACE_PLUGIN, downloadsBaseUrl, installPlugin, pluginDir, resolveBundle, type PluginPlatform } from "./plugins.js";
import { addInstallation, findInstallations, getInstalledVersion } from "./registry.js";

export type RefreshResult = "updated" | "reinstalled" | "current" | "kept" | "failed";

export interface RefreshOutcome {
  target: LauncherPlatform;
  result: RefreshResult;
  /** One line for the report. */
  message: string;
}

const LABELS: Record<LauncherPlatform, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  antigravity: "Antigravity",
};

/** Compares dotted versions; negative when a is older. */
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/);
  const pb = b.split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number(pa[i] ?? 0);
    const y = Number(pb[i] ?? 0);
    if (Number.isNaN(x) || Number.isNaN(y)) {
      if ((pa[i] ?? "") !== (pb[i] ?? "")) return (pa[i] ?? "") < (pb[i] ?? "") ? -1 : 1;
    } else if (x !== y) {
      return x - y;
    }
  }
  return 0;
}

async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Refresh installed plugins to this CLI's pins. With `check`, only reports
 * what would change. Prints one line per plugin and returns the outcomes.
 */
export async function refreshPlugins(opts: {
  check?: boolean;
  pins?: Record<PluginPlatform, PluginPin>;
  baseUrl?: string;
  log?: (line: string) => void;
} = {}): Promise<RefreshOutcome[]> {
  const pins = opts.pins ?? PLUGIN_PINS;
  const log = opts.log ?? ((line: string) => console.log(line));
  const omnodexHome = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  const ctx = { home: os.homedir(), omnodexHome, env: process.env };
  const outcomes: RefreshOutcome[] = [];

  for (const entry of await findInstallations({ component: "plugin" })) {
    const target = entry.target;
    const label = LABELS[target];
    const { platform, name } = SURFACE_PLUGIN[target];
    const pin = pins[platform];
    const installed = entry.pluginVersion ?? "unknown";
    const dir = entry.pluginPath ?? pluginDir(target, ctx);
    const present = await exists(dir);

    let outcome: RefreshOutcome;
    if (present && entry.pluginOverride && compareVersions(pin.version, installed) <= 0) {
      outcome = { target, result: "kept", message: `${label}: kept ${name} ${installed}, the version you chose (this CLI pins ${pin.version})` };
    } else if (present && !entry.pluginOverride && installed === pin.version) {
      outcome = { target, result: "current", message: `${label}: ${name} ${installed} is current` };
    } else if (opts.check) {
      const change = present ? `${installed} -> ${pin.version}` : `${pin.version} (the installed copy is missing)`;
      outcome = { target, result: present ? "updated" : "reinstalled", message: `${label}: would update ${name} ${change}` };
    } else {
      try {
        const bundle = await resolveBundle({
          target,
          baseUrl: opts.baseUrl ?? downloadsBaseUrl(),
          cacheDir: path.join(omnodexHome, "plugins", "cache"),
          pins,
        });
        const result = await installPlugin(target, bundle, ctx);
        await addInstallation({
          ...entry,
          installedAt: new Date().toISOString(),
          installedVersion: getInstalledVersion(),
          pluginPath: result.pluginPath,
          pluginVersion: bundle.version,
          pluginOverride: false,
        });
        const what = present ? `updated ${name} ${installed} -> ${bundle.version}` : `reinstalled ${name} ${bundle.version} (the installed copy was missing)`;
        const restart = result.registered ? `; start a new ${label} session to load it` : `; ${result.steps.at(-1)}`;
        outcome = { target, result: present ? "updated" : "reinstalled", message: `${label}: ${what}${restart}` };
      } catch (err) {
        outcome = {
          target,
          result: "failed",
          message: `${label}: ${name} not updated: ${(err as Error).message}; retry with \`omnodex update --refresh-plugins\``,
        };
      }
    }
    log(`  ${outcome.message}`);
    outcomes.push(outcome);
  }
  return outcomes;
}
