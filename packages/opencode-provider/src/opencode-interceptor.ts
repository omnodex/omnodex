// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * OpenCodeInterceptor
 *
 * Installs and removes the Omnodex plugin for OpenCode. OpenCode loads every
 * plugin file in `~/.config/opencode/plugins/` for all projects and in
 * `<project>/.opencode/plugins/` for one. Omnodex owns a single file,
 * `omnodex.js`, in whichever folder applies; it is never merged into anyone
 * else's plugin, and uninstall removes it only when it carries Omnodex's
 * marker.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { EmitFn, Interceptor, StopFn } from "@omnodex/shared";
import { buildPluginSource, PLUGIN_MARKER } from "./plugin-source.js";

export interface OpenCodeInterceptorOptions {
  /** Absolute path to the project whose `.opencode/plugins/` gets the file. */
  projectPath: string;
  /** Absolute path to the launcher (or the compiled plugin shim). */
  shimPath: string;
  omnodexHome: string;
  debug?: boolean;
  /** Absolute path to the Node.js binary the plugin runs the launcher with. Defaults to "node". */
  nodePath?: string;
  /** Absolute plugin file to write instead of `<project>/.opencode/plugins/omnodex.js`. */
  hooksPath?: string;
  /** Arguments for the launcher; the user-scope marker means the every-project file. */
  launcherArgs?: string[];
}

export class OpenCodeInterceptor implements Interceptor {
  readonly name = "opencode-plugin";
  readonly kind = "opencode-plugin" as const;
  readonly options: OpenCodeInterceptorOptions & { debug: boolean };

  constructor(options: OpenCodeInterceptorOptions) {
    this.options = { ...options, debug: options.debug ?? false };
  }

  async start(_emit: EmitFn): Promise<StopFn> {
    await this.install();
    return async () => {
      await this.uninstall();
    };
  }

  /** The plugin file (named for symmetry with the other interceptors' hooks files). */
  hooksFilePath(): string {
    return this.options.hooksPath ?? path.join(this.options.projectPath, ".opencode", "plugins", "omnodex.js");
  }

  async install(): Promise<void> {
    const file = this.hooksFilePath();
    const existing = await this.readOrNull(file);
    if (existing !== null && !existing.includes(PLUGIN_MARKER)) {
      throw new Error(`${file} exists and is not an Omnodex plugin; move it aside to install`);
    }
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(
      file,
      buildPluginSource({
        nodePath: this.options.nodePath ?? "node",
        launcherPath: this.options.shimPath,
        omnodexHome: this.options.omnodexHome,
        userScope: (this.options.launcherArgs ?? []).includes("--user-scope"),
        debug: this.options.debug,
      }),
      "utf8",
    );
  }

  async uninstall(): Promise<void> {
    const file = this.hooksFilePath();
    const existing = await this.readOrNull(file);
    if (existing === null || !existing.includes(PLUGIN_MARKER)) return;
    await fs.rm(file, { force: true });
  }

  private async readOrNull(file: string): Promise<string | null> {
    try {
      return await fs.readFile(file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }
}
