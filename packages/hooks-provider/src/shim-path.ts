// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Absolute filesystem path to the compiled Claude Code hook shim that
 * gets spawned by Claude Code for each subscribed hook event.
 *
 * Consumers (`omnodex init`, anything installing hooks at runtime) should
 * import this constant instead of hard-coding a relative path. Because it
 * is computed from `import.meta.url`, it continues to resolve correctly
 * no matter which workspace package the caller lives in.
 */

import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Resolves to <pkg>/dist/bin/claude-hook-shim.js */
export const CLAUDE_HOOK_SHIM_PATH = path.resolve(
  __dirname,
  "bin",
  "claude-hook-shim.js",
);
