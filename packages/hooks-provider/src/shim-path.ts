// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
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
