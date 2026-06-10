// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Absolute filesystem path to the compiled Antigravity hook shim that gets
 * spawned by Antigravity for each subscribed hook event.
 */

import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Resolves to <pkg>/dist/bin/antigravity-hook-shim.js */
export const ANTIGRAVITY_HOOK_SHIM_PATH = path.resolve(
  __dirname,
  "bin",
  "antigravity-hook-shim.js",
);
