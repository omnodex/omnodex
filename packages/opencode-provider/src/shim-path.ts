// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Absolute filesystem path to the compiled OpenCode plugin shim that OpenCode
 * spawns for each event the plugin sends.
 */

import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Resolves to <pkg>/dist/bin/opencode-plugin-shim.js */
export const OPENCODE_PLUGIN_SHIM_PATH = path.resolve(__dirname, "bin", "opencode-plugin-shim.js");
