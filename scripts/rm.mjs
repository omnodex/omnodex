// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

// Cross-platform `rm -rf` for package scripts: npm runs scripts through
// cmd.exe on Windows, where rm does not exist.
//
//   node scripts/rm.mjs dist bundle/omnodex-bundle.cjs
//   node scripts/rm.mjs "packages/*/dist"
//
// Paths are relative to the working directory. A "*" matches one whole
// path segment; nothing else is special. Missing paths are ignored.

import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

function expand(pattern) {
  let bases = ["."];
  for (const segment of pattern.split("/")) {
    const next = [];
    for (const base of bases) {
      if (segment === "*") {
        let entries = [];
        try {
          entries = readdirSync(base, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const entry of entries) if (entry.isDirectory()) next.push(join(base, entry.name));
      } else {
        next.push(join(base, segment));
      }
    }
    bases = next;
  }
  return bases;
}

for (const pattern of process.argv.slice(2)) {
  for (const target of expand(pattern)) {
    rmSync(target, { recursive: true, force: true });
  }
}
