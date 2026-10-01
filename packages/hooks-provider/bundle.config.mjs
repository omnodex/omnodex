// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

// Builds the Cowork container hook into one dependency-free ES module,
// bundle/omnodex-hook.mjs (or --out <file>). The Cowork plugin ships that
// file as scripts/omnodex-hook.mjs; a cloud agent container has no
// node_modules, so everything it needs must be inside.

import { build } from "esbuild";
import { dirname, join } from "node:path";
import { mkdirSync } from "node:fs";

const pkgDir = import.meta.dirname;
const outIdx = process.argv.indexOf("--out");
const outfile = outIdx !== -1 ? process.argv[outIdx + 1] : join(pkgDir, "bundle", "omnodex-hook.mjs");

mkdirSync(dirname(outfile), { recursive: true });

await build({
  entryPoints: [join(pkgDir, "dist", "bin", "container-hook.js")],
  bundle: true,
  platform: "node",
  // Cloud agent containers have run Node 22.
  target: "node22",
  format: "esm",
  outfile,
  legalComments: "inline",
  banner: {
    js: [
      "// Omnodex Cowork container hook. Generated from the omnodex repository",
      "// (packages/hooks-provider, `npm run bundle`); do not edit by hand.",
      "// SPDX-License-Identifier: AGPL-3.0-only",
    ].join("\n"),
  },
});

console.log(`Container hook written to ${outfile}`);
