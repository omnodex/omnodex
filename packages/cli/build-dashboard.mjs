// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

// Builds the local dashboard page (src/dashboard, React) into one
// self-contained file, dist/dashboard.html, with its script, styles and
// favicon inlined. `omnodex dashboard` serves that one file, and the npm
// bundle copies it; nothing about React ships as a runtime dependency.
//
// Runs from the root `prepare` script, so `npm install` builds it, and from
// this package's `build` script. esbuild reads the TypeScript sources
// directly, so it does not depend on `tsc -b` having run.
//
//   node packages/cli/build-dashboard.mjs [--out <file>]

import { build } from "esbuild";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const pkgDir = import.meta.dirname;
const srcDir = join(pkgDir, "src", "dashboard");
const outIdx = process.argv.indexOf("--out");
const outFile = outIdx !== -1 ? process.argv[outIdx + 1] : join(pkgDir, "dist", "dashboard.html");

const result = await build({
  entryPoints: [join(srcDir, "main.tsx")],
  bundle: true,
  write: false,
  outdir: join(pkgDir, "dist", "dashboard-build"),
  platform: "browser",
  format: "iife",
  target: ["es2022"],
  minify: true,
  jsx: "automatic",
  legalComments: "none",
  define: { "process.env.NODE_ENV": '"production"' },
  // The page needs only browser-safe pieces of the workspace packages.
  alias: {
    "@omnodex/analyzer": join(srcDir, "analyzer-browser.ts"),
    "@omnodex/shared": join(pkgDir, "..", "shared", "src", "index.ts"),
  },
  logLevel: "warning",
});

const script = result.outputFiles.find((f) => f.path.endsWith(".js"))?.text ?? "";
const style = result.outputFiles.find((f) => f.path.endsWith(".css"))?.text ?? "";
const favicon = readFileSync(join(srcDir, "favicon.png")).toString("base64");

// "</script>" inside the bundle would end the inline script early.
const safeScript = script.replace(/<\/script/gi, "<\\/script");

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Omnodex Dashboard</title>
<link rel="icon" type="image/png" href="data:image/png;base64,${favicon}">
<style>${style}</style>
</head>
<body>
<div id="root"></div>
<script>${safeScript}</script>
</body>
</html>
`;

mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, html);
console.log(`dashboard: ${outFile} (${(html.length / 1024).toFixed(1)} KB)`);
