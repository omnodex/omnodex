// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

// Builds the publishable `omnodex` npm package into bundle/ (or --out <dir>).
//
// Layout:
//   package.json                 copied from publish-package.json
//   omnodex-bundle.cjs           the CLI
//   dashboard.html
//   bin/omnodex                  CLI entry
//   bin/omnodex-mcp-proxy.js     MCP proxy entry (used by the agent plugins)
//   bin/<platform>-hook-shim.js  hook shims, found by the ~/.omnodex/bin launchers
//
// The shims must sit in bin/ next to the bundle: the CLI resolves
// CLAUDE_HOOK_SHIM_PATH and friends relative to its own file, and the
// launchers look for <package>/bin/<shim>.

import { build } from "esbuild";
import { writeFileSync, chmodSync, copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const pkgDir = import.meta.dirname;
const outIdx = process.argv.indexOf("--out");
const outDir = outIdx !== -1 ? process.argv[outIdx + 1] : join(pkgDir, "bundle");

// Replace import.meta.url with its CJS equivalent
const importMetaPlugin = {
  name: "import-meta-url",
  setup(build) {
    build.onLoad({ filter: /\.js$/ }, async (args) => {
      const fs = await import("fs");
      let contents = fs.readFileSync(args.path, "utf8");
      if (contents.includes("import.meta.url")) {
        contents = contents.replaceAll(
          "import.meta.url",
          "require(\"url\").pathToFileURL(__filename).href"
        );
        return { contents, loader: "js" };
      }
      return null;
    });
  },
};

/** Standalone executables bundled into bin/, keyed by output filename. */
const BIN_ENTRIES = {
  "omnodex-mcp-proxy.js": "../mcp-proxy/dist/bin/omnodex-mcp-proxy.js",
  "claude-hook-shim.js": "../hooks-provider/dist/bin/claude-hook-shim.js",
  "codex-hook-shim.js": "../codex-provider/dist/bin/codex-hook-shim.js",
  "antigravity-hook-shim.js": "../antigravity-provider/dist/bin/antigravity-hook-shim.js",
};

async function bundle(entry, outfile) {
  await build({
    entryPoints: [join(pkgDir, entry)],
    bundle: true,
    platform: "node",
    target: "node24",
    outfile,
    format: "cjs",
    plugins: [importMetaPlugin],
  });
}

mkdirSync(join(outDir, "bin"), { recursive: true });

await bundle("dist/index.js", join(outDir, "omnodex-bundle.cjs"));

for (const [name, entry] of Object.entries(BIN_ENTRIES)) {
  const outfile = join(outDir, "bin", name);
  await bundle(entry, outfile);
  chmodSync(outfile, 0o755);
}

// CJS launcher with shebang
writeFileSync(join(outDir, "bin", "omnodex"), `#!/usr/bin/env node\nrequire("../omnodex-bundle.cjs");\n`);
chmodSync(join(outDir, "bin", "omnodex"), 0o755);

// From src/: `tsc -b` alone (as in CI) does not copy it into dist/
copyFileSync(join(pkgDir, "src", "dashboard.html"), join(outDir, "dashboard.html"));
copyFileSync(join(pkgDir, "publish-package.json"), join(outDir, "package.json"));

console.log(`Bundle written to ${outDir}`);
