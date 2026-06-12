// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

import { build } from "esbuild";
import { writeFileSync, chmodSync } from "fs";

// Plugin: replace import.meta.url with CJS equivalent
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

await build({
  entryPoints: ["dist/index.js"],
  bundle: true,
  platform: "node",
  target: "node24",
  outfile: "bundle/omnodex-bundle.cjs",
  format: "cjs",
  plugins: [importMetaPlugin],
});

// CJS launcher with shebang
import { mkdirSync } from "fs";
mkdirSync("bundle/bin", { recursive: true });
writeFileSync("bundle/bin/omnodex", `#!/usr/bin/env node\nrequire("../omnodex-bundle.cjs");\n`);
chmodSync("bundle/bin/omnodex", 0o755);

// Copy dashboard.html into the bundle directory
import { copyFileSync } from "fs";
copyFileSync("dist/dashboard.html", "bundle/dashboard.html");

console.log("Bundle written to bundle/omnodex-bundle.cjs + omnodex.cjs launcher");
