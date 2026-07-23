#!/usr/bin/env node
// check-project-references.mjs
//
// CI guard (ENG-171): asserts every package's `@omnodex/*` runtime dependency
// has a matching `tsconfig.json` project reference. Without a reference, a
// clean `tsc -b` build can fail with TS2307 ("Cannot find module") because
// the dependency's `.d.ts` output was never built first -- the failure only
// shows up on a clean build, since a stale `dist/` from a previous build
// (e.g. via `tsc --watch` or an out-of-order local build) can mask it.
//
// Usage: node scripts/check-project-references.mjs
// Exit code 0 = all good, 1 = one or more packages missing a reference.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const packagesDir = join(repoRoot, "packages");

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

const packageDirs = readdirSync(packagesDir).filter((name) =>
  statSync(join(packagesDir, name)).isDirectory()
);

// Map package name (e.g. "@omnodex/shared") -> directory name (e.g. "shared")
const nameToDir = new Map();
for (const dir of packageDirs) {
  const pkgJsonPath = join(packagesDir, dir, "package.json");
  try {
    const pkg = readJson(pkgJsonPath);
    nameToDir.set(pkg.name, dir);
  } catch {
    // No package.json (or unreadable) -- skip, not a package dir.
  }
}

let hasErrors = false;

for (const dir of packageDirs) {
  const pkgJsonPath = join(packagesDir, dir, "package.json");
  const tsconfigPath = join(packagesDir, dir, "tsconfig.json");

  let pkg;
  try {
    pkg = readJson(pkgJsonPath);
  } catch {
    continue; // Not a package (e.g. stray directory).
  }

  const omnodexDeps = Object.keys(pkg.dependencies || {}).filter((d) =>
    d.startsWith("@omnodex/")
  );

  if (omnodexDeps.length === 0) continue;

  let tsconfig;
  try {
    tsconfig = readJson(tsconfigPath);
  } catch {
    console.error(
      `[check-project-references] ${dir}: has @omnodex/* dependencies but no readable tsconfig.json`
    );
    hasErrors = true;
    continue;
  }

  const referencedDirs = new Set(
    (tsconfig.references || []).map((r) =>
      // Reference paths are relative to this package's dir, e.g. "../shared".
      r.path.replace(/^\.\.\//, "").replace(/\/$/, "")
    )
  );

  for (const depName of omnodexDeps) {
    const depDir = nameToDir.get(depName);
    if (!depDir) {
      console.error(
        `[check-project-references] ${dir}: depends on ${depName}, but no package named ${depName} exists under packages/`
      );
      hasErrors = true;
      continue;
    }
    if (!referencedDirs.has(depDir)) {
      console.error(
        `[check-project-references] packages/${dir}: depends on ${depName} (package.json) but is missing a tsconfig.json project reference to "../${depDir}"`
      );
      hasErrors = true;
    }
  }
}

if (hasErrors) {
  console.error(
    "\ncheck-project-references: FAILED -- fix the missing reference(s) above (add to the package's tsconfig.json \"references\" array), then re-run.\n"
  );
  process.exit(1);
}

console.log("check-project-references: OK -- all @omnodex/* dependencies have matching project references.");
