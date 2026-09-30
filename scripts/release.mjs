#!/usr/bin/env node
// release.mjs
//
// Helpers for the Release workflow (.github/workflows/release.yml).
//
//   node scripts/release.mjs plan --bump patch|minor
//     Decides the next version and whether anything shipped has changed
//     since the last release. Prints a summary and, under GitHub Actions,
//     writes `version`, `tag`, `changed` and `last_tag` to $GITHUB_OUTPUT.
//
//   node scripts/release.mjs stamp <package-dir> <version>
//     Writes the version into a built package's package.json.
//
//   node scripts/release.mjs notes [<last-tag>]
//     Prints release notes for the commits since <last-tag> that touch what
//     ships, grouped by type (see conventional.mjs).
//
// The released version lives in git tags (vX.Y.Z) and on npm, never in a
// commit: the next version is one bump past the higher of npm's latest and
// the newest v* tag. Releases stay on 0.x: "minor" for features, "patch"
// for fixes.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { releaseNotes } from "./conventional.mjs";

const PACKAGE = "omnodex";
/** What ships in the npm package. A release with no change here is skipped. */
const SHIPPED_PATHS = ["packages", "package.json", "package-lock.json", "tsconfig.base.json"];

export function parseVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(v).trim());
  return m ? m.slice(1).map(Number) : null;
}

export function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function nextVersion(current, bump) {
  const [major, minor, patch] = current;
  if (bump === "minor") return [major, minor + 1, 0];
  if (bump === "patch") return [major, minor, patch + 1];
  throw new Error(`unknown bump "${bump}" (use patch or minor)`);
}

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

function latestTag() {
  const tags = git("tag", "--list", "v*").split("\n").filter((t) => parseVersion(t));
  tags.sort((a, b) => compareVersions(parseVersion(b), parseVersion(a)));
  return tags[0] ?? null;
}

function npmLatest() {
  try {
    return execFileSync("npm", ["view", PACKAGE, "version"], { encoding: "utf8", shell: process.platform === "win32" }).trim();
  } catch {
    return null;
  }
}

function plan(bump) {
  const tag = latestTag();
  const candidates = [tag, npmLatest()].map((v) => v && parseVersion(v)).filter(Boolean);
  const base = candidates.sort((a, b) => compareVersions(b, a))[0] ?? [0, 0, 0];
  const version = nextVersion(base, bump).join(".");
  let changed = true;
  if (tag) {
    try {
      git("diff", "--quiet", tag, "HEAD", "--", ...SHIPPED_PATHS);
      changed = false;
    } catch {
      changed = true;
    }
  }
  const out = { version, tag: `v${version}`, changed: String(changed), last_tag: tag ?? "" };
  console.log(`last release: ${tag ?? "(none tagged)"}; next: ${out.tag}; shipped code changed: ${changed}`);
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(out).map(([k, v]) => `${k}=${v}\n`).join(""));
  }
  return out;
}

function stamp(dir, version) {
  if (!parseVersion(version)) throw new Error(`not a version: ${version}`);
  const file = join(dir, "package.json");
  const pkg = JSON.parse(readFileSync(file, "utf8"));
  pkg.version = version;
  writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
  console.log(`${file}: version ${version}`);
}

function notes(lastTag) {
  if (!lastTag) return "First release published by the Release workflow.\n";
  const log = git("log", "--format=%s", `${lastTag}..HEAD`, "--", ...SHIPPED_PATHS);
  return releaseNotes(log.split("\n"));
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
const [cmd, ...rest] = isMain ? process.argv.slice(2) : [];
if (cmd === "plan") {
  const i = rest.indexOf("--bump");
  plan(i === -1 ? "patch" : rest[i + 1]);
} else if (cmd === "stamp") {
  stamp(rest[0], rest[1]);
} else if (cmd === "notes") {
  process.stdout.write(notes(rest[0]));
} else if (cmd) {
  console.error(`unknown command: ${cmd}`);
  process.exit(2);
}
