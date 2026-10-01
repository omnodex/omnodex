#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

// check-licence.mjs
//
// CI guard: Omnodex is licensed AGPL-3.0-only (see LICENSE), alongside a
// commercial license. A notice granting "or any later version" would give
// rights the project does not grant, so no tracked file or package manifest
// may say so.
//
// Usage: node scripts/check-licence.mjs

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const PATTERNS = [/AGPL-3\.0-or-later/, /AGPL-3\.0\+/, /GPL-3\.0-or-later/, /or \(at your option\) any later version/i];
const SELF = "scripts/check-licence.mjs";

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" })
  .split("\0")
  .filter((f) => f && f !== SELF && f !== "package-lock.json" && /\.(?:ts|tsx|mts|js|mjs|cjs|json|md|css|html|yml|yaml)$/i.test(f));

const problems = [];
for (const file of files) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  text.split(/\r?\n/).forEach((line, i) => {
    for (const re of PATTERNS) {
      const m = re.exec(line);
      if (m) problems.push(`${file}:${i + 1}: "${m[0]}"`);
    }
  });
}

if (problems.length > 0) {
  console.error("check-licence: Omnodex is AGPL-3.0-only; remove these \"or later\" notices:\n");
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`check-licence: OK -- ${files.length} files scanned, no "or later" licence notices.`);
