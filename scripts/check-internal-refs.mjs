#!/usr/bin/env node
// check-internal-refs.mjs
//
// CI guard: this repository is public, so its code and docs must stand on
// their own. Fails when a tracked file points at documents or tracking IDs
// that live outside it: planning or agent docs, feature spec numbers, or
// work item IDs. Say what the code does instead of where it was decided.
//
// Usage: node scripts/check-internal-refs.mjs

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const PATTERNS = [
  { re: /(?<![\w.-])planning\//, why: "path into internal planning docs" },
  { re: /(?<![\w.-])agents\/[A-Z]/, why: "path into internal agent docs" },
  { re: /\b(?:PRODUCT_CONTEXT|OPERATIONAL_CONTEXT|TASK_TRACKING|PROJECT_TRACKER)\b/, why: "internal context doc" },
  { re: /\bFS-\d{3}\b/, why: "feature spec number" },
  { re: /\b(?:ENG|BUG|VAL|PRD|BUS)-\d{3}\b/, why: "work item ID" },
  { re: /\bworkstream:/, why: "internal tracking label" },
];

// Text extensions worth scanning; binaries and lockfiles are skipped.
const SCANNED = /\.(?:ts|mts|cts|js|mjs|cjs|json|md|mdx|yml|yaml|html|css|sh|ps1|txt)$/i;
const SKIPPED = new Set(["package-lock.json", "scripts/check-internal-refs.mjs"]);

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" })
  .split("\0")
  .filter((f) => f && SCANNED.test(f) && !SKIPPED.has(f));

const problems = [];
for (const file of files) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  text.split(/\r?\n/).forEach((line, i) => {
    for (const { re, why } of PATTERNS) {
      const match = re.exec(line);
      if (match) problems.push(`${file}:${i + 1}: ${why}: "${match[0]}"`);
    }
  });
}

if (problems.length > 0) {
  console.error("check-internal-refs: this repository is public; remove these references:\n");
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`check-internal-refs: OK -- ${files.length} files scanned, no internal references.`);
