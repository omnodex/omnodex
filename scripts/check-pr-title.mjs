#!/usr/bin/env node
// check-pr-title.mjs
//
// CI guard for pull request titles. PRs are squash-merged with the title as
// the commit subject, and release notes are grouped from those subjects, so
// the title has to follow the convention in conventional.mjs.
//
// Usage: PR_TITLE="fix(cli): ..." node scripts/check-pr-title.mjs
//        node scripts/check-pr-title.mjs "fix(cli): ..."

import { checkTitle } from "./conventional.mjs";

const title = process.argv[2] ?? process.env.PR_TITLE ?? "";
const problems = checkTitle(title);
if (problems.length > 0) {
  console.error(`PR title "${title}":`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error("\nEdit the title on the PR page; this check reruns on its own.");
  process.exit(1);
}
console.log(`check-pr-title: OK -- "${title}"`);
