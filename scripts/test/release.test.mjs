import { test } from "node:test";
import assert from "node:assert/strict";
import { checkTitle, parseSubject, releaseNotes } from "../conventional.mjs";
import { compareVersions, nextVersion, parseVersion } from "../release.mjs";

test("parseSubject reads type, scope, breaking and summary", () => {
  assert.deepEqual(parseSubject("feat(cli): add a flag (#12)"), {
    type: "feat",
    scope: "cli",
    breaking: false,
    summary: "add a flag (#12)",
  });
  assert.equal(parseSubject("fix!: drop the old format").breaking, true);
  assert.equal(parseSubject("fix: no scope").scope, null);
});

test("parseSubject rejects subjects outside the convention", () => {
  for (const s of ["Feature/client name payload (#51)", "feat:missing space", "Feat: capital", "wip: thing", "feat(Cli): x"]) {
    assert.equal(parseSubject(s), null, s);
  }
});

test("checkTitle accepts a conventional title and flags the rest", () => {
  assert.deepEqual(checkTitle("fix(dashboard): keep the session list sorted"), []);
  assert.equal(checkTitle("Feature/local dash data").length, 1);
  assert.match(checkTitle("fix: close ENG-12 in the proxy").join(), /internal reference "ENG-12"/);
  assert.match(checkTitle(`feat: ${"x".repeat(100)}`).join(), /characters/);
  // The squash-merge suffix does not count toward the length.
  assert.deepEqual(checkTitle(`feat: ${"x".repeat(94)} (#123)`), []);
});

test("releaseNotes groups by type and leaves out maintenance", () => {
  const notes = releaseNotes([
    "fix(sync): pair routed calls (#48)",
    "ci: run on macOS",
    "feat(cli): publish the proxy command (#52)",
    "Feature/local dash data (#47)",
    "feat!: rename the config file",
    "test: cover the collapse",
  ]);
  assert.equal(
    notes,
    [
      "## Features",
      "",
      "- **cli:** publish the proxy command (#52)",
      "- **Breaking:** rename the config file",
      "",
      "## Fixes",
      "",
      "- **sync:** pair routed calls (#48)",
      "",
      "## Other changes",
      "",
      "- Feature/local dash data (#47)",
      "",
    ].join("\n"),
  );
  assert.match(releaseNotes(["ci: only this"]), /no user-facing changes/);
});

test("nextVersion bumps within 0.x", () => {
  assert.deepEqual(nextVersion(parseVersion("v0.2.0"), "minor"), [0, 3, 0]);
  assert.deepEqual(nextVersion(parseVersion("0.3.4"), "patch"), [0, 3, 5]);
  assert.throws(() => nextVersion([0, 1, 0], "major"));
  assert.ok(compareVersions(parseVersion("0.10.0"), parseVersion("0.9.9")) > 0);
});
