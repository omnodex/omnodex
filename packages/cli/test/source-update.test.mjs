// The update notice for a source install counts only commits on the branch
// it updates from that HEAD does not have. A new tag or another branch on
// the remote is not an update.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { sourceUpdateNotice, sourceUpdateStatus, sourceUpdateTarget } from "../dist/update.js";

function git(cwd, ...args) {
  const r = spawnSync("git", ["-c", "user.name=case", "-c", "user.email=case@example.com", "-c", "init.defaultBranch=main", ...args], { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

async function commit(repo, name) {
  await writeFile(path.join(repo, name), name);
  git(repo, "add", name);
  git(repo, "commit", "-q", "-m", `add ${name}`);
}

/** A remote with one commit on main, a clone of it, and a second clone that pushes. */
async function setup(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-source-update-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const remote = path.join(dir, "remote.git");
  const install = path.join(dir, "install");
  const other = path.join(dir, "other");
  git(dir, "init", "-q", "--bare", remote);
  git(dir, "clone", "-q", remote, other);
  await commit(other, "a.txt");
  git(other, "push", "-q", "origin", "HEAD:main");
  git(dir, "clone", "-q", remote, install);
  return { install, other };
}

test("a new tag or a new remote branch is not an update", async (t) => {
  const { install, other } = await setup(t);
  assert.deepEqual(sourceUpdateStatus(install), { target: "origin/main", behind: 0 });

  git(other, "tag", "v0.8.0");
  git(other, "push", "-q", "origin", "v0.8.0");
  git(other, "checkout", "-q", "-b", "feature/x");
  await commit(other, "b.txt");
  git(other, "push", "-q", "origin", "feature/x");
  git(install, "fetch", "-q", "--tags", "origin");

  assert.deepEqual(sourceUpdateStatus(install), { target: "origin/main", behind: 0 });
  assert.equal(sourceUpdateNotice({ repoRoot: install, branch: "main", sha: "abc1234" }), null);
});

test("a new commit on main is an update, counted", async (t) => {
  const { install, other } = await setup(t);
  await commit(other, "b.txt");
  await commit(other, "c.txt");
  git(other, "push", "-q", "origin", "HEAD:main");
  git(install, "fetch", "-q", "--no-tags", "origin", "main");

  assert.deepEqual(sourceUpdateStatus(install), { target: "origin/main", behind: 2 });
  assert.equal(
    sourceUpdateNotice({ repoRoot: install, branch: "main", sha: "abc1234" }),
    "Omnodex source updates available: 2 new commits on origin/main (main @ abc1234)",
  );

  git(install, "pull", "-q", "--ff-only");
  assert.equal(sourceUpdateNotice({ repoRoot: install, branch: "main", sha: "def5678" }), null);
});

test("a local branch with no upstream compares with origin/main", async (t) => {
  const { install, other } = await setup(t);
  git(install, "checkout", "-q", "--no-track", "-b", "full-history", "origin/main");
  await commit(install, "local.txt");
  assert.equal(sourceUpdateTarget(install), "origin/main");
  assert.equal(sourceUpdateStatus(install).behind, 0, "local commits ahead are not an update");

  await commit(other, "b.txt");
  git(other, "push", "-q", "origin", "HEAD:main");
  git(install, "fetch", "-q", "--no-tags", "origin", "main");
  assert.equal(sourceUpdateStatus(install).behind, 1);
});

test("a checkout with no remote has nothing to compare with", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-source-update-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  git(dir, "init", "-q");
  await commit(dir, "a.txt");
  assert.equal(sourceUpdateTarget(dir), null);
  assert.equal(sourceUpdateNotice({ repoRoot: dir, branch: "main", sha: "abc1234" }), null);
});
