// Tests for reading a project's git origin remote at session start:
// normalizing remote URLs, parsing git config, finding the repository from
// a nested folder or a linked worktree, and stamping session.started.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  normalizeGitRemote,
  originUrlFromConfig,
  readProjectRemote,
  withProjectRemote,
} from "../dist/index.js";

async function scratch(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-remote-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** A repository at `dir` whose config has `body` after the core section. */
async function makeRepo(dir, body) {
  await mkdir(path.join(dir, ".git"), { recursive: true });
  await writeFile(path.join(dir, ".git", "config"), `[core]\n\tbare = false\n${body}`, "utf8");
}

const ORIGIN = '[remote "origin"]\n\turl = git@github.com:case/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n';

test("normalizeGitRemote: ssh and https forms of one repository are equal", () => {
  const forms = [
    "git@github.com:case/repo.git",
    "git@github.com:case/repo",
    "ssh://git@github.com/case/repo.git",
    "ssh://git@github.com:22/case/repo.git",
    "https://github.com/case/repo.git",
    "https://github.com/case/repo",
    "https://github.com/case/repo/",
    "https://GitHub.com/case/repo.git",
  ];
  for (const url of forms) assert.equal(normalizeGitRemote(url), "github.com/case/repo", url);
});

test("normalizeGitRemote: credentials and ports never survive", () => {
  assert.equal(normalizeGitRemote("https://case:ghp_secret@github.com/case/repo.git"), "github.com/case/repo");
  assert.equal(normalizeGitRemote("https://oauth2:token@gitlab.example.com:8443/group/sub/repo.git"), "gitlab.example.com/group/sub/repo");
});

test("normalizeGitRemote: the path keeps its case", () => {
  assert.equal(normalizeGitRemote("https://git.example.com/Case/Repo.git"), "git.example.com/Case/Repo");
});

test("normalizeGitRemote: local paths and junk have no remote", () => {
  for (const url of ["/srv/git/repo.git", "../repo", "file:///srv/git/repo.git", "C:\\repos\\repo", "C:/repos/repo", "", "   ", "not a url"]) {
    assert.equal(normalizeGitRemote(url), undefined, JSON.stringify(url));
  }
});

test("originUrlFromConfig: reads origin's url, not another remote's", () => {
  const config = '[remote "upstream"]\n\turl = https://github.com/other/repo.git\n' + ORIGIN + '[branch "main"]\n\tremote = origin\n';
  assert.equal(originUrlFromConfig(config), "git@github.com:case/repo.git");
});

test("originUrlFromConfig: quoted values, CRLF and comments", () => {
  const config = '# comment\r\n[remote "origin"]\r\n\t; another\r\n\turl = "https://github.com/case/repo.git"\r\n';
  assert.equal(originUrlFromConfig(config), "https://github.com/case/repo.git");
});

test("originUrlFromConfig: no origin, no url", () => {
  assert.equal(originUrlFromConfig('[remote "upstream"]\n\turl = https://github.com/other/repo.git\n'), undefined);
  assert.equal(originUrlFromConfig(""), undefined);
});

test("readProjectRemote: found from a nested folder", async (t) => {
  const dir = await scratch(t);
  await makeRepo(dir, ORIGIN);
  const nested = path.join(dir, "packages", "app");
  await mkdir(nested, { recursive: true });
  assert.equal(await readProjectRemote(nested), "github.com/case/repo");
});

test("readProjectRemote: a linked worktree reads the main repository's config", async (t) => {
  const dir = await scratch(t);
  const main = path.join(dir, "repo");
  await makeRepo(main, ORIGIN);
  const gitDir = path.join(main, ".git", "worktrees", "wt");
  await mkdir(gitDir, { recursive: true });
  await writeFile(path.join(gitDir, "commondir"), "../..\n", "utf8");
  const wt = path.join(dir, "wt");
  await mkdir(wt);
  await writeFile(path.join(wt, ".git"), `gitdir: ${gitDir}\n`, "utf8");
  assert.equal(await readProjectRemote(wt), "github.com/case/repo");
});

test("readProjectRemote: a .git file with a relative gitdir", async (t) => {
  const dir = await scratch(t);
  const main = path.join(dir, "repo");
  await makeRepo(main, ORIGIN);
  const gitDir = path.join(main, ".git", "worktrees", "wt");
  await mkdir(gitDir, { recursive: true });
  await writeFile(path.join(gitDir, "commondir"), "../..\n", "utf8");
  const wt = path.join(dir, "wt");
  await mkdir(wt);
  await writeFile(path.join(wt, ".git"), "gitdir: ../repo/.git/worktrees/wt\n", "utf8");
  assert.equal(await readProjectRemote(wt), "github.com/case/repo");
});

test("readProjectRemote: no repository, no origin, or a missing folder reads as none", async (t) => {
  const dir = await scratch(t);
  assert.equal(await readProjectRemote(path.join(dir, "missing")), undefined);
  const noOrigin = path.join(dir, "no-origin");
  await makeRepo(noOrigin, '[remote "upstream"]\n\turl = https://github.com/other/repo.git\n');
  assert.equal(await readProjectRemote(noOrigin), undefined);
  assert.equal(await readProjectRemote("unknown"), undefined);
  assert.equal(await readProjectRemote(undefined), undefined);
});

test("withProjectRemote: stamps session.started only, and leaves other events alone", async (t) => {
  const dir = await scratch(t);
  await makeRepo(dir, ORIGIN);
  const start = { event_type: "session.started", event_id: "e1", project_path: dir };
  const call = { event_type: "tool.invoked", event_id: "e2" };
  const [stamped, untouched] = await withProjectRemote([start, call]);
  assert.equal(stamped.project_remote, "github.com/case/repo");
  assert.equal(untouched, call);
});

test("withProjectRemote: a batch with no session.started is returned as is", async () => {
  const events = [{ event_type: "tool.invoked", event_id: "e2" }];
  assert.equal(await withProjectRemote(events), events);
});

test("withProjectRemote: a folder with no remote adds no field", async (t) => {
  const dir = await scratch(t);
  const [start] = await withProjectRemote([{ event_type: "session.started", event_id: "e1", project_path: dir }]);
  assert.ok(!("project_remote" in start));
});
