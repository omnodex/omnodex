// Scratch homes must remain isolated when TEMP belongs to another checkout.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { gitTestEnv } from "../test-git.mjs";

function enclosingRepo(t) {
  const dir = mkdtempSync(join(tmpdir(), "omnodex-enclosing-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const result = spawnSync("git", ["init", "-q", dir], { env: gitTestEnv(dir), encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return dir;
}

test("scratch Git discovery ignores an enclosing repository but finds fixture repositories", (t) => {
  const enclosing = enclosingRepo(t);
  const scratch = mkdtempSync(join(enclosing, "scratch-"));
  const env = { ...process.env, GIT_CEILING_DIRECTORIES: "" };
  const unbounded = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: scratch, env, encoding: "utf8" });
  assert.equal(unbounded.status, 0, unbounded.stderr);
  assert.equal(basename(unbounded.stdout.trim()), basename(enclosing));
  const isolated = gitTestEnv(scratch, env);
  const outside = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: scratch, env: isolated, encoding: "utf8" });
  assert.notEqual(outside.status, 0, "scratch must not discover the enclosing repository");
  const repo = join(scratch, "repo");
  const init = spawnSync("git", ["init", "-q", repo], { env: isolated, encoding: "utf8" });
  assert.equal(init.status, 0, init.stderr);
  const nested = join(repo, "src");
  mkdirSync(nested);
  const inside = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: nested, env: isolated, encoding: "utf8" });
  assert.equal(inside.status, 0, inside.stderr);
  assert.equal(basename(inside.stdout.trim()), "repo");
});

test("the shared home helper isolates Git when TEMP is inside an enclosing repository", (t) => {
  const enclosing = enclosingRepo(t);
  const helper = new URL("../test-home.mjs", import.meta.url).href;
  const script = `
    import ${JSON.stringify(helper)};
    import { spawnSync } from "node:child_process";
    const result = spawnSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: process.env.HOME, env: process.env, encoding: "utf8"
    });
    console.log(JSON.stringify({ status: result.status, error: result.error?.message }));
  `;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, TEMP: enclosing, TMP: enclosing, TMPDIR: enclosing, GIT_CEILING_DIRECTORIES: "" },
    encoding: "utf8",
  });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0, "the helper's scratch home must not find its enclosing repository");
});
