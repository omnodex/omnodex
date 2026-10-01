/**
 * `omnodex install` must not wait on the dashboard sign-in when nobody can
 * answer it: with --no-connect, or without a terminal (a script, CI, or an
 * agent running the command).
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs, existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { skipConnectReason } from "../dist/connect-prompt.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

test("the sign-in is skipped with --no-connect or without a terminal", () => {
  assert.equal(skipConnectReason(["--no-connect"], true), "--no-connect");
  assert.equal(skipConnectReason([], false), "not running in a terminal");
  assert.equal(skipConnectReason([], undefined), "not running in a terminal");
  assert.equal(skipConnectReason(["--debug"], true), null);
});

test("install without a terminal finishes and says how to connect later", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-install-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const home = path.join(root, "home");
  const project = path.join(root, "project");
  await fs.mkdir(project, { recursive: true });
  // An isolated home: never the developer's real ~/.omnodex.
  const env = { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: path.join(home, ".omnodex") };

  const child = spawn(process.execPath, [CLI, "install", "claude-code", project], { env, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.end();
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const code = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`install did not finish:\n${out}`));
    }, 30000);
    child.on("exit", (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });

  assert.equal(code, 0, out);
  assert.match(out, /skipped the dashboard sign-in \(not running in a terminal\)/);
  assert.match(out, /omnodex connect/);
  assert.ok(existsSync(path.join(project, ".claude", "settings.local.json")), "hooks were installed");
  assert.ok(!existsSync(path.join(home, ".omnodex", "stream-config.json")), "no half-written cloud connection");
});
