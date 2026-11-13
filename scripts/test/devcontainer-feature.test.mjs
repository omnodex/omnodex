// The devcontainer feature: valid metadata, an install script that refuses
// unsafe input, and a post-create step that is a no-op without settings.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "devcontainer", "src", "omnodex");
const posix = process.platform !== "win32";

test("feature metadata is complete and the lifecycle command points at the generated script", () => {
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "devcontainer-feature.json"), "utf8"));
  assert.equal(meta.id, "omnodex");
  assert.match(meta.version, /^\d+\.\d+\.\d+$/);
  assert.ok(meta.options.agents.default.includes("claude-code"));
  assert.equal(meta.postCreateCommand, "/usr/local/share/omnodex-feature/post-create.sh");
  assert.ok(meta.installsAfter.includes("ghcr.io/devcontainers/features/node"));
});

test("install.sh is valid shell", { skip: !posix }, () => {
  assert.equal(spawnSync("sh", ["-n", path.join(dir, "install.sh")]).status, 0);
});

// A fake npm on PATH records the install and lets the script run unprivileged.
function runInstall(env) {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-feat-bin-"));
  fs.writeFileSync(path.join(bin, "npm"), '#!/bin/sh\necho "$@" >> "$FAKE_LOG"\n', { mode: 0o755 });
  const log = path.join(bin, "log");
  const r = spawnSync("sh", [path.join(dir, "install.sh")], {
    env: { PATH: `${bin}:${process.env.PATH}`, FAKE_LOG: log, ...env },
    encoding: "utf8",
  });
  return { ...r, log: fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "" };
}

test("MUST_NOT_FIRE: install.sh rejects agent lists and versions that are not plain names", { skip: !posix }, () => {
  for (const env of [{ AGENTS: "claude-code; rm -rf /" }, { AGENTS: "a b" }, { VERSION: "1.0.0 && x" }, { VERSION: "$(x)" }]) {
    const r = runInstall(env);
    assert.notEqual(r.status, 0, JSON.stringify(env));
    assert.equal(r.log, "");
  }
});

test("MUST_NOT_FIRE: install.sh stops without npm", { skip: !posix }, () => {
  const r = spawnSync("sh", [path.join(dir, "install.sh")], { env: { PATH: "/nonexistent" }, encoding: "utf8" });
  assert.notEqual(r.status, 0);
});
