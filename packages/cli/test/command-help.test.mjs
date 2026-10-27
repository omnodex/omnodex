import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { COMMAND_OPTIONS, commandOptionError } from "../dist/command-options.js";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const GUARD = fileURLToPath(new URL("./helpers/no-command-effects.cjs", import.meta.url));

async function snapshot(dir) {
  const entries = [];
  for (const name of (await fs.readdir(dir)).sort()) {
    const file = path.join(dir, name);
    const stat = await fs.stat(file);
    entries.push([name, stat.mtimeMs, stat.isDirectory() ? await snapshot(file) : (await fs.readFile(file)).toString("base64")]);
  }
  return entries;
}

async function scratch(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-help-case-"));
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const home = path.join(root, "home");
  const data = path.join(home, ".omnodex");
  await fs.mkdir(path.join(data, "bin"), { recursive: true });
  await fs.writeFile(path.join(data, "stream-config.json"), JSON.stringify({
    api_token: "omx_case", passphrase: "case-secret", api_url: "http://127.0.0.1:9",
  }));
  await fs.writeFile(path.join(data, "bin", "codex-hook-launcher.js"), "// stale case launcher\n");
  await fs.writeFile(path.join(data, "live-push-state.json"), JSON.stringify({ paused_until: Date.now() + 600_000, backoff_ms: 60_000 }));
  const effects = path.join(root, "effects.log");
  await fs.writeFile(effects, "");
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(OMNODEX_|NODE_OPTIONS$|HOME$|USERPROFILE$|CODEX_HOME$|CLAUDE_CONFIG_DIR$)/i.test(key)));
  Object.assign(env, {
    HOME: home, USERPROFILE: home, OMNODEX_HOME: data, OMNODEX_SINGLE_ROOT: "1",
    CODEX_HOME: path.join(home, ".codex"), CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
    OMNODEX_API_TOKEN: "omx_case", OMNODEX_STREAM_SECRET: "case-secret",
    OMNODEX_SYNC_PASSPHRASE: "case-secret", OMNODEX_API_URL: "http://127.0.0.1:9",
    CASE_EFFECT_LOG: effects,
  });
  return { home, effects, env };
}

function run(ctx, args, extraEnv = {}) {
  return spawnSync(process.execPath, ["--require", GUARD, CLI, ...args], {
    cwd: ctx.home, env: { ...ctx.env, ...extraEnv }, encoding: "utf8", timeout: 15_000,
  });
}

async function unchanged(ctx, before) {
  assert.equal(await fs.readFile(ctx.effects, "utf8"), "", "no network, process launch or filesystem mutation attempted");
  assert.deepEqual(await snapshot(ctx.home), before, "home contents and modification times must be unchanged");
}

test("help coverage includes every command in the CLI dispatcher", async () => {
  const source = await fs.readFile(new URL("../src/index.ts", import.meta.url), "utf8");
  const main = source.slice(source.indexOf("async function main()"));
  const commands = [...main.matchAll(/case "([^\"]+)":/g)].map((m) => m[1])
    .filter((c) => !["help", "--help", "-h", "--version", "-V"].includes(c));
  assert.deepEqual(Object.keys(COMMAND_OPTIONS).sort(), commands.sort());
});

for (const [command, options] of Object.entries(COMMAND_OPTIONS)) {
  const paths = [[command], ...Object.keys(options.subcommands ?? {}).map((sub) => [command, sub])];
  if (command === "clear") {
    paths.push([command, "case-session", "--unattended"], [command, "--all", "--confirm", "--unattended"]);
  }
  for (const args of paths) {
    const usageCommand = options.subcommands && Object.hasOwn(options.subcommands, args[1])
      ? args.slice(0, 2).join(" ") : command;
    for (const flag of ["--help", "-h"]) {
      test(`${args.join(" ")} ${flag} exits successfully without effects`, async (t) => {
        const ctx = await scratch(t);
        const before = await snapshot(ctx.home);
        const result = run(ctx, [...args, flag]);
        assert.equal(result.error, undefined);
        assert.equal(result.status, 0, result.stderr);
        assert.ok(result.stdout.startsWith(`Usage: omnodex ${usageCommand}`), result.stdout);
        assert.match(result.stdout, /--help, -h/);
        if (command === "clear") assert.match(result.stdout, /--unattended/);
        await unchanged(ctx, before);
      });
    }
    test(`${args.join(" ")} rejects unknown flags before effects`, async (t) => {
      const ctx = await scratch(t);
      const before = await snapshot(ctx.home);
      const result = run(ctx, [...args, "--case-unknown"]);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /unknown option '--case-unknown'/);
      await unchanged(ctx, before);
    });
  }
}

for (const args of [
  [], ["help"], ["--help"], ["-h"], ["mcp-proxy", "help"],
  ["clear", "--all", "--confirm", "--help"],
  ["uninstall", "codex", "--everywhere", "--unattended", "--confirm", "-h"],
  ["install", "codex", "--yes", "--help"],
  ["sync", "--token", "omx_case", "--secret", "case-secret", "--help"],
  ["mcp-proxy", "serve", "--http", "127.0.0.1:8787", "-h"],
]) {
  test(`${args.join(" ") || "no command"} prints help without startup effects`, async (t) => {
    const ctx = await scratch(t);
    const before = await snapshot(ctx.home);
    const result = run(ctx, args);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /omnodex/);
    await unchanged(ctx, before);
  });
}

test("recognized options keep their existing value syntax", () => {
  for (const [command, args] of [
    ["install", ["codex", "--hooks", "-y", "--from=case.plugin", "--sha256=abc"]],
    ["clear", ["case-session", "--unattended"]],
    ["clear", ["--all", "--confirm", "--unattended"]],
    ["sync", ["--token", "omx_case", "--passphrase", "case phrase", "--sessions", "a,b"]],
    ["spike", ["case", "--seed", "-1", "--scenario-set", "history", "--machine", "a"]],
    ["dashboard", ["0", "--roots", "/home/case/a", "/home/case/b", "--no-detect"]],
    ["mcp-proxy", ["serve", "--http", "127.0.0.1:0", "--allow-remote", "--config", "case.json"]],
  ]) assert.equal(commandOptionError(command, args), undefined);
  assert.match(commandOptionError("sync", ["--token"]), /requires a value/);
  assert.match(commandOptionError("clear", ["--confirm=true"]), /unknown option/);
  assert.match(commandOptionError("mcp-proxy", ["install", "--allow-remote"]), /unknown option/);
});
