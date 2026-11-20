// `omnodex auth login|status|logout <upstream>`. Sign-in itself is covered in
// the proxy package; here a fake session stands in for the browser round trip.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { MemoryTokenStore } from "@omnodex/mcp-proxy";
import { runAuth } from "../dist/auth-command.js";
import { commandHelp, commandOptionError } from "../dist/command-options.js";

const URL_A = "https://mcp.example.test/mcp";

function config(servers) {
  return async () => ({ version: 1, upstream_servers: servers });
}
const remote = (name, extra = {}) => ({ name, transport: "http", url: URL_A, ...extra });

function setup({ servers = [remote("plane")], signIn } = {}) {
  const out = [];
  const err = [];
  const opened = [];
  const store = new MemoryTokenStore();
  const deps = {
    io: { stdinIsTTY: true, stdoutIsTTY: true, ask: async () => "", log: (l) => out.push(l), error: (l) => err.push(l) },
    store,
    loadConfig: config(servers),
    beginSignIn: signIn ?? (async () => ({ authorizationUrl: "https://auth.example.test/authorize?x=1", completed: Promise.resolve(), cancel() {} })),
    openBrowser: (u) => opened.push(u),
    now: () => 1_000_000,
  };
  return { deps, out, err, opened, store };
}

test("usage errors", async () => {
  const t = setup();
  assert.equal(await runAuth([], t.deps), 1);
  assert.equal(await runAuth(["login"], t.deps), 1);
  assert.match(t.err[0], /usage: omnodex auth/);
});

test("status: not signed in, then signed in with expiry, never showing tokens", async () => {
  const t = setup();
  assert.equal(await runAuth(["status"], t.deps), 0);
  assert.match(t.out[0], /plane: not signed in/);
  await t.store.put("plane", {
    url: URL_A,
    tokens: { access_token: "secret-access-token", token_type: "Bearer", refresh_token: "secret-refresh-token", expires_in: 3600, obtained_at: 1_000_000 - 600_000 },
  });
  t.out.length = 0;
  await runAuth(["status"], t.deps);
  assert.match(t.out[0], /plane: signed in, access expires in 50 min, refreshes automatically/);
  assert.equal(JSON.stringify(t.out).includes("secret-"), false);
});

test("status: ignores upstreams that do not use OAuth", async () => {
  const t = setup({ servers: [remote("tokened", { bearer_token_env_var: "X_TOKEN" }), { name: "local", transport: "stdio", command: "x", args: [] }] });
  assert.equal(await runAuth(["status"], t.deps), 0);
  assert.match(t.out[0], /no remote upstream/);
});

test("login: prints the URL, opens the browser and reports success", async () => {
  const t = setup();
  assert.equal(await runAuth(["login", "plane"], t.deps), 0);
  assert.ok(t.out.includes("https://auth.example.test/authorize?x=1"));
  assert.deepEqual(t.opened, ["https://auth.example.test/authorize?x=1"]);
  assert.match(t.out.at(-1), /signed in to plane/);
});

test("login --no-browser only prints the URL", async () => {
  const t = setup();
  assert.equal(await runAuth(["login", "plane", "--no-browser"], t.deps), 0);
  assert.deepEqual(t.opened, []);
});

test("login: a sign-in that is denied exits 1", async () => {
  const t = setup({
    signIn: async () => ({ authorizationUrl: "https://a.test/x", completed: Promise.reject(new Error("authorization was not granted (access_denied)")), cancel() {} }),
  });
  assert.equal(await runAuth(["login", "plane"], t.deps), 1);
  assert.match(t.err[0], /access_denied/);
});

test("login: an unknown or non-OAuth upstream is refused and lists what is available", async () => {
  const t = setup({ servers: [remote("plane"), remote("tokened", { bearer_token_env_var: "X_TOKEN" })] });
  assert.equal(await runAuth(["login", "tokened"], t.deps), 1);
  assert.match(t.err[0], /available: plane/);
});

test("logout removes the stored sign-in", async () => {
  const t = setup();
  await t.store.put("plane", { url: URL_A, tokens: { access_token: "a", token_type: "Bearer", obtained_at: 1 } });
  assert.equal(await runAuth(["logout", "plane"], t.deps), 0);
  assert.equal(await t.store.get("plane", URL_A), undefined);
  assert.match(t.out[0], /signed out of plane/);
  t.out.length = 0;
  assert.equal(await runAuth(["logout", "plane"], t.deps), 0);
  assert.match(t.out[0], /was not signed in/);
});

test("help and option checks know the auth command", () => {
  assert.match(commandHelp("auth", ["login"]), /--no-browser/);
  assert.equal(commandOptionError("auth", ["login", "plane", "--no-browser"]), undefined);
  assert.match(commandOptionError("auth", ["login", "plane", "--bogus"]), /unknown option/);
});
