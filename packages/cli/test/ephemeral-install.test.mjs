// `omnodex install --ephemeral`: a disposable host is set up from environment
// variables with no prompt, nothing secret is written, and a host with
// missing settings is left untouched.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs, existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { DEFAULT_EPHEMERAL_TARGETS, EPHEMERAL_SHIMS, installEphemeral, isEphemeralTarget } from "../dist/ephemeral-install.js";
import { bytesToBase64, generateStreamKeyPair } from "../../sync-encryptor/dist/hpke-event.js";

async function host(t, extraEnv = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-ephemeral-"));
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const pair = await generateStreamKeyPair();
  const sealedHook = path.join(root, "omnodex-sealed-hook.js");
  await fs.writeFile(sealedHook, "// sealed hook\n");
  const home = path.join(root, "home");
  const installed = [];
  const logs = [];
  const options = (over = {}) => ({
    home,
    env: {
      OMNODEX_INGEST_PUBLIC_KEY: bytesToBase64(pair.publicKey),
      OMNODEX_INGEST_SOURCE_ID: "src_0123456789ab",
      ...extraEnv,
    },
    targets: ["claude-code", "codex"],
    sealedHook,
    installTarget: async (target) => void installed.push(target),
    log: (m) => logs.push(m),
    ...over,
  });
  return { root, home, pair, installed, logs, options };
}

test("MUST_FIRE: installs each agent through the launcher with the sealed hook as its shim", async (t) => {
  const h = await host(t);
  const result = await installEphemeral(h.options());
  assert.deepEqual(result, { ok: true });
  assert.deepEqual(h.installed, ["claude-code", "codex"]);
  const config = JSON.parse(await fs.readFile(path.join(h.home, "omnodex-config.json"), "utf8"));
  assert.equal(config.shim_paths["claude-code"], path.join(h.home, "sealed", "claude-hook-shim.js"));
  assert.equal(config.shim_paths.codex, path.join(h.home, "sealed", "codex-hook-shim.js"));
  assert.equal(await fs.readFile(config.shim_paths["claude-code"], "utf8"), "// sealed hook\n");
  assert.ok(existsSync(path.join(h.home, "ephemeral-host")));
});

test("the settings written are public values only: the token never reaches the disk", async (t) => {
  const token = "oxi_" + "E".repeat(43);
  const h = await host(t, { OMNODEX_INGEST_TOKEN: token, OMNODEX_INGEST_API_BASE: "https://api.example.com" });
  assert.deepEqual(await installEphemeral(h.options()), { ok: true });
  const settings = JSON.parse(await fs.readFile(path.join(h.home, "ingest.json"), "utf8"));
  assert.equal(settings.source_id, "src_0123456789ab");
  assert.equal(settings.key_id, h.pair.keyId);
  assert.equal(settings.api_base, "https://api.example.com");
  assert.equal(settings.ingest_token, undefined);
  for (const f of await fs.readdir(h.home, { recursive: true })) {
    const p = path.join(h.home, f);
    if ((await fs.stat(p)).isFile()) assert.ok(!(await fs.readFile(p, "utf8")).includes(token), `${f} holds the token`);
  }
});

test("other config fields and other shim paths are kept", async (t) => {
  const h = await host(t);
  await fs.mkdir(h.home, { recursive: true });
  await fs.writeFile(path.join(h.home, "omnodex-config.json"), JSON.stringify({ keep: 1, shim_paths: { cursor: "/x/cursor.js" } }));
  await installEphemeral(h.options());
  const config = JSON.parse(await fs.readFile(path.join(h.home, "omnodex-config.json"), "utf8"));
  assert.equal(config.keep, 1);
  assert.equal(config.shim_paths.cursor, "/x/cursor.js");
  assert.ok(config.shim_paths.codex);
});

test("MUST_NOT_FIRE: missing or invalid settings change nothing and say what to set", async (t) => {
  const h = await host(t);
  for (const env of [{}, { OMNODEX_INGEST_PUBLIC_KEY: "AAAA", OMNODEX_INGEST_SOURCE_ID: "src_0123456789ab" }]) {
    const result = await installEphemeral(h.options({ env }));
    assert.equal(result.ok, false);
    assert.match(result.reason, /OMNODEX_INGEST_PUBLIC_KEY/);
  }
  assert.equal(existsSync(h.home), false);
  assert.deepEqual(h.installed, []);
});

test("MUST_NOT_FIRE: a missing sealed hook file changes nothing", async (t) => {
  const h = await host(t);
  const result = await installEphemeral(h.options({ sealedHook: path.join(h.root, "nope.js") }));
  assert.equal(result.ok, false);
  assert.match(result.reason, /sealed hook/);
  assert.equal(existsSync(path.join(h.home, "ephemeral-host")), false);
});

test("a rerun is safe: same files, hooks installed again", async (t) => {
  const h = await host(t);
  await installEphemeral(h.options());
  await installEphemeral(h.options());
  assert.deepEqual(h.installed, ["claude-code", "codex", "claude-code", "codex"]);
});

test("the supported agents and defaults", () => {
  assert.deepEqual(Object.keys(EPHEMERAL_SHIMS).sort(), ["antigravity", "claude-code", "codex", "copilot", "cursor"]);
  assert.deepEqual([...DEFAULT_EPHEMERAL_TARGETS], ["claude-code", "codex"]);
  assert.equal(isEphemeralTarget("opencode"), false);
  assert.equal(isEphemeralTarget("toString"), false);
});
