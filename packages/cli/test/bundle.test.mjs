/**
 * Tests for the publishable npm package built by bundle.config.mjs.
 *
 * Builds the bundle into a temp dir once, then checks that the packed
 * package ships everything installed hooks and agent plugins look for.
 *
 * Tests:
 *   1. Every shim the launchers look for is in bin/
 *   2. package.json bins point at files that exist, including omnodex-mcp-proxy
 *   3. npm pack includes every bin file
 *   4. The bundled Claude Code shim writes an event
 *   5. The bundled MCP proxy starts and lists upstream tools
 */

import { test, before, after } from "node:test";
import * as assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

import { LAUNCHER_PLATFORMS, shimFilename } from "../dist/launcher-template.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const PKG_DIR = path.join(__dirname, "..");
const MOCK_SERVER = path.join(PKG_DIR, "..", "mcp-proxy", "test", "helpers", "mock-mcp-server.mjs");

let tmp;
let out;

before(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-bundle-"));
  out = path.join(tmp, "package");
  const result = spawnSync(process.execPath, [path.join(PKG_DIR, "bundle.config.mjs"), "--out", out], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
});

after(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

test("bundle: bin/ contains every shim the launchers look for", async () => {
  for (const platform of LAUNCHER_PLATFORMS) {
    await fs.access(path.join(out, "bin", shimFilename(platform)));
  }
});

test("bundle: package.json bins exist, including omnodex-mcp-proxy", async () => {
  const pkg = JSON.parse(await fs.readFile(path.join(out, "package.json"), "utf8"));
  assert.equal(pkg.name, "omnodex");
  assert.ok(pkg.bin["omnodex-mcp-proxy"], "omnodex-mcp-proxy bin is declared");
  for (const file of Object.values(pkg.bin)) {
    await fs.access(path.join(out, file));
  }
});

test("bundle: npm pack includes every bin file", async () => {
  const result = spawnSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: out,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  const packed = new Set((Array.isArray(report) ? report[0] : Object.values(report)[0]).files.map((f) => f.path));
  for (const file of await fs.readdir(path.join(out, "bin"))) {
    assert.ok(packed.has(`bin/${file}`), `bin/${file} is packed`);
  }
});

test("bundle: the bundled Claude Code shim writes an event", async () => {
  const home = path.join(tmp, "shim-home");
  const payload = {
    session_id: "bundle-test",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_use_id: "tu_bundle",
    tool_input: { command: "ls" },
    cwd: "/home/case/repo",
    transcript_path: "/home/case/transcript.jsonl",
  };
  const result = spawnSync(process.execPath, [path.join(out, "bin", "claude-hook-shim.js")], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    env: { ...process.env, OMNODEX_HOME: home },
  });
  assert.equal(result.status, 0, result.stderr);

  const log = await fs.readFile(path.join(home, "event-log", "sessions", "bundle-test.jsonl"), "utf8");
  const events = log.trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(events[0].event_type, "tool.invoked");
  assert.equal(events[0].tool_name, "Bash");
});

test("bundle: the bundled MCP proxy starts and lists upstream tools", async () => {
  const home = path.join(tmp, "proxy-home");
  await fs.mkdir(home, { recursive: true });
  const configPath = path.join(home, "omnodex-proxy.json");
  await fs.writeFile(
    configPath,
    JSON.stringify({
      version: 1,
      upstream_servers: [
        {
          name: "filesystem",
          transport: "stdio",
          command: process.execPath,
          args: [MOCK_SERVER],
          env: { MOCK_TOOLS: JSON.stringify(["read_file"]) },
        },
      ],
    }),
  );

  const child = spawn(process.execPath, [path.join(out, "bin", "omnodex-mcp-proxy.js"), "--config", configPath], {
    env: { ...process.env, OMNODEX_HOME: home },
    stdio: ["pipe", "pipe", "ignore"],
  });
  try {
    let buf = "";
    const responses = new Map();
    const waiters = new Map();
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString();
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (waiters.has(msg.id)) waiters.get(msg.id)(msg);
        else responses.set(msg.id, msg);
      }
    });
    const request = (id, method, params) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no response to ${method}`)), 15000);
        waiters.set(id, (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });

    await request(1, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "bundle-test", version: "0.0.0" },
    });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const list = await request(2, "tools/list", {});
    const names = list.result.tools.map((t) => t.name);
    assert.ok(names.includes("filesystem__read_file"), `upstream tool listed: ${names.join(", ")}`);
  } finally {
    child.kill("SIGKILL");
  }
});
