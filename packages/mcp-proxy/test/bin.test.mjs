// End-to-end tests for the omnodex-mcp-proxy entrypoint.
// Spawns the built bin as an agent host would, makes one tool call over
// stdio, closes stdin, and checks the process exits and the session is
// recorded as ended after the call.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, "..", "dist", "bin", "omnodex-mcp-proxy.js");
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

/** Sends newline-delimited JSON-RPC and resolves responses by id. */
function rpcClient(child) {
  let buf = "";
  const pending = new Map();
  child.stdout.on("data", (chunk) => {
    buf += chunk.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      if (msg.id != null && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });
  let nextId = 1;
  return {
    request(method, params) {
      const id = nextId++;
      return new Promise((resolve) => {
        pending.set(id, resolve);
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });
    },
    notify(method) {
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");
    },
  };
}

test("closing stdin ends the session after the calls and exits the process", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-proxy-bin-"));
  let child;
  try {
    const configPath = path.join(home, "omnodex-proxy.json");
    await writeFile(
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
      })
    );

    child = spawn(process.execPath, [BIN, "--config", configPath], {
      env: { ...process.env, OMNODEX_HOME: home },
      stdio: ["pipe", "pipe", "ignore"],
    });
    const exited = new Promise((resolve) => child.on("exit", (code) => resolve(code)));
    const rpc = rpcClient(child);

    await rpc.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "bin-test", version: "0.0.0" },
    });
    rpc.notify("notifications/initialized");
    const call = await rpc.request("tools/call", { name: "filesystem__read_file", arguments: {} });
    assert.equal(call.result.isError, false);

    child.stdin.end();
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("proxy did not exit after stdin closed")), 15000).unref()
    );
    assert.equal(await Promise.race([exited, timeout]), 0);

    const sessionsDir = path.join(home, "event-log", "sessions");
    const [file] = await readdir(sessionsDir);
    const events = (await readFile(path.join(sessionsDir, file), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const types = events.map((e) => e.event_type);

    assert.equal(types.filter((t) => t === "session.ended").length, 1);
    assert.equal(types.at(-1), "session.ended");
    assert.ok(types.indexOf("tool.completed") < types.indexOf("session.ended"));
  } finally {
    // Kill a proxy that failed to exit (and its upstream) so the runner does not hang.
    if (child && child.exitCode === null) child.kill("SIGKILL");
    await rm(home, { recursive: true, force: true });
  }
});

test("the proxy answers the host while its upstreams are failing or still starting", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-proxy-bin-"));
  let child;
  try {
    const configPath = path.join(home, "omnodex-proxy.json");
    const mock = (name, env) => ({
      name,
      transport: "stdio",
      command: process.execPath,
      args: [MOCK_SERVER],
      env: { MOCK_TOOLS: JSON.stringify(["ping"]), ...env },
    });
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        upstream_servers: [
          mock("broken", { MOCK_FAIL_STARTUP: "1" }),
          mock("slow", { MOCK_STARTUP_DELAY_MS: "60000" }),
        ],
        upstream_connection: { discovery_window_ms: 300 },
      })
    );

    child = spawn(process.execPath, [BIN, "--config", configPath], {
      env: { ...process.env, OMNODEX_HOME: home },
      stdio: ["pipe", "pipe", "ignore"],
    });
    const exited = new Promise((resolve) => child.on("exit", (code) => resolve(code)));
    const rpc = rpcClient(child);

    const init = await rpc.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "bin-test", version: "0.0.0" },
    });
    assert.deepEqual(init.result.capabilities.tools, { listChanged: true });
    rpc.notify("notifications/initialized");

    const list = await rpc.request("tools/list", {});
    assert.deepEqual(
      list.result.tools.map((t) => t.name),
      ["omnodex_status", "omnodex_connect", "omnodex_connection_status"]
    );
    // The built-ins answer while "broken" fails and "slow" keeps starting.
    let states = [];
    const deadline = Date.now() + 15000;
    while (states[0] !== "broken:failed" && Date.now() < deadline) {
      const status = await rpc.request("tools/call", { name: "omnodex_status", arguments: {} });
      states = JSON.parse(status.result.content[0].text).upstream_servers.map(
        (u) => `${u.name}:${u.state}`
      );
      if (states[0] !== "broken:failed") await new Promise((r) => setTimeout(r, 100));
    }
    assert.deepEqual(states, ["broken:failed", "slow:connecting"]);

    child.stdin.end();
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("proxy did not exit after stdin closed")), 15000).unref()
    );
    assert.equal(await Promise.race([exited, timeout]), 0);
  } finally {
    if (child && child.exitCode === null) child.kill("SIGKILL");
    await rm(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Background sync child mode
// ---------------------------------------------------------------------------

test("with OMNODEX_AUTO_SYNC_CHILD=1 the bin syncs and exits instead of speaking MCP", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-bin-autosync-"));
  try {
    // No stream credentials, so runAutoSync bails at its first guard. What is
    // under test is the branch itself: a running proxy respawns this binary
    // to do the sync, and that child must never start an MCP server or sit
    // waiting on a stdin nobody is writing to.
    const child = spawn(process.execPath, [BIN], {
      env: {
        ...process.env,
        OMNODEX_HOME: home,
        OMNODEX_AUTO_SYNC_CHILD: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c.toString()));
    const exited = new Promise((resolve) => child.on("exit", (code) => resolve(code)));
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("sync child did not exit")), 15000).unref()
    );

    assert.equal(await Promise.race([exited, timeout]), 0);
    assert.equal(stdout, "", "the sync child must not write MCP traffic to stdout");

    // An MCP session would have written session.started; this child did not
    // open one, so there is no event log at all.
    await assert.rejects(readdir(path.join(home, "event-log", "sessions")));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
