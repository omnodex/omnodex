// End-to-end test for the omnodex-mcp-proxy entrypoint.
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
