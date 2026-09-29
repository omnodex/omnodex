// Tests for recording which MCP client the proxy served.
// session.started waits for the initialize handshake so it can record the
// client's own name and version, and the runtime they identify. A launcher
// that knows its platform (OMNODEX_PLATFORM) takes precedence, and every
// later event carries the platform too.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { runProxyServer } from "../dist/proxy-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";
import { asPlatform, platformForClient } from "../dist/core/events.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

async function runSession({ clientName, clientVersion = "1.2.3", platformEnv }) {
  const config = ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: { MOCK_TOOLS: JSON.stringify(["get_info"]), MOCK_RESULT_TEXT: "ok" },
      },
    ],
  });
  const previous = process.env.OMNODEX_PLATFORM;
  if (platformEnv === undefined) delete process.env.OMNODEX_PLATFORM;
  else process.env.OMNODEX_PLATFORM = platformEnv;

  const pool = new UpstreamClientPool();
  await pool.connect(config);
  const events = [];
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    const serverDone = runProxyServer({
      pool,
      config,
      emit: (ev) => events.push(ev),
      sessionId: "sess-client-test",
      projectPath: "/home/case/project",
      transport: serverTransport,
    });
    const client = new Client({ name: clientName, version: clientVersion }, {});
    await client.connect(clientTransport);
    await client.callTool({ name: "filesystem__get_info", arguments: {} });
    await client.close();
    await serverDone;
    return events;
  } finally {
    await pool.close();
    if (previous === undefined) delete process.env.OMNODEX_PLATFORM;
    else process.env.OMNODEX_PLATFORM = previous;
  }
}

test("session.started records the client and the runtime its name identifies", async () => {
  const events = await runSession({ clientName: "claude-code" });
  assert.equal(events[0].event_type, "session.started", "written before any other event");
  assert.deepEqual(events[0].mcp_client, { name: "claude-code", version: "1.2.3" });
  assert.equal(events[0].platform, "claude-code");
  for (const e of events) assert.equal(e.platform, "claude-code", `${e.event_type} carries the platform`);
});

test("an unrecognised client is recorded by name, with no platform", async () => {
  const events = await runSession({ clientName: "Some Other Client" });
  assert.deepEqual(events[0].mcp_client, { name: "Some Other Client", version: "1.2.3" });
  for (const e of events) assert.equal(e.platform, undefined);
});

test("a platform the launcher declares wins over the client's name", async () => {
  const events = await runSession({ clientName: "claude-ai", platformEnv: "cowork" });
  assert.equal(events[0].platform, "cowork");
  assert.equal(events[0].mcp_client.name, "claude-ai");
  for (const e of events) assert.equal(e.platform, "cowork");
});

test("a launcher value that names no platform is ignored", async () => {
  const events = await runSession({ clientName: "codex-mcp-client", platformEnv: "not-a-platform" });
  assert.equal(events[0].platform, "codex");
});

test("platform helpers accept only known values", () => {
  assert.equal(asPlatform(" Cowork "), "cowork");
  assert.equal(asPlatform("desktop"), undefined);
  assert.equal(asPlatform(undefined), undefined);
  assert.equal(platformForClient("Claude-Code"), "claude-code");
  assert.equal(platformForClient("claude-ai"), undefined, "the desktop app is ambiguous; its launcher says which");
});
