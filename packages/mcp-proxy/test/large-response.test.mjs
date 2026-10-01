import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { EventLog } from "@omnodex/event-log";
import { startProxyHttpServer } from "../dist/http-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const MOCK = fileURLToPath(new URL("./helpers/mock-mcp-server.mjs", import.meta.url));
const BIN = fileURLToPath(new URL("../dist/bin/omnodex-mcp-proxy.js", import.meta.url));
const BYTES = 2 * 1024 * 1024;
const expected = "x".repeat(BYTES) + ":read_file:case";

async function waitFor(check) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await delay(20);
  }
  throw new Error("large response completion was not recorded within 15 seconds");
}

for (const protocol of ["stdio", "http"]) {
  for (const structured of [false, true]) {
    test(`${protocol} forwards 2 MB ${structured ? "structured and text" : "text"} content and keeps completion logs bounded`, { timeout: 30000 }, async () => {
      const home = await mkdtemp(join(tmpdir(), "omnodex-large-response-"));
      const root = join(home, "event-log");
      const config = ProxyConfigSchema.parse({
        version: 1,
        upstream_servers: [{
          name: "mock", transport: "stdio", command: process.execPath, args: [MOCK],
          env: { MOCK_TOOLS: JSON.stringify(["read_file"]), MOCK_RESULT_BYTES: String(BYTES), MOCK_STRUCTURED: structured ? "1" : "0" },
        }],
      });
      const client = new Client({ name: "large-response-test", version: "0.0.0" }, {});
      let pool, server, log, transport;
      const writes = [];
      try {
        if (protocol === "stdio") {
          const configPath = join(home, "proxy.json");
          await writeFile(configPath, JSON.stringify(config));
          const env = Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== undefined));
          delete env.OMNODEX_AUTO_SYNC_CHILD;
          transport = new StdioClientTransport({ command: process.execPath, args: [BIN, "--config", configPath], env: { ...env, OMNODEX_HOME: home }, stderr: "ignore" });
        } else {
          log = new EventLog({ root });
          await log.init();
          pool = new UpstreamClientPool();
          await pool.connect(config);
          server = await startProxyHttpServer({ host: "127.0.0.1", port: 0, pool, config, projectPath: "/home/case/project", emit: (event) => { const write = log.append(event); writes.push(write); return write; } });
          transport = new StreamableHTTPClientTransport(new URL(server.url));
        }
        await client.connect(transport);
        await waitFor(async () => (await client.listTools()).tools.some((tool) => tool.name === "mock__read_file"));
        const result = await client.callTool({ name: "mock__read_file", arguments: { input: "case" } });
        assert.deepEqual(result.content, [{ type: "text", text: expected }]);
        if (structured) assert.deepEqual(result.structuredContent, { content: expected });
        else assert.equal(result.structuredContent, undefined);

        const completed = await waitFor(async () => {
          const files = await readdir(join(root, "sessions")).catch(() => []);
          for (const file of files) {
            const raw = await readFile(join(root, "sessions", file), "utf8");
            for (const line of raw.trim().split("\n")) {
              let event;
              try { event = JSON.parse(line); } catch { continue; }
              if (event.event_type === "tool.completed") return event;
            }
          }
          return undefined;
        });
        assert.equal(completed.status, "success");
        // The current metric serializes content only, excluding structuredContent.
        assert.equal(completed.response_bytes, Buffer.byteLength(JSON.stringify(result.content)));
        assert.ok(Buffer.byteLength(JSON.stringify(completed)) < 1024, "completion records metadata, not a truncated or full response body");
        assert.ok(!JSON.stringify(completed).includes("x".repeat(100)));
        const files = await readdir(join(root, "sessions"));
        for (const file of files) assert.ok(Buffer.byteLength(await readFile(join(root, "sessions", file))) < 16384, "entire session log stays bounded");
      } finally {
        if (protocol === "http" && transport) await transport.terminateSession().catch(() => undefined);
        await client.close();
        if (server) await server.close();
        if (pool) await pool.close();
        await Promise.all(writes);
        if (log) await log.close();
        await rm(home, { recursive: true, force: true });
      }
    });
  }
}
