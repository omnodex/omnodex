// Each proxy session supplies its own project to capture and enforcement.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { runProxyServer } from "../dist/proxy-server.js";
import { startProxyHttpServer } from "../dist/http-server.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";
import { createProxyGuardrails } from "../dist/guardrails.js";
import { installModule } from "../../analyzer/test/helpers/make-module.mjs";
import { Projector, InMemoryReadModelStore } from "../../projection/dist/index.js";
import { serializeReadModel } from "../../sync-encryptor/dist/serializer.js";
import { StreamingTransport } from "../../sync-encryptor/dist/streaming-transport.js";

const mock = fileURLToPath(new URL("./helpers/mock-mcp-server.mjs", import.meta.url));
for (const transportKind of ["memory", "http"]) {
  for (const redact of [false, true]) {
    test(`${transportKind}: project enforcement stays per session with redaction ${redact}`, async (t) => {
      const root = await mkdtemp(path.join(os.tmpdir(), "omnodex-project-context-"));
      t.after(() => rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
      const home = path.join(root, ".omnodex");
      const inside = path.join(root, "case", "repo");
      const outside = path.join(root, "case", "other-repo");
      await mkdir(home, { recursive: true });
      await mkdir(inside, { recursive: true });
      await mkdir(outside, { recursive: true });
      await writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement: {
        mode: "guardrails", projects: { [inside]: { rules: { RULE_SENSITIVE_PATH_READ: "deny" } } },
      } }));
      const module = installModule(home);
      const prior = Object.fromEntries(Object.keys(module.env).map((k) => [k, process.env[k]]));
      Object.assign(process.env, module.env);
      t.after(() => { for (const [k, v] of Object.entries(prior)) if (v === undefined) delete process.env[k]; else process.env[k] = v; });
      const config = ProxyConfigSchema.parse({ version: 1, redact_parameters: redact, upstream_servers: [{
        name: "mock", transport: "stdio", command: process.execPath, args: [mock],
      }] });
      const pool = new UpstreamClientPool();
      await pool.connect(config);
      const events = [];
      const decided = [];
      const realGuardrails = createProxyGuardrails({ home });
      // Deliberately shared: only the call's own context may choose a project.
      const guardrails = { ...realGuardrails, async decide(full, logged) {
        decided.push({ full, logged });
        return realGuardrails.decide(full, logged);
      } };
      const sessions = [];
      async function connect(projectPath, sessionId) {
        const client = new Client({ name: "codex-mcp-client", version: "1.0.0" }, {});
        const opts = { pool, config, emit: (event) => events.push(event), projectPath, guardrails };
        if (transportKind === "http") {
          const server = await startProxyHttpServer({ ...opts, host: "127.0.0.1", port: 0 });
          const transport = new StreamableHTTPClientTransport(new URL(server.url));
          sessions.push({ close: async () => { await client.close(); await server.close(); } });
          await client.connect(transport);
        } else {
          const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
          const done = runProxyServer({ ...opts, sessionId, transport: serverTransport });
          sessions.push({ close: async () => { await client.close(); await done; } });
          await client.connect(clientTransport);
        }
        return client;
      }
      try {
        const a = await connect(inside, "case-inside");
        const b = await connect(outside, "case-outside");
        const call = (client, file) => client.callTool({ name: "mock__read_file", arguments: { file_path: file, cwd: "/spoofed/project" } });
        const [blocked, allowed] = await Promise.all([call(a, "/etc/shadow"), call(b, "/etc/shadow")]);
        assert.equal(blocked.isError, true, "matching project must hold the call");
        assert.ok(!allowed.isError, "the other session must not inherit that project");
        assert.equal((await call(a, "/etc/shadow")).isError, true);
        assert.ok(!(await call(a, "/home/case/repo/README.md")).isError);
        assert.ok(decided.some(({ full }) => full.cwd === inside));
        assert.ok(decided.some(({ full }) => full.cwd === outside));
        for (const { full, logged } of decided) {
          assert.equal(full.cwd, logged.cwd, "redaction keeps the session context");
          if (redact) assert.equal(logged.parameters.file_path, "[REDACTED]");
        }
        for (const event of events.filter((e) => e.event_type === "tool.invoked")) {
          assert.ok([inside, outside].includes(event.cwd));
          const session = events.find((e) => e.event_type === "session.started" && e.session_id === event.session_id);
          assert.equal(event.cwd, session.project_path);
        }
        const store = new InMemoryReadModelStore();
        const projector = new Projector(store);
        for (const event of events) await projector.apply(event);
        const payload = await serializeReadModel(store);
        assert.ok(payload.sessions.some((s) => s.project_path === inside));
        assert.ok(Object.values(payload.tool_calls).flat().every((row) => !Object.hasOwn(row, "cwd")), "sync tool rows retain their existing allowlist");
        // Live events carry cwd inside the authenticated ciphertext only.
        const key = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const calls = [];
        const previousFetch = globalThis.fetch;
        const live = new StreamingTransport({ apiBase: "http://127.0.0.1:1", apiToken: "case-token", keyId: "case-key", streamingKey: key });
        try {
          globalThis.fetch = async (url, init) => { calls.push({ url, init }); return new Response(JSON.stringify({ live: true }), { status: 200 }); };
          const event = events.find((e) => e.event_type === "tool.invoked" && e.cwd === inside);
          await live.push(event);
          await live.flush();
          assert.equal(calls.length, 1);
          const request = JSON.stringify(calls[0]);
          assert.ok(!request.includes(inside) && !request.includes('"cwd"'));
          const [wire] = JSON.parse(calls[0].init.body).events;
          assert.deepEqual(Object.keys(wire).sort(), ["ct", "event_id", "iv", "key_id", "ts"]);
          const plaintext = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(wire.iv, "base64") }, key, Buffer.from(wire.ct, "base64"));
          assert.equal(JSON.parse(new TextDecoder().decode(plaintext)).cwd, inside);
        } finally {
          await live.stop();
          globalThis.fetch = previousFetch;
        }
      } finally {
        for (const session of sessions) await session.close();
        await pool.close();
      }
    });
  }
}
