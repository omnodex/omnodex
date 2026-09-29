import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../../event-log/dist/index.js";
import { SqliteReadModelStore } from "../../projection/dist/index.js";
import { serializeReadModel } from "../dist/index.js";
import { syncReadModel } from "../dist/sync-runner.js";

/**
 * A sync rebuilds the read model from the log before encrypting it. A
 * rebuild leaves a routed call's hook and proxy rows unpaired, so unless the
 * sync also pairs them, the hosted dashboard counts every routed call, and
 * any finding both hosts raised on it, twice.
 */

const HOOK_AT = "2026-09-29T12:00:00.000Z";
const PROXY_AT = "2026-09-29T12:00:01.400Z";
const PARAMS = { path: "/home/case/repo/README.md", head: 3 };

function event(sessionId, interceptor, at, n, body) {
  return {
    schema_version: 1,
    event_id: `${sessionId}-e${n}`,
    session_id: sessionId,
    occurred_at: at,
    recorded_at: at,
    interceptor,
    ...body,
  };
}

const START = (sid, interceptor) =>
  event(sid, interceptor, HOOK_AT, 0, {
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
  });

const ROUTED = [
  START("hook", "claude-code-hook"),
  START("proxy", "mcp-proxy"),
  event("hook", "claude-code-hook", HOOK_AT, 1, {
    event_type: "tool.invoked",
    tool_call_id: "toolu_hook_1",
    tool_name: "mcp__omnodex__filesystem__read_text_file",
    mcp_server: "omnodex",
    parameters: PARAMS,
  }),
  event("proxy", "mcp-proxy", PROXY_AT, 1, {
    event_type: "tool.invoked",
    tool_call_id: "proxy-call-1",
    tool_name: "filesystem__read_text_file",
    mcp_server: "filesystem",
    parameters: PARAMS,
  }),
  event("hook", "analyzer", HOOK_AT, 2, {
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "read a sensitive path",
    related_event_id: "toolu_hook_1",
    rule_id: "rule_1",
  }),
  event("proxy", "analyzer", PROXY_AT, 2, {
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "read a sensitive path",
    related_event_id: "proxy-call-1",
    rule_id: "rule_1",
  }),
];

/** Local stand-in for the sync push endpoint. */
async function startSyncServer() {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ blob_id: "blob_case_1", received_at: new Date().toISOString(), payload_bytes: 1 }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

test("a sync pairs routed calls and their findings before it encrypts", async (t) => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-synccorr-"));
  const api = await startSyncServer();
  t.after(async () => {
    await api.close();
    await fs.rm(home, { recursive: true, force: true });
  });

  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  for (const e of ROUTED) await log.append(e);
  await log.close();

  await syncReadModel({
    home,
    apiUrl: api.url,
    apiToken: "omx_test_case",
    passphrase: "correct horse battery staple",
    customerId: "cust_case",
  });

  // The store the blob was serialized from.
  const store = new SqliteReadModelStore({ dbPath: path.join(home, "traces.db") });
  await store.init();
  try {
    const payload = await serializeReadModel(store);
    const [hookCall] = payload.tool_calls.hook;
    const [proxyCall] = payload.tool_calls.proxy;
    assert.ok(hookCall.correlation_id, "the hook's call was not paired");
    assert.equal(hookCall.correlation_id, proxyCall.correlation_id);
    assert.equal(hookCall.mcp_server, "filesystem", "the hook's call names the upstream server");
    assert.equal(payload.risk_events.hook[0].correlation_id, hookCall.correlation_id);
    assert.equal(payload.risk_events.proxy[0].correlation_id, hookCall.correlation_id);
  } finally {
    await store.close();
  }
});
