/**
 * Machine-scope first-seen tests: known-mcp-servers.json and the
 * RULE_SUPPLY_CHAIN_NEW_MCP_SERVER rule that reads it.
 *
 * Run: node --test packages/analyzer/test/machine-state.test.mjs
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile, mkdir, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  openMachineState,
  memoryMachineState,
  KNOWN_MCP_SERVERS_FILE,
} from "../dist/machine-state.js";
import { createEvaluator } from "../dist/evaluator.js";
import { RuleRegistry } from "../dist/registry.js";
import { RULE_SUPPLY_CHAIN_NEW_MCP_SERVER } from "../dist/rules/index.js";

let seq = 0;
function call(sessionId, server, at = "2026-09-21T12:00:00.000Z") {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-ms-${seq}`,
    session_id: sessionId,
    occurred_at: at,
    recorded_at: at,
    interceptor: "mcp-proxy",
    event_type: "tool.invoked",
    tool_call_id: `tc-ms-${seq}`,
    tool_name: `${server}__list`,
    mcp_server: server,
    parameters: {},
  };
}

function started(sessionId, transports) {
  return {
    schema_version: 1,
    event_id: `evt-ms-start-${sessionId}`,
    session_id: sessionId,
    occurred_at: "2026-09-21T11:59:00.000Z",
    recorded_at: "2026-09-21T11:59:00.000Z",
    interceptor: "mcp-proxy",
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: transports.map((t) => t.name),
    mcp_server_transports: transports,
  };
}

const PLANE_HTTP = { name: "plane", transport: "http", host: "api.plane.example" };
const PLANE_OTHER = { name: "plane", transport: "http", host: "evil.example" };

function evaluator(machineState, host = "proxy") {
  return createEvaluator({
    host,
    registry: new RuleRegistry([RULE_SUPPLY_CHAIN_NEW_MCP_SERVER]),
    newEventId: () => `risk-${++seq}`,
    machineState,
  });
}

describe("memoryMachineState", () => {
  it("reports new, then known, then changed when the transport moves", () => {
    const state = memoryMachineState();
    assert.equal(state.noteMcpServer("plane", PLANE_HTTP, "t1"), "new");
    assert.equal(state.noteMcpServer("plane", PLANE_HTTP, "t2"), "known");
    assert.equal(state.noteMcpServer("plane", undefined, "t3"), "known");
    assert.equal(state.noteMcpServer("plane", PLANE_OTHER, "t4"), "changed");
    assert.equal(state.noteMcpServer("plane", PLANE_OTHER, "t5"), "known");
  });

  it("learns a transport for a name first seen without one, without firing", () => {
    const state = memoryMachineState();
    assert.equal(state.noteMcpServer("plane", undefined, "t1"), "new");
    assert.equal(state.noteMcpServer("plane", PLANE_HTTP, "t2"), "known");
    assert.equal(state.noteMcpServer("plane", PLANE_OTHER, "t3"), "changed");
  });
});

describe("openMachineState", () => {
  let home;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-machine-state-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("persists across instances, as across proxy restarts", async () => {
    const first = openMachineState(home, { seedRoots: [] });
    assert.equal(first.noteMcpServer("plane", PLANE_HTTP, "2026-09-21T12:00:00.000Z"), "new");
    const second = openMachineState(home, { seedRoots: [] });
    assert.equal(second.noteMcpServer("plane", PLANE_HTTP, "2026-09-21T13:00:00.000Z"), "known");
    const file = JSON.parse(await readFile(path.join(home, KNOWN_MCP_SERVERS_FILE), "utf8"));
    assert.equal(file.version, 1);
    assert.deepEqual(file.servers.plane, {
      first_seen: "2026-09-21T12:00:00.000Z",
      transport: "http",
      host: "api.plane.example",
    });
  });

  it("merges with entries another process wrote meanwhile", async () => {
    const a = openMachineState(home, { seedRoots: [] });
    const b = openMachineState(home, { seedRoots: [] });
    a.noteMcpServer("plane", undefined, "t1");
    b.noteMcpServer("github", undefined, "t2");
    const file = JSON.parse(await readFile(path.join(home, KNOWN_MCP_SERVERS_FILE), "utf8"));
    assert.deepEqual(Object.keys(file.servers).sort(), ["github", "plane"]);
  });

  it("seeds from the event logs on first use, so servers already in use are known", async () => {
    const root = path.join(home, "event-log");
    await mkdir(path.join(root, "sessions"), { recursive: true });
    const lines = [started("sess-old", [PLANE_HTTP]), call("sess-old", "plane", "2026-09-01T09:00:00.000Z"),
      call("sess-old", "builtin")];
    await writeFile(path.join(root, "sessions", "sess-old.jsonl"), lines.map((e) => JSON.stringify(e)).join("\n") + "\n");

    const state = openMachineState(home, { seedRoots: [root] });

    assert.equal(state.noteMcpServer("plane", PLANE_HTTP, "t"), "known");
    assert.equal(state.noteMcpServer("builtin", undefined, "t"), "new", "builtin is never seeded");
    const file = JSON.parse(await readFile(path.join(home, KNOWN_MCP_SERVERS_FILE), "utf8"));
    assert.equal(file.servers.plane.first_seen, "2026-09-01T09:00:00.000Z");
  });

  it("does not reseed once the file exists", async () => {
    openMachineState(home, { seedRoots: [] });
    const root = path.join(home, "event-log");
    await mkdir(path.join(root, "sessions"), { recursive: true });
    await writeFile(path.join(root, "sessions", "s.jsonl"), JSON.stringify(call("s", "plane")) + "\n");
    assert.equal(openMachineState(home, { seedRoots: [root] }).noteMcpServer("plane", undefined, "t"), "new");
  });
});

describe("RULE_SUPPLY_CHAIN_NEW_MCP_SERVER with machine scope", () => {
  it("does not re-fire for a known server in a new session, as after a proxy restart", () => {
    const state = memoryMachineState();
    const first = evaluator(state);
    first.evaluate(started("sess-1", [PLANE_HTTP]));
    assert.equal(first.evaluate(call("sess-1", "plane")).length, 1);

    const restarted = evaluator(state);
    restarted.evaluate(started("sess-2", [PLANE_HTTP]));
    assert.deepEqual(restarted.evaluate(call("sess-2", "plane")), []);
  });

  it("fires once for a new server and once when its target changes", () => {
    const state = memoryMachineState();
    const ev = evaluator(state);
    ev.evaluate(started("sess-1", [PLANE_HTTP]));
    const [firstUse] = ev.evaluate(call("sess-1", "plane"));
    assert.match(firstUse.description, /first use on this machine/);
    assert.deepEqual(ev.evaluate(call("sess-1", "plane")), []);

    ev.evaluate(started("sess-2", [PLANE_OTHER]));
    const [moved] = ev.evaluate(call("sess-2", "plane"));
    assert.match(moved.description, /now reached over http at evil\.example/);
    assert.deepEqual(ev.evaluate(call("sess-2", "plane")), []);
  });

  it("falls back to session scope without a store", () => {
    const ev = evaluator(undefined);
    const [finding] = ev.evaluate(call("sess-1", "plane"));
    assert.match(finding.description, /first use in this session/);
    assert.equal(ev.evaluate(call("sess-2", "plane")).length, 1);
  });

  it("is not run by the hook host", () => {
    assert.equal(evaluator(memoryMachineState(), "hook").rules.length, 0);
  });
});
