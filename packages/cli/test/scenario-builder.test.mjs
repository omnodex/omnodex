import { test } from "node:test";
import assert from "node:assert/strict";
import { buildScenarios, MIN_SCENARIO_SESSIONS } from "../../hooks-provider/dist/scenario-builder.js";
import { detectRisks, COMMUNITY_RULES } from "../../analyzer/dist/index.js";
import { InMemoryReadModelStore, Projector, runCorrelation } from "../../projection/dist/index.js";
import { riskScoreFor, roundRiskScore } from "../../shared/dist/index.js";
import { parseSpikeOptions } from "../dist/spike-options.js";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { SqliteReadModelStore } from "../../projection/dist/index.js";

for (const seed of [0, 1, 42, -1, 2147483647]) {
  test(`scenario manifest and real rule catalog: seed ${seed}`, async () => {
    const events = buildScenarios({ seed });
    const ids = [...new Set(events.map(e => e.session_id))];
    assert.equal(ids.length, MIN_SCENARIO_SESSIONS);
    assert.equal(new Set(events.map(e => e.event_id)).size, events.length);
    const store = new InMemoryReadModelStore();
    const projector = new Projector(store);
    const findings = [];
    for (const id of ids) {
      const source = events.filter(e => e.session_id === id);
      const calls = source.filter(e => e.event_type === "tool.invoked");
      const start = source[0];
      for (const e of source) {
        assert.equal(e.schema_version, 1);
        assert.ok(Number.isFinite(Date.parse(e.occurred_at)));
        assert.notEqual(e.event_type, "risk.detected");
        if (e.event_type === "tool.invoked") assert.ok(start.mcp_servers.includes(e.mcp_server));
        if (e.event_type === "tool.completed") assert.equal(calls.filter(c => c.tool_call_id === e.tool_call_id).length, 1);
        if (e.event_type === "file.read" || e.event_type === "file.written") assert.ok(calls.some(c => (c.parameters.file_path ?? c.parameters.path) === e.path));
      }
      let n = 0;
      const risks = detectRisks(source, () => `${id}_risk_${n++}`).newEvents;
      findings.push(...risks);
      for (const e of [...source, ...risks]) await projector.apply(e);
      const row = await store.getSession(id);
      assert.equal(row.tool_call_count, calls.length);
      assert.equal(row.file_read_count, source.filter(e => e.event_type === "file.read").length);
      assert.equal(row.file_write_count, source.filter(e => e.event_type === "file.written").length);
      assert.equal(row.risk_score, roundRiskScore(risks.reduce((n, r) => n + riskScoreFor(r.severity), 0)));
      assert.equal((await store.listToolCalls(id)).length, calls.length);
    }
    assert.deepEqual([...new Set(findings.map(e => e.rule_id))].sort(), COMMUNITY_RULES.map(r => r.rule_id).sort());
    assert.deepEqual([...new Set(findings.map(e => e.severity))].sort(), ["CRITICAL", "HIGH", "LOW", "MEDIUM"]);
    const rows = await store.listSessions();
    assert.deepEqual([...new Set(rows.map(r => r.status))].sort(), ["completed", "errored", "in_progress", "interrupted"]);
    assert.ok(rows.some(r => r.risk_score === 0));
    assert.deepEqual([...new Set(events.map(e => e.platform))].sort(), ["antigravity", "claude-code", "codex", "cowork"]);
    assert.ok(events.filter(e => e.platform === "cowork").every(e => e.interceptor === "mcp-proxy"));
    assert.ok(events.filter(e => e.platform === "cowork" && e.event_type === "tool.invoked").every(e => e.mcp_server !== "builtin"));
    for (const type of ["permission.requested", "permission.denied", "subagent.started", "subagent.stopped", "session.renamed"]) assert.ok(events.some(e => e.event_type === type), type);
    assert.ok(events.some(e => e.event_type === "prompt.submitted" && e.prompt_id));
    assert.ok(events.some(e => e.event_type === "prompt.submitted" && !e.prompt_id));
    assert.ok(events.some(e => e.event_type === "tool.invoked" && e.agent_id));
    await runCorrelation(store);
    const tools = (await Promise.all(ids.map(id => store.listToolCalls(id)))).flat();
    assert.equal(tools.filter(t => t.correlation_id).length, 2, "hook/proxy pair");
    assert.deepEqual([...new Set(tools.map(t => t.status))].sort(), ["error", "in_progress", "success"]);
  });
}

test("stable bytes, different seeds, and append-safe identifiers", () => {
  const first = buildScenarios({ seed: 0 });
  assert.equal(JSON.stringify(first), JSON.stringify(buildScenarios({ seed: 0 })));
  assert.notEqual(JSON.stringify(first), JSON.stringify(buildScenarios({ seed: 1 })));
  const second = buildScenarios({ seed: 0, existingSessionIds: first.map(e => e.session_id) });
  const third = buildScenarios({ seed: 0, existingSessionIds: [...first, ...second].map(e => e.session_id) });
  const all = [...first, ...second, ...third];
  assert.equal(new Set(all.map(e => e.event_id)).size, all.length);
  const calls = all.filter(e => e.event_type === "tool.invoked");
  assert.equal(new Set(calls.map(e => e.tool_call_id)).size, calls.length);
});

test("strict options, seed zero and injectable random seed", () => {
  assert.equal(parseSpikeOptions(["--seed", "0"]).seed, 0);
  assert.equal(parseSpikeOptions(["--random"], () => 123).seed, 123);
  assert.equal(parseSpikeOptions(["demo", "--seed", "-1"]).name, "demo");
  for (const args of [["--seed"], ["--now"], ["--seed", "1x"], ["--seed", "1.5"], ["--random", "--seed", "1"], ["--random", "--random"], ["--sessions", "1"], ["--sessions", "1001"], ["--now", "yesterday"], ["--now", "2026-10-01"], ["../escape"], ["--unknown"], ["a", "b"]]) assert.throws(() => parseSpikeOptions(args), args.join(" "));
});

test("CLI writes reproducible session logs, replays SQLite and appends unique runs", async () => {
  const scratch = await mkdtemp(path.join(tmpdir(), "omnodex-scenarios-"));
  const cli = fileURLToPath(new URL("../dist/index.js", import.meta.url));
  const run = (home, args) => {
    const result = spawnSync(process.execPath, [cli, ...args], {
      env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: home, OMNODEX_SINGLE_ROOT: "1", OMNODEX_NO_UPDATE_CHECK: "1", OMNODEX_AUTO_SYNC: "0" },
      encoding: "utf8", timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    return result.stdout;
  };
  try {
    const a = path.join(scratch, "a"), b = path.join(scratch, "b");
    await mkdir(a); await mkdir(b);
    for (const home of [a, b]) run(home, ["spike", "case", "--seed", "42", "--now", "2026-10-18T12:00:00Z"]);
    const logs = async home => {
      const dir = path.join(home, "event-log", "sessions");
      return Promise.all((await readdir(dir)).sort().map(f => readFile(path.join(dir, f), "utf8")));
    };
    assert.deepEqual(await logs(a), await logs(b));
    run(a, ["replay"]);
    const store = new SqliteReadModelStore({ dbPath: path.join(a, "traces.db") });
    await store.init();
    try { assert.equal((await store.listSessions()).length, MIN_SCENARIO_SESSIONS); }
    finally { await store.close(); }
    run(a, ["spike", "case", "--seed", "42", "--now", "2026-10-18T12:00:00Z"]);
    const appended = (await logs(a)).flatMap(raw => raw.trim().split("\n").map(JSON.parse));
    assert.equal(new Set(appended.map(e => e.event_id)).size, appended.length);
    assert.equal((await logs(a)).length, MIN_SCENARIO_SESSIONS * 2);
    const one = run(b, ["spike", "--random"]), two = run(b, ["spike", "--random"]);
    assert.notEqual(one.match(/seed: (\d+)/)[1], two.match(/seed: (\d+)/)[1]);
  } finally { await rm(scratch, { recursive: true, force: true }); }
});
