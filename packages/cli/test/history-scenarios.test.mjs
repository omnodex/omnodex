import { test } from "node:test";
import assert from "node:assert/strict";
import { buildHistoryScenarios, HISTORY_DAYS, HISTORY_EXPECTATIONS } from "../../hooks-provider/dist/history-scenarios.js";
import { detectRisks, normalizeAction } from "../../analyzer/dist/index.js";
import { CAPTURE_CONTROL_SESSION_ID } from "../../shared/dist/index.js";
import { SqliteReadModelStore } from "../../projection/dist/index.js";
import { parseSpikeOptions } from "../dist/spike-options.js";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const NOW = "2026-10-18T12:00:00.000Z";
const DAY = 86_400_000;
const dayOf = (iso) => HISTORY_DAYS - Math.ceil((Date.parse(NOW) - Date.parse(iso)) / DAY);

/** Sessions of both machines in time order, with what each used. */
function history(seed = 1) {
  const sessions = [];
  const markers = [];
  for (const machine of ["a", "b"]) {
    const events = buildHistoryScenarios({ machine, seed, now: NOW });
    for (const e of events) if (e.event_type === "monitoring.changed") markers.push({ machine, at: Date.parse(e.occurred_at), event: e });
    const byId = Map.groupBy(events.filter((e) => e.session_id !== CAPTURE_CONTROL_SESSION_ID), (e) => e.session_id);
    for (const [id, source] of byId) {
      const start = source.find((e) => e.event_type === "session.started");
      const calls = source.filter((e) => e.event_type === "tool.invoked");
      const destinations = new Set(calls.flatMap((c) => normalizeAction(c).destinations.map((d) => d.host)));
      sessions.push({
        id, machine, source, at: Date.parse(start.occurred_at), day: dayOf(start.occurred_at), project: start.project_remote, platform: start.platform,
        items: { destination: destinations, server: new Set(calls.map((c) => c.mcp_server).filter((s) => s !== "builtin")), tool: new Set(calls.map((c) => c.tool_name)) },
      });
    }
  }
  return { sessions: sessions.sort((x, y) => x.at - y.at), markers };
}

for (const seed of [1, 7, 2147483647]) {
  test(`every documented expectation holds in the raw history: seed ${seed}`, () => {
    const { sessions, markers } = history(seed);
    for (const x of HISTORY_EXPECTATIONS) {
      const label = `${x.dataset}: ${x.kind} ${x.key} on day ${x.day} (${x.expect})`;
      const same = (s) => s.project === x.project && (x.kind !== "tool" || s.platform === x.platform);
      const session = sessions.find((s) => s.machine === x.machine && s.day === x.day && same(s) && s.items[x.kind].has(x.key));
      assert.ok(session, `${label}: used that day`);
      const before = sessions.filter((s) => s.at < session.at && same(s) && s.items[x.kind].has(x.key));
      if (x.expect === "not-new") {
        assert.ok(before.length > 0, `${label}: used in the project before`);
        continue;
      }
      assert.equal(before.length, 0, `${label}: first use in the project`);
      // How many of the project's sessions on this machine ran since its
      // last monitoring change: under 2 is the coverage window. A change for
      // one platform (hooks installed for Codex) applies to, and counts,
      // that platform's sessions only.
      const applies = (m, platform) => !m.event.target || m.event.target === platform;
      const change = markers.filter((m) => m.machine === x.machine && m.at <= session.at && applies(m, session.platform)).at(-1);
      const since = sessions.filter((s) => s.machine === x.machine && same(s) && applies(change, s.platform) && s.at >= change.at && s.at < session.at).length;
      // The day-0 installs start each machine's history; they are not changes.
      if (x.expect === "new-coverage") assert.ok(since < 2 && dayOf(change.event.occurred_at) > 0, `${label}: right after a change (${since})`);
      else assert.ok(since >= 2, `${label}: not right after a change (${since})`);
      if (x.expect === "held") {
        let n = 0;
        const risks = detectRisks(session.source, () => `r${n++}`).newEvents;
        const reaching = new Set(session.source.filter((e) => e.event_type === "tool.invoked" && normalizeAction(e).destinations.some((d) => d.host === x.key)).map((e) => e.tool_call_id));
        assert.ok(risks.some((r) => reaching.has(r.related_event_id) && ["HIGH", "CRITICAL"].includes(r.severity)), `${label}: HIGH or CRITICAL finding`);
      }
    }
  });
}

test("the history set is reproducible, varies with the seed, and appends under new ids", () => {
  const a = buildHistoryScenarios({ machine: "a", seed: 3, now: NOW });
  assert.equal(JSON.stringify(a), JSON.stringify(buildHistoryScenarios({ machine: "a", seed: 3, now: NOW })));
  const other = buildHistoryScenarios({ machine: "a", seed: 4, now: NOW });
  assert.notEqual(JSON.stringify(a), JSON.stringify(other));
  // The seed varies timing and file reads, never the hosts, servers or tools.
  const items = (events) => [...new Set(events.filter((e) => e.event_type === "tool.invoked" && e.tool_name !== "Read").map((e) => `${e.session_id.split("_").slice(-2).join("_")}|${e.tool_name}|${JSON.stringify(e.parameters)}`))].sort();
  assert.deepEqual(items(a), items(other));
  const again = buildHistoryScenarios({ machine: "a", seed: 3, now: NOW, existingSessionIds: a.map((e) => e.session_id) });
  const all = [...a, ...again];
  assert.equal(new Set(all.map((e) => e.event_id)).size, all.length);
  // Both machines' events stay within the six weeks before now.
  for (const machine of ["a", "b"]) {
    for (const e of buildHistoryScenarios({ machine, now: NOW })) {
      assert.ok(Date.parse(e.occurred_at) < Date.parse(NOW) && Date.parse(e.occurred_at) >= Date.parse(NOW) - HISTORY_DAYS * DAY, e.event_id);
    }
  }
});

test("spike options for the history set", () => {
  assert.deepEqual(parseSpikeOptions(["--scenario-set", "history", "--machine", "b", "--seed", "2"]), { history: "b", seed: 2 });
  for (const args of [["--scenario-set", "history"], ["--machine", "a"], ["--scenario-set", "history", "--machine", "c"], ["--scenario-set", "history", "--machine", "a", "--sessions", "20"], ["--scenario-set", "other"]]) {
    assert.throws(() => parseSpikeOptions(args), args.join(" "));
  }
});

// Two machines in two isolated homes, plus a repeat of one, through the CLI.
test("CLI writes each machine's history reproducibly into its own home", { timeout: 180_000 }, async () => {
  const scratch = await mkdtemp(path.join(tmpdir(), "omnodex-history-"));
  const cli = fileURLToPath(new URL("../dist/index.js", import.meta.url));
  const run = (home, args) => {
    const result = spawnSync(process.execPath, [cli, ...args], {
      env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: home, OMNODEX_SINGLE_ROOT: "1", OMNODEX_NO_UPDATE_CHECK: "1", OMNODEX_AUTO_SYNC: "0" },
      encoding: "utf8", timeout: 90_000,
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    return result.stdout;
  };
  const logs = async (home) => {
    const dir = path.join(home, "event-log", "sessions");
    return Promise.all((await readdir(dir)).sort().map((f) => readFile(path.join(dir, f), "utf8")));
  };
  try {
    const homes = { a: path.join(scratch, "a"), a2: path.join(scratch, "a2"), b: path.join(scratch, "b") };
    for (const home of Object.values(homes)) await mkdir(home);
    for (const [home, machine] of [[homes.a, "a"], [homes.a2, "a"], [homes.b, "b"]]) {
      run(home, ["spike", "--scenario-set", "history", "--machine", machine, "--seed", "5", "--now", NOW]);
    }
    assert.deepEqual(await logs(homes.a), await logs(homes.a2));
    for (const [home, machine] of [[homes.a, "a"], [homes.b, "b"]]) {
      const expected = new Set(buildHistoryScenarios({ machine, seed: 5, now: NOW }).map((e) => e.session_id));
      expected.delete(CAPTURE_CONTROL_SESSION_ID);
      const store = new SqliteReadModelStore({ dbPath: path.join(home, "traces.db") });
      await store.init();
      try {
        const rows = (await store.listSessions()).filter((r) => r.session_id !== CAPTURE_CONTROL_SESSION_ID);
        assert.equal(rows.length, expected.size);
        assert.ok(rows.every((r) => r.project_remote?.startsWith("github.com/")), "every session carries its remote");
      } finally { await store.close(); }
      const raw = (await logs(home)).join("");
      assert.ok(raw.includes('"event_type":"monitoring.changed"'), "monitoring markers written");
    }
    // The planted known-bad host raised its finding through the real pipeline.
    assert.ok((await logs(homes.a)).join("").includes("RULE_SUPPLY_CHAIN_IOC_DOMAIN"));
  } finally { await rm(scratch, { recursive: true, force: true }); }
});
