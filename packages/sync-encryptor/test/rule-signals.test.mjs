// Rule signals: the capture paths' per-rule enforcement lines are totaled by
// the background pass, sent as rule ids and counts only, at most every 15
// minutes with a batch_id kept across retries, dropped after 7 days rather
// than sent late, and never sent without credentials.
//
// Run: node --test packages/sync-encryptor/test/rule-signals.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { appendFile, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  collectRuleSignals,
  readRuleSignals,
  submitRuleSignals,
  RULE_SIGNALS_LOG,
} from "../dist/rule-signals.js";
import { SUBMIT_INTERVAL_MS } from "../dist/advanced-usage.js";
import { submitSignals } from "../dist/auto-sync.js";

const T = Date.parse("2026-10-18T10:00:00Z");

function api(status = 200) {
  const bodies = [];
  const fetchFn = async (url, init) => {
    bodies.push({ url, auth: init.headers.Authorization, body: JSON.parse(init.body) });
    if (status === "down") throw new Error("offline");
    return new Response(JSON.stringify({ ok: status < 300 }), { status });
  };
  return { bodies, fetchFn, opts: (now) => ({ apiUrl: "https://api.case/", apiToken: "omx_test_case", fetchFn, now }) };
}

const line = (rule_id, kind, day = "2026-10-18") => JSON.stringify({ day, rule_id, kind }) + "\n";

describe("rule signals", () => {
  let home;
  beforeEach(async () => { home = await mkdtemp(path.join(os.tmpdir(), "omnodex-signals-")); });
  afterEach(async () => { await rm(home, { recursive: true, force: true }); });

  it("collects lines into per-day, per-rule, per-kind counts and removes the log", async () => {
    await writeFile(path.join(home, RULE_SIGNALS_LOG),
      line("RULE_A", "would_block") + line("RULE_A", "would_block") + line("RULE_B", "in_force") +
      "not json\n" + line("BAD|ID", "would_block") + JSON.stringify({ day: "yesterday", rule_id: "X", kind: "k" }) + "\n");
    assert.equal(await collectRuleSignals(home, T), 3);
    assert.deepEqual((await readRuleSignals(home)).pending, {
      "2026-10-18|RULE_A|would_block": 2,
      "2026-10-18|RULE_B|in_force": 1,
    });
    await assert.rejects(stat(path.join(home, RULE_SIGNALS_LOG)));
    // A second pass adds to the same counts.
    await appendFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_A", "would_block"));
    await collectRuleSignals(home, T);
    assert.equal((await readRuleSignals(home)).pending["2026-10-18|RULE_A|would_block"], 3);
  });

  it("submits rule ids and counts only, then waits before the next submission", async () => {
    const a = api();
    await writeFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_A", "would_block"));
    await collectRuleSignals(home, T);
    assert.equal(await submitRuleSignals(home, a.opts(T)), "submitted");
    assert.equal(a.bodies[0].url, "https://api.case/api/v1/usage/rules");
    assert.deepEqual(Object.keys(a.bodies[0].body).sort(), ["batch_id", "counts"]);
    assert.deepEqual(a.bodies[0].body.counts, [{ day: "2026-10-18", rule_id: "RULE_A", kind: "would_block", count: 1 }]);
    assert.deepEqual((await readRuleSignals(home)).pending, {});

    await writeFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_A", "would_block"));
    await collectRuleSignals(home, T + 60_000);
    assert.equal(await submitRuleSignals(home, a.opts(T + 60_000)), "too-soon");
    assert.equal(await submitRuleSignals(home, a.opts(T + SUBMIT_INTERVAL_MS)), "submitted");
  });

  it("resends a failed batch with the same batch_id", async () => {
    const down = api("down");
    await writeFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_A", "would_block"));
    await collectRuleSignals(home, T);
    assert.equal(await submitRuleSignals(home, down.opts(T)), "failed");
    const up = api();
    assert.equal(await submitRuleSignals(home, up.opts(T + SUBMIT_INTERVAL_MS)), "submitted");
    assert.equal(up.bodies[0].body.batch_id, down.bodies[0].body.batch_id);
  });

  it("drops counts the server refuses, and counts older than 7 days", async () => {
    const refused = api(403);
    await writeFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_A", "would_block"));
    await collectRuleSignals(home, T);
    assert.equal(await submitRuleSignals(home, refused.opts(T)), "refused");
    assert.equal((await readRuleSignals(home)).in_flight, undefined);

    await writeFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_OLD", "would_block", "2026-10-01"));
    await collectRuleSignals(home, T);
    assert.deepEqual((await readRuleSignals(home)).pending, {});
    assert.equal((await readRuleSignals(home)).dropped.counts, 2);
  });

  it("never sends without credentials, but still totals the log", async () => {
    const today = new Date().toISOString().slice(0, 10);
    await writeFile(path.join(home, RULE_SIGNALS_LOG), line("RULE_A", "would_block", today));
    let called = false;
    const outcome = await submitSignals(home, async () => { called = true; return new Response("{}"); });
    assert.equal(outcome, "no-credentials");
    assert.equal(called, false);
    assert.equal((await readRuleSignals(home)).pending[`${today}|RULE_A|would_block`], 1);
  });

  it("is a no-op with nothing logged", async () => {
    assert.equal(await collectRuleSignals(home, T), 0);
    assert.equal(await submitRuleSignals(home, api().opts(T)), "nothing");
  });
});

