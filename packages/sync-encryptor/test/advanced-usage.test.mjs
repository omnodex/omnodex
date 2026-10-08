// Advanced (Pro) usage counter: counts survive restarts (they live in a
// file), are submitted at most every 15 minutes with a batch_id that stays
// the same across retries, are dropped after 7 days offline rather than
// billed late, and ride the background pass without a per-event request.
//
// Run: node --test packages/sync-encryptor/test/advanced-usage.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  addAdvancedUsage,
  readAdvancedUsage,
  submitAdvancedUsage,
  SUBMIT_INTERVAL_MS,
} from "../dist/advanced-usage.js";
import { runAutoSync } from "../dist/auto-sync.js";

const T = Date.parse("2026-10-08T10:00:00Z");
const DAY = 86_400_000;

/** A fake API: answers with `status`, records each request body. */
function api(status = 200) {
  const bodies = [];
  const fetchFn = async (url, init) => {
    bodies.push({ url, auth: init.headers.Authorization, body: JSON.parse(init.body) });
    if (status === "down") throw new Error("offline");
    return new Response(JSON.stringify({ ok: status < 300 }), { status });
  };
  return { bodies, fetchFn, opts: (now) => ({ apiUrl: "https://api.case/", apiToken: "omx_test_case", fetchFn, now }) };
}

describe("advanced usage counter", () => {
  let home;
  beforeEach(async () => { home = await mkdtemp(path.join(os.tmpdir(), "omnodex-adv-usage-")); });
  afterEach(async () => { await rm(home, { recursive: true, force: true }); });

  it("accumulates by UTC day in a file, so counts survive a restart", async () => {
    await addAdvancedUsage(home, { evaluated: 10, findings: 1 }, T);
    await addAdvancedUsage(home, { evaluated: 5, findings: 0 }, T + 60_000);
    await addAdvancedUsage(home, { evaluated: 0, findings: 0 }, T + 120_000); // nothing to add
    await addAdvancedUsage(home, { evaluated: 7, findings: 2 }, T + DAY);
    assert.deepEqual((await readAdvancedUsage(home)).pending, {
      "2026-10-08": { evaluated: 15, findings: 1 },
      "2026-10-09": { evaluated: 7, findings: 2 },
    });
  });

  it("submits counts only, then waits 15 minutes before the next submission", async () => {
    const a = api();
    await addAdvancedUsage(home, { evaluated: 15, findings: 1 }, T);
    assert.equal(await submitAdvancedUsage(home, a.opts(T)), "submitted");
    assert.equal(a.bodies[0].url, "https://api.case/api/v1/usage/advanced");
    assert.equal(a.bodies[0].auth, "Bearer omx_test_case");
    assert.deepEqual(Object.keys(a.bodies[0].body).sort(), ["batch_id", "days"]);
    assert.deepEqual(a.bodies[0].body.days, [{ day: "2026-10-08", evaluated: 15, findings: 1 }]);
    const after = await readAdvancedUsage(home);
    assert.deepEqual(after.pending, {});
    assert.equal(after.in_flight, undefined);

    await addAdvancedUsage(home, { evaluated: 3, findings: 0 }, T + 60_000);
    assert.equal(await submitAdvancedUsage(home, a.opts(T + 60_000)), "too-soon");
    assert.equal(await submitAdvancedUsage(home, a.opts(T + SUBMIT_INTERVAL_MS)), "submitted");
    assert.equal(a.bodies.length, 2);
    assert.notEqual(a.bodies[1].body.batch_id, a.bodies[0].body.batch_id);
    assert.equal(await submitAdvancedUsage(home, a.opts(T + 3 * SUBMIT_INTERVAL_MS)), "nothing");
  });

  it("resends the same batch after a failure, without mixing in newer counts", async () => {
    const down = api("down");
    await addAdvancedUsage(home, { evaluated: 4, findings: 0 }, T);
    assert.equal(await submitAdvancedUsage(home, down.opts(T)), "failed");
    await addAdvancedUsage(home, { evaluated: 6, findings: 1 }, T + 60_000);

    const up = api();
    assert.equal(await submitAdvancedUsage(home, up.opts(T + SUBMIT_INTERVAL_MS)), "submitted");
    assert.equal(up.bodies[0].body.batch_id, down.bodies[0].body.batch_id);
    assert.deepEqual(up.bodies[0].body.days, [{ day: "2026-10-08", evaluated: 4, findings: 0 }]);
    // The newer counts go in the next batch.
    assert.equal(await submitAdvancedUsage(home, up.opts(T + 2 * SUBMIT_INTERVAL_MS)), "submitted");
    assert.deepEqual(up.bodies[1].body.days, [{ day: "2026-10-08", evaluated: 6, findings: 1 }]);
  });

  it("drops days older than 7 days instead of billing them late, and records the drop", async () => {
    const down = api("down");
    await addAdvancedUsage(home, { evaluated: 9, findings: 0 }, T);
    assert.equal(await submitAdvancedUsage(home, down.opts(T)), "failed");
    await addAdvancedUsage(home, { evaluated: 2, findings: 0 }, T + 8 * DAY);

    const up = api();
    assert.equal(await submitAdvancedUsage(home, up.opts(T + 8 * DAY)), "submitted");
    // The stale in-flight day is dropped; only the fresh day goes out.
    assert.equal(up.bodies.length, 1);
    assert.deepEqual(up.bodies[0].body.days, [{ day: "2026-10-16", evaluated: 2, findings: 0 }]);
    const state = await readAdvancedUsage(home);
    assert.deepEqual(state.dropped && { evaluated: state.dropped.evaluated, days: state.dropped.days }, { evaluated: 9, days: 1 });
  });

  it("drops counts the server refuses (no advanced rules on the plan)", async () => {
    const refused = api(403);
    await addAdvancedUsage(home, { evaluated: 5, findings: 0 }, T);
    assert.equal(await submitAdvancedUsage(home, refused.opts(T)), "refused");
    const state = await readAdvancedUsage(home);
    assert.equal(state.in_flight, undefined);
    assert.equal(state.dropped.evaluated, 5);
  });
});

describe("background pass", () => {
  let home;
  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-adv-pass-"));
    process.env.OMNODEX_AUTO_DETECT = "1";
  });
  afterEach(async () => {
    delete process.env.OMNODEX_AUTO_DETECT;
    await rm(home, { recursive: true, force: true });
  });

  it("records the detection pass's counts and submits them once per pass", async () => {
    await writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_test_case", passphrase: "p", api_url: "http://127.0.0.1:9", auto_sync: false }));
    const submissions = [];
    await runAutoSync(home, {
      detect: async () => ({ findings: [], advanced: { evaluated: 12, findings: 2 } }),
      refreshRules: async () => {},
      refreshLicense: async () => {},
      submitUsage: async (h) => { submissions.push((await readAdvancedUsage(h)).pending); },
    });
    assert.equal(submissions.length, 1);
    const [pending] = submissions;
    assert.deepEqual(Object.values(pending), [{ evaluated: 12, findings: 2 }]);
  });

  it("still takes a plain list of findings from older callers", async () => {
    let submitted = 0;
    await runAutoSync(home, { detect: async () => [], refreshRules: async () => {}, refreshLicense: async () => {}, submitUsage: async () => { submitted++; } });
    assert.equal(submitted, 1);
    assert.deepEqual((await readAdvancedUsage(home)).pending, {});
  });
});
