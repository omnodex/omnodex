/**
 * The read model is one canonical artifact derived from every configured root.
 *
 * Before this, only `omnodex dashboard` resolved roots. `omnodex replay`
 * rebuilt the same database file from the primary root alone, so replaying
 * deleted every secondary root's sessions and the next sync pushed the
 * smaller set. These tests pin the two paths to the same result.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { EventLog } from "../../event-log/dist/index.js";
import { SqliteReadModelStore } from "../../projection/dist/index.js";
import { resolveRoots } from "../dist/config.js";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));

async function mkTmp(label) {
  return await fs.mkdtemp(path.join(os.tmpdir(), `omnodex-${label}-`));
}

/** Write one finished session into a root's event log. */
async function seedRoot(root, sessionId) {
  const log = new EventLog({ root: path.join(root, "event-log") });
  await log.init();
  const at = "2026-09-18T12:00:00.000Z";
  const base = {
    schema_version: 1,
    session_id: sessionId,
    occurred_at: at,
    recorded_at: at,
    interceptor: "claude-code-hook",
  };
  await log.appendMany([
    {
      ...base,
      event_id: `${sessionId}-start`,
      event_type: "session.started",
      user: "case",
      project_path: "/home/case/repo",
      mcp_servers: [],
    },
    {
      ...base,
      event_id: `${sessionId}-tc`,
      event_type: "tool.invoked",
      tool_call_id: `${sessionId}-tc1`,
      tool_name: "Read",
      mcp_server: "builtin",
      parameters: { file_path: "/home/case/repo/a.md" },
    },
  ]);
  await log.close();
}

/**
 * Run the CLI against a throwaway HOME.
 *
 * resolveRoots always includes the default home, which comes from
 * os.homedir(), so without this every test would read the developer's real
 * ~/.omnodex. `detect` would go further and append risk events to their
 * event log, which is a supported command doing supported work, just not to
 * data a test has any business touching.
 */
function runCli(args, env) {
  return spawnSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, HOME: env.FAKE_HOME, USERPROFILE: env.FAKE_HOME, ...env },
    encoding: "utf8",
    timeout: 60_000,
  });
}

/** Run a body with os.homedir() pointed somewhere harmless. */
async function withFakeHome(fakeHome, body) {
  const prevHome = process.env.HOME;
  const prevProfile = process.env.USERPROFILE;
  process.env.HOME = fakeHome;
  process.env.USERPROFILE = fakeHome;
  try {
    return await body();
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = prevProfile;
  }
}

async function sessionIdsIn(dbPath) {
  const store = new SqliteReadModelStore({ dbPath });
  await store.init();
  const sessions = await store.listSessions();
  await store.close();
  return sessions.map((s) => s.session_id).sort();
}

// ---------------------------------------------------------------------------
// resolveRoots: primary must be this installation's home
// ---------------------------------------------------------------------------

test("primary is OMNODEX_HOME when it is set", async () => {
  // The read model is written to primary, and every non-dashboard command
  // reads OMNODEX_HOME. If those disagree, the dashboard builds one database
  // and sync reads another.
  const home = await mkTmp("primary");
  const fakeHome = await mkTmp("home");
  const previous = process.env.OMNODEX_HOME;
  process.env.OMNODEX_HOME = home;
  try {
    await withFakeHome(fakeHome, async () => {
      const resolved = await resolveRoots();
      assert.equal(resolved.primary, path.resolve(home));
      assert.equal(resolved.all[0], path.resolve(home));
    });
  } finally {
    if (previous === undefined) delete process.env.OMNODEX_HOME;
    else process.env.OMNODEX_HOME = previous;
  }
});

test("the default home is still aggregated when it is not primary", async () => {
  // Cowork Desktop writes to ~/.omnodex whatever OMNODEX_HOME says, so it
  // has to stay in the list even when another root leads.
  const home = await mkTmp("primary");
  const fakeHome = await mkTmp("home");
  const previous = process.env.OMNODEX_HOME;
  process.env.OMNODEX_HOME = home;
  try {
    await withFakeHome(fakeHome, async () => {
      const resolved = await resolveRoots();
      assert.ok(
        resolved.all.includes(path.resolve(path.join(fakeHome, ".omnodex"))),
        "default home should remain in the root list",
      );
    });
  } finally {
    if (previous === undefined) delete process.env.OMNODEX_HOME;
    else process.env.OMNODEX_HOME = previous;
  }
});

// ---------------------------------------------------------------------------
// replay: every root, into one place
// ---------------------------------------------------------------------------

test("replay rebuilds the read model from every configured root", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  const secondary = await mkTmp("root-secondary");

  await seedRoot(primary, "sess-primary");
  await seedRoot(secondary, "sess-secondary");

  await fs.writeFile(
    path.join(primary, "config.json"),
    JSON.stringify({ dashboard: { roots: [secondary] } }),
    "utf8",
  );

  const result = runCli(["replay"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const ids = await sessionIdsIn(path.join(primary, "traces.db"));
  assert.deepEqual(
    ids,
    ["sess-primary", "sess-secondary"],
    "the secondary root's session must survive a replay",
  );
});

test("replay does not narrow a read model that already holds every root", async () => {
  // The regression: replaying twice used to leave only the primary root,
  // because the second pass rebuilt from one log after resetting the store.
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  const secondary = await mkTmp("root-secondary");

  await seedRoot(primary, "sess-primary");
  await seedRoot(secondary, "sess-secondary");
  await fs.writeFile(
    path.join(primary, "config.json"),
    JSON.stringify({ dashboard: { roots: [secondary] } }),
    "utf8",
  );

  runCli(["replay"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  const first = await sessionIdsIn(path.join(primary, "traces.db"));

  runCli(["replay"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  const second = await sessionIdsIn(path.join(primary, "traces.db"));

  assert.deepEqual(second, first);
  assert.equal(second.length, 2);
});

test("replay writes the read model to the primary root", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  const secondary = await mkTmp("root-secondary");
  await seedRoot(primary, "sess-primary");
  await seedRoot(secondary, "sess-secondary");
  await fs.writeFile(
    path.join(primary, "config.json"),
    JSON.stringify({ dashboard: { roots: [secondary] } }),
    "utf8",
  );

  runCli(["replay"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });

  // The secondary root must not acquire a read model of its own: one
  // canonical location is the point.
  await assert.rejects(() => fs.access(path.join(secondary, "traces.db")));
  await fs.access(path.join(primary, "traces.db"));
});

test("--roots adds a root for this run", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  const extra = await mkTmp("root-extra");
  await seedRoot(primary, "sess-primary");
  await seedRoot(extra, "sess-extra");

  const result = runCli(["replay", "--roots", extra], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const ids = await sessionIdsIn(path.join(primary, "traces.db"));
  assert.ok(ids.includes("sess-extra"));
});

test("a single-root install still works unchanged", async () => {
  const only = await mkTmp("root-only");
  const fakeHome = await mkTmp("home");
  await seedRoot(only, "sess-only");

  const result = runCli(["replay"], { OMNODEX_HOME: only, FAKE_HOME: fakeHome });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  assert.deepEqual(await sessionIdsIn(path.join(only, "traces.db")), ["sess-only"]);
});

// ---------------------------------------------------------------------------
// detect: every root, or none of them gets analysed
// ---------------------------------------------------------------------------

test("detect scans every configured root", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  const secondary = await mkTmp("root-secondary");
  await seedRoot(primary, "sess-primary");
  await seedRoot(secondary, "sess-secondary");
  await fs.writeFile(
    path.join(primary, "config.json"),
    JSON.stringify({ dashboard: { roots: [secondary] } }),
    "utf8",
  );

  const result = runCli(["detect"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  // Both sessions are reported on. Before this, a secondary root could
  // accumulate tool calls and never be analysed at all.
  assert.match(result.stdout, /sess-primary/);
  assert.match(result.stdout, /sess-secondary/);
});

test("detect reports a session id that exists in no root", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  await seedRoot(primary, "sess-primary");

  const result = runCli(["detect", "sess-nope"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /not found in any root/);
});

// ---------------------------------------------------------------------------
// clear: find the session wherever it lives
// ---------------------------------------------------------------------------

test("clear removes a session that lives in a secondary root", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  const secondary = await mkTmp("root-secondary");
  await seedRoot(primary, "sess-primary");
  await seedRoot(secondary, "sess-secondary");
  await fs.writeFile(
    path.join(primary, "config.json"),
    JSON.stringify({ dashboard: { roots: [secondary] } }),
    "utf8",
  );

  const result = runCli(["clear", "sess-secondary"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  // Gone from disk, not merely from the read model.
  const remaining = new EventLog({ root: path.join(secondary, "event-log") });
  await remaining.init();
  assert.deepEqual(await remaining.listSessions(), []);
  await remaining.close();

  // And the primary root's session survived the rebuild.
  assert.deepEqual(await sessionIdsIn(path.join(primary, "traces.db")), ["sess-primary"]);
});

test("clear says so when the session is in no root", async () => {
  const primary = await mkTmp("root-primary");
  const fakeHome = await mkTmp("home");
  await seedRoot(primary, "sess-primary");

  const result = runCli(["clear", "sess-nope"], { OMNODEX_HOME: primary, FAKE_HOME: fakeHome });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not found in any root/);
});
