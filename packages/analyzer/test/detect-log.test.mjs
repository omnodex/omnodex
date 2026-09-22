/**
 * detectEventLogs() and runBackgroundDetect() tests.
 *
 * Detection over event logs on disk: findings are appended to the session
 * they belong to, runs are idempotent, and with a state file an unchanged
 * session is skipped without being read.
 *
 * Run: node --test packages/analyzer/test/detect-log.test.mjs
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog } from "@omnodex/event-log";
import {
  detectEventLogs,
  runBackgroundDetect,
  DETECT_STATE_FILE,
} from "../dist/detect-log.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function baseEvent(sessionId) {
  const now = new Date().toISOString();
  return {
    schema_version: 1,
    event_id: randomUUID(),
    session_id: sessionId,
    occurred_at: now,
    recorded_at: now,
    interceptor: "claude-code-hook",
  };
}

function sessionStarted(sessionId) {
  return {
    ...baseEvent(sessionId),
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
  };
}

/** A Read of /etc/passwd: fires RULE_SENSITIVE_PATH_READ. */
function sensitiveRead(sessionId) {
  return {
    ...baseEvent(sessionId),
    event_type: "tool.invoked",
    tool_call_id: `tc-${randomUUID()}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: "/etc/passwd" },
  };
}

/** A Read inside the project: fires nothing. */
function harmlessRead(sessionId) {
  return {
    ...baseEvent(sessionId),
    event_type: "tool.invoked",
    tool_call_id: `tc-${randomUUID()}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: "/home/case/repo/README.md" },
  };
}

async function append(root, events) {
  const log = new EventLog({ root });
  await log.init();
  await log.appendMany(events);
  await log.close();
}

async function readSession(root, sessionId) {
  const log = new EventLog({ root });
  await log.init();
  const events = await log.readSession(sessionId);
  await log.close();
  return events;
}

function risks(events) {
  return events.filter((e) => e.event_type === "risk.detected");
}

// ---------------------------------------------------------------------------
// detectEventLogs
// ---------------------------------------------------------------------------

describe("detectEventLogs", () => {
  let dir;
  let root;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-detect-log-"));
    root = path.join(dir, "event-log");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("appends findings to the session they belong to and returns them", async () => {
    await append(root, [sessionStarted("sess-case-a"), sensitiveRead("sess-case-a")]);

    const result = await detectEventLogs({ roots: [root] });

    assert.equal(result.scanned, 1);
    assert.ok(result.newEvents.length >= 1);
    assert.ok(result.newEvents.some((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ"));
    const logged = risks(await readSession(root, "sess-case-a"));
    assert.deepEqual(
      logged.map((e) => e.event_id).sort(),
      result.newEvents.map((e) => e.event_id).sort(),
    );
  });

  it("is idempotent: a second full run appends nothing", async () => {
    await append(root, [sessionStarted("sess-case-b"), sensitiveRead("sess-case-b")]);

    const first = await detectEventLogs({ roots: [root] });
    const second = await detectEventLogs({ roots: [root] });

    assert.ok(first.newEvents.length >= 1);
    assert.equal(second.newEvents.length, 0);
    assert.equal(second.skipped, first.newEvents.length);
    assert.equal(risks(await readSession(root, "sess-case-b")).length, first.newEvents.length);
  });

  it("evaluates only the named session", async () => {
    await append(root, [
      sessionStarted("sess-case-c1"),
      sensitiveRead("sess-case-c1"),
      sessionStarted("sess-case-c2"),
      sensitiveRead("sess-case-c2"),
    ]);

    const result = await detectEventLogs({ roots: [root], sessionId: "sess-case-c2" });

    assert.equal(result.scanned, 1);
    assert.ok(result.newEvents.every((e) => e.session_id === "sess-case-c2"));
    assert.equal(risks(await readSession(root, "sess-case-c1")).length, 0);
  });

  it("covers every root it is given", async () => {
    const second = path.join(dir, "other", "event-log");
    await append(root, [sessionStarted("sess-case-d1"), sensitiveRead("sess-case-d1")]);
    await append(second, [sessionStarted("sess-case-d2"), sensitiveRead("sess-case-d2")]);

    const result = await detectEventLogs({ roots: [root, second] });

    assert.equal(result.scanned, 2);
    assert.ok(risks(await readSession(root, "sess-case-d1")).length >= 1);
    assert.ok(risks(await readSession(second, "sess-case-d2")).length >= 1);
  });

  it("reports each evaluated session", async () => {
    await append(root, [
      sessionStarted("sess-case-e1"),
      sensitiveRead("sess-case-e1"),
      sessionStarted("sess-case-e2"),
      harmlessRead("sess-case-e2"),
    ]);
    const reports = [];

    await detectEventLogs({ roots: [root], onSession: (r) => reports.push(r) });

    const bySession = Object.fromEntries(reports.map((r) => [r.sessionId, r]));
    assert.ok(bySession["sess-case-e1"].newEvents.length >= 1);
    assert.equal(bySession["sess-case-e2"].newEvents.length, 0);
  });

  describe("with a state file", () => {
    let statePath;

    beforeEach(() => {
      statePath = path.join(dir, DETECT_STATE_FILE);
    });

    it("skips a session whose file has not changed since the last run", async () => {
      await append(root, [sessionStarted("sess-case-f"), harmlessRead("sess-case-f")]);

      const first = await detectEventLogs({ roots: [root], statePath });
      const second = await detectEventLogs({ roots: [root], statePath });

      assert.equal(first.scanned, 1);
      assert.equal(second.scanned, 0);
      assert.equal(second.unchanged, 1);
    });

    it("rescans a session that has grown and finds its new risk", async () => {
      await append(root, [sessionStarted("sess-case-g"), harmlessRead("sess-case-g")]);
      await detectEventLogs({ roots: [root], statePath });

      await append(root, [sensitiveRead("sess-case-g")]);
      const result = await detectEventLogs({ roots: [root], statePath });

      assert.equal(result.scanned, 1);
      assert.ok(result.newEvents.some((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ"));
    });

    it("settles after one extra scan when a run appends its own findings", async () => {
      await append(root, [sessionStarted("sess-case-h"), sensitiveRead("sess-case-h")]);

      const first = await detectEventLogs({ roots: [root], statePath });
      // The first run's findings grew the file after its size was recorded.
      const second = await detectEventLogs({ roots: [root], statePath });
      const third = await detectEventLogs({ roots: [root], statePath });

      assert.ok(first.newEvents.length >= 1);
      assert.equal(second.scanned, 1);
      assert.equal(second.newEvents.length, 0);
      assert.equal(third.scanned, 0);
      assert.equal(third.unchanged, 1);
    });

    it("records the run time and per-root sizes", async () => {
      await append(root, [sessionStarted("sess-case-i"), harmlessRead("sess-case-i")]);

      await detectEventLogs({ roots: [root], statePath });

      const state = JSON.parse(await readFile(statePath, "utf8"));
      assert.equal(state.version, 1);
      assert.ok(Date.parse(state.last_run_at) > 0);
      assert.ok(state.sessions[root]["sess-case-i"] > 0);
    });

    it("falls back to a full scan on an unreadable state file", async () => {
      await append(root, [sessionStarted("sess-case-j"), sensitiveRead("sess-case-j")]);
      await writeFile(statePath, "{ not json");

      const result = await detectEventLogs({ roots: [root], statePath });

      assert.equal(result.scanned, 1);
      assert.ok(result.newEvents.length >= 1);
    });
  });
});

// ---------------------------------------------------------------------------
// runBackgroundDetect
// ---------------------------------------------------------------------------

describe("runBackgroundDetect", () => {
  let home;

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-bg-detect-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("evaluates the home's event log and keeps its watermark under the home", async () => {
    const root = path.join(home, "event-log");
    await append(root, [sessionStarted("sess-case-k"), sensitiveRead("sess-case-k")]);

    const findings = await runBackgroundDetect(home);

    assert.ok(findings.some((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ"));
    assert.ok(risks(await readSession(root, "sess-case-k")).length >= 1);
    const state = JSON.parse(await readFile(path.join(home, DETECT_STATE_FILE), "utf8"));
    assert.ok(state.sessions[root]["sess-case-k"] > 0);
  });

  it("returns nothing on a home with no activity, and creates no event log there", async () => {
    assert.deepEqual(await runBackgroundDetect(home), []);
    await assert.rejects(readFile(path.join(home, "event-log", "index.jsonl")));
  });
});
