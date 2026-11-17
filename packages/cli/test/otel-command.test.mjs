// `omnodex otel serve` and `omnodex otel token`, run in-process against a
// scratch home so nothing touches the real one.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { createServer } from "node:net";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "@omnodex/event-log";
import { runOtel } from "../dist/otel-command.js";

async function scratch(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-otelcli-case-"));
  const home = path.join(root, ".omnodex");
  await fs.mkdir(home, { recursive: true });
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, OMNODEX_HOME: process.env.OMNODEX_HOME, OMNODEX_SINGLE_ROOT: process.env.OMNODEX_SINGLE_ROOT };
  Object.assign(process.env, { HOME: root, USERPROFILE: root, OMNODEX_HOME: home, OMNODEX_SINGLE_ROOT: "1" });
  t.after(async () => {
    for (const [k, v] of Object.entries(saved)) (v === undefined ? delete process.env[k] : (process.env[k] = v));
    await fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return home;
}

function io() {
  const out = [];
  const err = [];
  return { out, err, io: { log: (l) => out.push(l), error: (l) => err.push(l) } };
}

const TOOL_EXPORT = JSON.stringify({
  resourceSpans: [{
    scopeSpans: [{
      spans: [{
        traceId: "0".repeat(31) + "1", spanId: "0".repeat(15) + "2", name: "anthropic.tool_use bash",
        startTimeUnixNano: "1794582000000000000", endTimeUnixNano: "1794582000100000000",
        attributes: [
          { key: "anthropic.session.id", value: { stringValue: "sesn_cli" } },
          { key: "gen_ai.operation.name", value: { stringValue: "execute_tool" } },
          { key: "gen_ai.tool.name", value: { stringValue: "bash" } },
          { key: "gen_ai.tool.call.id", value: { stringValue: "toolu_cli" } },
          { key: "gen_ai.tool.call.arguments", value: { stringValue: '{"command":"id"}' } },
        ],
      }],
    }],
  }],
});

/** Run `otel serve` until `body` finishes, then stop it. Returns the exit code and output. */
async function serving(home, args, body, env = {}) {
  const { out, err, io: sinks } = io();
  const stop = new AbortController();
  let listening;
  const ready = new Promise((resolve) => (listening = resolve));
  const done = runOtel(["serve", ...args], { home, io: sinks, signal: stop.signal, env, onListening: listening });
  const first = await Promise.race([ready, done]);
  if (typeof first === "number") return { code: first, out, err };
  try {
    await body(first);
  } finally {
    stop.abort();
  }
  return { code: await done, out, err };
}

test("token prints the token alone on stdout, and keeps it until rotated", async (t) => {
  const home = await scratch(t);
  const a = io();
  assert.equal(await runOtel(["token"], { home, io: a.io }), 0);
  assert.equal(a.out.length, 1);
  assert.match(a.out[0], /^omxotel_/);
  assert.deepEqual(a.err, ["[otel] token created"]);

  const b = io();
  await runOtel(["token"], { home, io: b.io });
  assert.deepEqual(b.out, a.out);
  assert.deepEqual(b.err, []);

  const c = io();
  await runOtel(["token", "--rotate"], { home, io: c.io });
  assert.notEqual(c.out[0], a.out[0]);
  assert.match(c.err[0], /restart the receiver/);
});

test("serve receives a trace export and writes the local event log", async (t) => {
  const home = await scratch(t);
  const result = await serving(home, ["--listen", "127.0.0.1:0"], async ({ port }) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/traces`, { method: "POST", headers: { "content-type": "application/json" }, body: TOOL_EXPORT });
    assert.equal(res.status, 200);
    for (let i = 0; i < 200; i++) {
      const stats = await (await fetch(`http://127.0.0.1:${port}/status`)).json();
      if (stats.events_written >= 3) return;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.fail("events were not written");
  });
  assert.equal(result.code, 0);
  assert.ok(result.out.some((l) => /receiving traces at http:\/\/127\.0\.0\.1:\d+\/v1\/traces/.test(l)));
  assert.ok(result.out.some((l) => /no token set/.test(l)), "says plainly that nothing guards the port");
  assert.ok(result.out.some((l) => /1 request\(s\), 1 span\(s\) received/.test(l)));

  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  const events = await log.readSession("ma:sesn_cli");
  await log.close();
  assert.deepEqual(events.map((e) => e.event_type), ["session.started", "tool.invoked", "tool.completed"]);
  assert.equal(events[1].parameters.command, "id");
});

test("serve enforces the token from the environment, then the stored one", async (t) => {
  const home = await scratch(t);
  const post = (port, token) =>
    fetch(`http://127.0.0.1:${port}/v1/traces`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ resourceSpans: [] }),
    });

  const fromEnv = await serving(home, ["--listen", "127.0.0.1:0"], async ({ port }) => {
    assert.equal((await post(port)).status, 401);
    assert.equal((await post(port, "env-secret")).status, 200);
  }, { OMNODEX_OTEL_TOKEN: "env-secret" });
  assert.equal(fromEnv.code, 0);
  assert.ok(fromEnv.out.some((l) => /bearer token is required \(OMNODEX_OTEL_TOKEN\)/.test(l)));

  const stored = io();
  await runOtel(["token"], { home, io: stored.io });
  const token = stored.out[0];
  const fromFile = await serving(home, ["--listen", "127.0.0.1:0"], async ({ port }) => {
    assert.equal((await post(port, "wrong")).status, 401);
    assert.equal((await post(port, token)).status, 200);
  });
  assert.equal(fromFile.code, 0);
  assert.ok(!fromFile.out.some((l) => l.includes(token)), "the token is never echoed");
});

test("serve refuses a bad address, a remote address without consent, and a port in use", async (t) => {
  const home = await scratch(t);
  const bad = await serving(home, ["--listen", "nonsense"], async () => {});
  assert.equal(bad.code, 1);
  assert.match(bad.err.join("\n"), /--listen/);

  const remote = await serving(home, ["--listen", "0.0.0.0:0"], async () => {});
  assert.equal(remote.code, 1);
  assert.match(remote.err.join("\n"), /non-loopback.*--allow-remote/);

  const noToken = await serving(home, ["--listen", "0.0.0.0:0", "--allow-remote"], async () => {});
  assert.equal(noToken.code, 1);
  assert.match(noToken.err.join("\n"), /requires a token/);

  const blocker = createServer();
  await new Promise((r) => blocker.listen(0, "127.0.0.1", r));
  t.after(() => blocker.close());
  const busy = await serving(home, ["--listen", `127.0.0.1:${blocker.address().port}`], async () => {});
  assert.equal(busy.code, 1);
  assert.match(busy.err.join("\n"), /already in use/);
});

test("an unknown or missing otel command prints usage and fails", async (t) => {
  const home = await scratch(t);
  for (const args of [[], ["frobnicate"]]) {
    const r = io();
    assert.equal(await runOtel(args, { home, io: r.io }), 1);
    assert.match(r.err.join("\n"), /Usage: omnodex otel/);
  }
});
