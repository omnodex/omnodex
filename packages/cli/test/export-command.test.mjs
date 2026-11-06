// `omnodex export` end to end: argument checks, one-shot export, follow with
// a watermark, and size-based rotation.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { runExport, parseExportArgs, parseSize, RotatingFile } from "../dist/export-command.js";

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-export-"));
  await fs.mkdir(path.join(root, "event-log", "sessions"), { recursive: true });
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

const ev = (id, session, at, over = {}) => ({
  schema_version: 1,
  event_id: id,
  session_id: session,
  event_type: "tool.invoked",
  occurred_at: at,
  recorded_at: at,
  interceptor: "claude-code-hook",
  tool_call_id: `c-${id}`,
  tool_name: "Bash",
  mcp_server: "builtin",
  parameters: { command: "echo PRIVATE" },
  ...over,
});

const sessionFile = (root, id) => path.join(root, "event-log", "sessions", `${id}.jsonl`);
const lines = (events) => events.map((e) => JSON.stringify(e)).join("\n") + "\n";
const readLines = async (file) => (await fs.readFile(file, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));

function fakeIo() {
  const out = [];
  const err = [];
  return { out, err, write: (t) => out.push(t), error: (l) => err.push(l) };
}

test("argument errors name the problem", () => {
  assert.match(parseExportArgs([]).error, /--out/);
  assert.match(parseExportArgs(["--out", "x", "--format", "xml"]).error, /unknown format/);
  assert.match(parseExportArgs(["--out", "x", "--since", "later"]).error, /--since/);
  assert.match(parseExportArgs(["--out", "x", "--include", "secrets"]).error, /unknown content group/);
  assert.match(parseExportArgs(["--out", "x", "--follow", "--until", "1d"]).error, /--until/);
  assert.match(parseExportArgs(["--out", "x", "--max-size", "big"]).error, /--max-size/);
  assert.equal(parseExportArgs(["--out", "x"]).format, "jsonl");
  assert.equal(parseSize("10m"), 10 * 1024 * 1024);
  assert.equal(parseSize("0"), undefined);
});

test("one-shot export writes the window oldest first, across roots and sessions", async (t) => {
  const a = await tempRoot(t);
  const b = await tempRoot(t);
  await fs.writeFile(sessionFile(a, "s1"), lines([ev("e2", "s1", "2026-11-06T10:02:00Z"), ev("e0", "s1", "2026-11-01T00:00:00Z")]));
  await fs.writeFile(sessionFile(b, "s2"), lines([ev("e1", "s2", "2026-11-06T10:01:00Z")]) + "{broken");
  const out = path.join(a, "out", "events.jsonl");
  const io = fakeIo();
  const code = await runExport(["--out", out, "--since", "2026-11-05"], { roots: [a, b], io });
  assert.equal(code, 0);
  const rows = await readLines(out);
  assert.deepEqual(rows.map((r) => r.event_id), ["e1", "e2"]);
  assert.equal(rows[0].export_schema, "omnodex.event/1");
  assert.match(io.err.join("\n"), /wrote 2 event/);
});

test("MUST_NOT: the default export carries no tool parameters; --include adds them", async (t) => {
  const root = await tempRoot(t);
  await fs.writeFile(sessionFile(root, "s1"), lines([ev("e1", "s1", "2026-11-06T10:00:00Z")]));
  const out = path.join(root, "o.jsonl");
  await runExport(["--out", out], { roots: [root], io: fakeIo() });
  assert.ok(!(await fs.readFile(out, "utf8")).includes("PRIVATE"));
  await runExport(["--out", out, "--include", "parameters", "--format", "ocsf"], { roots: [root], io: fakeIo() });
  const [row] = await readLines(out);
  assert.equal(row.class_uid, 6003);
  assert.equal(row.unmapped.parameters.command, "echo PRIVATE");
});

test("--until bounds the window; --out - writes to standard output only", async (t) => {
  const root = await tempRoot(t);
  await fs.writeFile(sessionFile(root, "s1"), lines([ev("e1", "s1", "2026-11-06T10:00:00Z"), ev("e2", "s1", "2026-11-06T11:00:00Z")]));
  const io = fakeIo();
  assert.equal(await runExport(["--out", "-", "--until", "2026-11-06T10:30:00Z"], { roots: [root], io }), 0);
  const rows = io.out.join("").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  assert.deepEqual(rows.map((r) => r.event_id), ["e1"]);
  assert.ok(io.err.every((l) => l.startsWith("[export]")));
});

test("a bad argument exits 1 and writes nothing", async (t) => {
  const root = await tempRoot(t);
  const io = fakeIo();
  assert.equal(await runExport(["--format", "ocsf"], { roots: [root], io }), 1);
  assert.equal(io.out.length, 0);
  assert.match(io.err[0], /--out/);
});

async function follow(args, deps, run) {
  const stop = new AbortController();
  const done = runExport(args, { ...deps, signal: stop.signal, pollMs: 20 });
  await run();
  stop.abort();
  return done;
}
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

test("--follow with no --since starts at the end and appends only new events", async (t) => {
  const root = await tempRoot(t);
  const file = sessionFile(root, "s1");
  await fs.writeFile(file, lines([ev("old", "s1", "2026-11-06T09:00:00Z")]));
  const out = path.join(root, "feed.jsonl");
  await follow(["--out", out, "--follow"], { roots: [root], io: fakeIo() }, async () => {
    await settle();
    await fs.appendFile(file, lines([ev("new1", "s1", "2026-11-06T09:01:00Z")]));
    // A new session file is read from its first line.
    await fs.writeFile(sessionFile(root, "s2"), lines([ev("new2", "s2", "2026-11-06T09:02:00Z")]));
    await settle(300);
  });
  const ids = (await readLines(out)).map((r) => r.event_id).sort();
  assert.deepEqual(ids, ["new1", "new2"]);
});

test("--follow with --since exports that history first", async (t) => {
  const root = await tempRoot(t);
  await fs.writeFile(sessionFile(root, "s1"), lines([ev("a", "s1", "2026-11-01T00:00:00Z"), ev("b", "s1", "2026-11-06T09:00:00Z")]));
  const out = path.join(root, "feed.jsonl");
  await follow(["--out", out, "--follow", "--since", "2026-11-05"], { roots: [root], io: fakeIo() }, () => settle(250));
  assert.deepEqual((await readLines(out)).map((r) => r.event_id), ["b"]);
});

test("a restart resumes from the watermark without repeating events", async (t) => {
  const root = await tempRoot(t);
  const file = sessionFile(root, "s1");
  await fs.writeFile(file, lines([ev("e1", "s1", "2026-11-06T09:00:00Z")]));
  const out = path.join(root, "feed.jsonl");
  const args = ["--out", out, "--follow", "--since", "2026-11-05"];
  await follow(args, { roots: [root], io: fakeIo() }, () => settle(250));
  // Events arrive while the exporter is not running, and a line is half written.
  await fs.appendFile(file, lines([ev("e2", "s1", "2026-11-06T09:05:00Z")]) + '{"event_id":"e3"');
  const io = fakeIo();
  await follow(args, { roots: [root], io }, async () => {
    await settle(250);
    await fs.appendFile(file, `,"session_id":"s1","event_type":"tool.invoked","occurred_at":"2026-11-06T09:06:00Z","recorded_at":"2026-11-06T09:06:00Z"}\n`);
    await settle(250);
  });
  assert.match(io.err.join("\n"), /resuming/);
  assert.deepEqual((await readLines(out)).map((r) => r.event_id), ["e1", "e2", "e3"]);
});

test("rotation moves the file aside by size and keeps a bounded number", async (t) => {
  const root = await tempRoot(t);
  const file = path.join(root, "r", "feed.jsonl");
  const rot = new RotatingFile(file, 100, 2);
  const line = (c) => c.repeat(59) + "\n";
  for (const c of ["a", "b", "c", "d"]) await rot.append(line(c));
  assert.equal((await fs.readFile(file, "utf8"))[0], "d");
  assert.equal((await fs.readFile(`${file}.1`, "utf8"))[0], "c");
  assert.equal((await fs.readFile(`${file}.2`, "utf8"))[0], "b");
  await assert.rejects(fs.access(`${file}.3`));
});

test("rotation with --keep 0 discards the old file", async (t) => {
  const root = await tempRoot(t);
  const file = path.join(root, "feed.jsonl");
  const rot = new RotatingFile(file, 50, 0);
  await rot.append("x".repeat(40) + "\n");
  await rot.append("y".repeat(40) + "\n");
  assert.equal((await fs.readFile(file, "utf8"))[0], "y");
  await assert.rejects(fs.access(`${file}.1`));
});
