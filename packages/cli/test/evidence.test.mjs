// The signed evidence chain: canonical form, seals, bundles and verify.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { canonicalize, eventHash, foldHead, GENESIS_HEAD, keyIdFor, publicKeyHex, sha256Hex } from "../dist/evidence/canonical.js";
import { sealPending, readSeals, loadOrCreateKey, signBody } from "../dist/evidence/seal.js";
import { buildBundle } from "../dist/evidence/bundle.js";
import { verifyBundle } from "../dist/evidence/verify.js";
import { runExport } from "../dist/export-command.js";
import { runSeal, runVerify } from "../dist/evidence/commands.js";

async function setup(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-evidence-"));
  await fs.mkdir(path.join(home, "event-log", "sessions"), { recursive: true });
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

const ev = (id, session, at, over = {}) => ({
  schema_version: 1, event_id: id, session_id: session, event_type: "tool.invoked",
  occurred_at: at, recorded_at: at, interceptor: "claude-code-hook",
  tool_call_id: `c-${id}`, tool_name: "Bash", mcp_server: "builtin", parameters: { command: "ls" }, ...over,
});
const file = (home, session) => path.join(home, "event-log", "sessions", `${session}.jsonl`);
const add = (home, session, events) => fs.appendFile(file(home, session), events.map((e) => JSON.stringify(e)).join("\n") + "\n");

/** Two seals over five events, one of them a capture pause. */
async function sealedHome(t) {
  const home = await setup(t);
  await add(home, "s1", [ev("e1", "s1", "2026-11-06T10:00:00Z"), ev("e2", "s1", "2026-11-06T10:01:00Z")]);
  await add(home, "omnodex-capture-control", [ev("p1", "omnodex-capture-control", "2026-11-06T10:02:00Z", { event_type: "capture.paused", kind: "record", parameters: undefined })]);
  assert.equal((await sealPending({ home, roots: [home] })).sealed, true);
  await add(home, "s2", [ev("e3", "s2", "2026-11-06T11:00:00Z"), ev("e4", "s2", "2026-11-06T11:01:00Z")]);
  assert.equal((await sealPending({ home, roots: [home] })).seq, 2);
  return home;
}

const bundleLines = async (home) => (await buildBundle({ home, roots: [home] })).text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
const toText = (rows) => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
const codes = (report) => report.problems.map((p) => p.code);

test("canonical form follows RFC 8785: sorted keys, ES numbers, no whitespace", () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, "x"], "é": 2, A: 0 }), '{"A":0,"a":[true,null,"x"],"b":1,"é":2}');
  assert.equal(canonicalize({ n: [1e21, 0.000001, 1e-7, -0, 4.5, 100] }), '{"n":[1e+21,0.000001,1e-7,0,4.5,100]}');
  assert.equal(canonicalize("a\"\\\n\u0007"), '"a\\"\\\\\\n\\u0007"');
  assert.equal(canonicalize({ a: undefined, b: 1 }), '{"b":1}');
  assert.throws(() => canonicalize({ a: Infinity }));
  assert.equal(eventHash({ b: 1, a: 2 }), eventHash({ a: 2, b: 1 }));
  assert.equal(foldHead(GENESIS_HEAD, sha256Hex("x")).length, 64);
});

test("the first seal chains from genesis; the second continues from the first", async (t) => {
  const home = await sealedHome(t);
  const [s1, s2] = await readSeals(home);
  assert.equal(s1.prev_head, GENESIS_HEAD);
  assert.deepEqual(s1.event_ids, ["e1", "e2", "p1"]);
  assert.equal(s1.count, 3);
  assert.equal(s2.prev_head, s1.head);
  assert.deepEqual(s2.event_ids, ["e3", "e4"]);
  let head = GENESIS_HEAD;
  for (const e of [ev("e1", "s1", "2026-11-06T10:00:00Z"), ev("e2", "s1", "2026-11-06T10:01:00Z")]) head = foldHead(head, eventHash(e));
  assert.notEqual(head, s1.head); // the pause marker is folded in too
  assert.equal(s1.key_id, (await loadOrCreateKey(home)).key_id);
});

test("sealing again with nothing new writes nothing; new events go in the next seal once", async (t) => {
  const home = await sealedHome(t);
  assert.deepEqual(await sealPending({ home, roots: [home] }), { sealed: false, reason: "nothing-new" });
  await add(home, "s1", [ev("e5", "s1", "2026-11-06T12:00:00Z")]);
  const r = await sealPending({ home, roots: [home] });
  assert.equal(r.count, 1);
  const seals = await readSeals(home);
  const ids = seals.flatMap((s) => s.event_ids);
  assert.equal(new Set(ids).size, ids.length);
});

test("a half-written line is left for the next seal", async (t) => {
  const home = await setup(t);
  await add(home, "s1", [ev("e1", "s1", "2026-11-06T10:00:00Z")]);
  await fs.appendFile(file(home, "s1"), '{"event_id":"e2"');
  assert.equal((await sealPending({ home, roots: [home] })).count, 1);
  await fs.appendFile(file(home, "s1"), `,"event_type":"x","recorded_at":"2026-11-06T10:05:00Z"}\n`);
  const next = await sealPending({ home, roots: [home] });
  assert.equal(next.count, 1);
  assert.deepEqual((await readSeals(home))[1].event_ids, ["e2"]);
});

test("a seal busy elsewhere is reported, not run twice", async (t) => {
  const home = await setup(t);
  await add(home, "s1", [ev("e1", "s1", "2026-11-06T10:00:00Z")]);
  await fs.writeFile(path.join(home, "seal.lock"), "");
  assert.deepEqual(await sealPending({ home, roots: [home] }), { sealed: false, reason: "busy" });
  // A lock left by a crashed process goes stale.
  const old = Date.now() - 10 * 60_000;
  await fs.utimes(path.join(home, "seal.lock"), old / 1000, old / 1000);
  assert.equal((await sealPending({ home, roots: [home] })).sealed, true);
});

test("seals stay out of the session files and the key file is private to the home", async (t) => {
  const home = await sealedHome(t);
  const names = await fs.readdir(path.join(home, "event-log", "sessions"));
  assert.deepEqual(names.sort(), ["omnodex-capture-control.jsonl", "s1.jsonl", "s2.jsonl"]);
  const key = JSON.parse(await fs.readFile(path.join(home, "signing", "seal-key.json"), "utf8"));
  assert.equal(key.key_id, keyIdFor(key.public_key));
  const again = await loadOrCreateKey(home);
  assert.equal(again.public_key, key.public_key);
});

test("MUST: a clean bundle verifies, and lists the capture pause", async (t) => {
  const home = await sealedHome(t);
  const report = verifyBundle(toText(await bundleLines(home)));
  assert.equal(report.ok, true, JSON.stringify(report.problems));
  assert.equal(report.seals, 2);
  assert.equal(report.events, 5);
  assert.equal(report.keys.length, 1);
  assert.deepEqual(report.integrity.map((i) => i.event_type), ["capture.paused"]);
  assert.match(report.integrity[0].detail, /record/);
  // Trusting the right key keeps it valid, by id or by public key.
  const key = await loadOrCreateKey(home);
  assert.equal(verifyBundle(toText(await bundleLines(home)), { trustedKeys: [key.key_id] }).ok, true);
  assert.equal(verifyBundle(toText(await bundleLines(home)), { trustedKeys: [key.public_key] }).ok, true);
});

test("MUST_NOT: an edited event verifies as clean", async (t) => {
  const home = await sealedHome(t);
  const rows = await bundleLines(home);
  const row = rows.find((r) => r.type === "event" && r.event.event_id === "e2");
  row.event.tool_name = "Read";
  const report = verifyBundle(toText(rows));
  assert.equal(report.ok, false);
  assert.deepEqual(report.problems.map((p) => [p.code, p.event_id]), [["edited", "e2"]]);

  // Editing the recorded hash as well is still caught, against the signed head.
  row.event_hash = eventHash(row.event);
  const quiet = verifyBundle(toText(rows));
  assert.deepEqual(codes(quiet), ["edited"]);
  assert.equal(quiet.problems[0].event_id, undefined);
  assert.equal(quiet.problems[0].seal, 1);
});

test("MUST_NOT: a dropped event verifies as clean", async (t) => {
  const home = await sealedHome(t);
  const rows = (await bundleLines(home)).filter((r) => !(r.type === "event" && r.event.event_id === "e3"));
  const report = verifyBundle(toText(rows));
  assert.equal(report.ok, false);
  assert.deepEqual(report.problems.map((p) => [p.code, p.event_id, p.seal]), [["dropped", "e3", 2]]);
});

test("MUST_NOT: a reordered range verifies as clean", async (t) => {
  const home = await sealedHome(t);
  const rows = await bundleLines(home);
  const i1 = rows.findIndex((r) => r.type === "event" && r.event.event_id === "e1");
  const i2 = rows.findIndex((r) => r.type === "event" && r.event.event_id === "e2");
  [rows[i1], rows[i2]] = [rows[i2], rows[i1]];
  const report = verifyBundle(toText(rows));
  assert.equal(report.ok, false);
  assert.deepEqual(codes(report), ["reordered"]);
  assert.equal(report.problems[0].seal, 1);
});

test("MUST_NOT: an extra event slipped into a seal verifies as clean", async (t) => {
  const home = await sealedHome(t);
  const rows = await bundleLines(home);
  const at = rows.findIndex((r) => r.type === "event" && r.event.event_id === "e4");
  const forged = ev("e9", "s2", "2026-11-06T11:30:00Z");
  rows.splice(at + 1, 0, { type: "event", seal: 2, event_hash: eventHash(forged), event: forged });
  assert.deepEqual(codes(verifyBundle(toText(rows))), ["extra"]);
});

test("MUST_NOT: a wrong key verifies as clean", async (t) => {
  const home = await sealedHome(t);
  const rows = await bundleLines(home);
  // Someone else's key trusted by the auditor.
  const other = publicKeyHex(generateKeyPairSync("ed25519").privateKey);
  const report = verifyBundle(toText(rows), { trustedKeys: [other] });
  assert.equal(report.ok, false);
  assert.deepEqual(new Set(codes(report)), new Set(["key_untrusted"]));

  // A bundle re-signed by an attacker's own key fails against the real one.
  const attacker = generateKeyPairSync("ed25519");
  const apub = publicKeyHex(attacker.privateKey);
  const forged = rows.map((r) => ({ ...r }));
  forged.find((r) => r.type === "key").public_key = apub;
  const swapped = verifyBundle(toText(forged));
  assert.equal(swapped.ok, false);
  assert.ok(codes(swapped).includes("bad_signature"));

  // Swapping the key id in the seals too, and signing properly, passes only if the key is not pinned.
  const akeyId = keyIdFor(apub);
  const resigned = forged.map((r) => (r.type === "seal" ? { ...r, key_id: akeyId } : r));
  resigned.find((r) => r.type === "key").key_id = akeyId;
  for (const r of resigned.filter((x) => x.type === "seal")) {
    const { type, signature, ...body } = r;
    r.signature = signBody(body, { privateKey: attacker.privateKey });
  }
  assert.equal(verifyBundle(toText(resigned)).ok, true);
  const real = await loadOrCreateKey(home);
  const pinned = verifyBundle(toText(resigned), { trustedKeys: [real.public_key] });
  assert.equal(pinned.ok, false);
  assert.ok(codes(pinned).includes("key_untrusted"));
});

test("a changed seal, a missing seal and a broken link are each named", async (t) => {
  const home = await sealedHome(t);
  const rows = await bundleLines(home);
  const tampered = rows.map((r) => (r.type === "seal" && r.seq === 1 ? { ...r, head: "f".repeat(64) } : r));
  assert.ok(codes(verifyBundle(toText(tampered))).includes("bad_signature"));

  await add(home, "s3", [ev("e5", "s3", "2026-11-06T12:00:00Z")]);
  const three = await bundleLines(home);
  const gap = three.filter((r) => !((r.type === "seal" && r.seq === 2) || (r.type === "event" && r.seal === 2)));
  assert.deepEqual(codes(verifyBundle(toText(gap))), ["gap"]);

  const dropFirst = three.filter((r) => !((r.type === "seal" && r.seq === 1) || (r.type === "event" && r.seal === 1)));
  const partial = verifyBundle(toText(dropFirst));
  assert.equal(partial.ok, true);
  assert.match(partial.notes[0], /starts at seal 2/);
});

test("a file that is not a bundle, or has no events for a seal, is not accepted", async (t) => {
  assert.equal(verifyBundle("hello\n").ok, false);
  const home = await sealedHome(t);
  const rows = (await bundleLines(home)).filter((r) => r.type !== "event");
  assert.ok(codes(verifyBundle(toText(rows))).includes("dropped"));
});

test("a time range picks whole seals; an empty range is an error", async (t) => {
  const home = await sealedHome(t);
  const second = await buildBundle({ home, roots: [home], since: Date.parse("2026-11-06T10:30:00Z") });
  assert.equal(second.seals, 1);
  assert.equal(verifyBundle(second.text).ok, true);
  await assert.rejects(buildBundle({ home, roots: [home], since: Date.parse("2027-01-01") }), /no sealed events/);
});

test("a bundle seals what is pending first, and notes events the log lost", async (t) => {
  const home = await sealedHome(t);
  await add(home, "s3", [ev("late", "s3", "2026-11-06T13:00:00Z")]);
  const built = await buildBundle({ home, roots: [home] });
  assert.equal(built.seals, 3);
  assert.equal(built.missing.length, 0);
  await fs.rm(file(home, "s2"));
  const lost = await buildBundle({ home, roots: [home] });
  assert.deepEqual(lost.missing.sort(), ["e3", "e4"]);
  assert.deepEqual(new Set(codes(verifyBundle(lost.text))), new Set(["dropped"]));
});

test("export --bundle, seal and verify work as commands", async (t) => {
  const home = await sealedHome(t);
  const out = path.join(home, "out", "evidence.jsonl");
  const err = [];
  const io = { write: () => {}, error: (l) => err.push(l) };
  assert.equal(await runExport(["--bundle", "--out", out], { roots: [home], home, io }), 0);
  assert.match(err.join("\n"), /in full/);
  const log = [];
  const eio = { log: (l) => log.push(l), error: (l) => log.push(l) };
  assert.equal(await runVerify([out], { io: eio }), 0);
  assert.match(log[0], /^VALID/);
  assert.equal(await runVerify([out, "--key", "0".repeat(64)], { io: eio }), 2);
  assert.equal(await runVerify([], { io: eio }), 1);
  assert.equal(await runVerify([path.join(home, "missing")], { io: eio }), 1);

  // A tampered file exits 2 and --json is parseable.
  const text = (await fs.readFile(out, "utf8")).replace('"Bash"', '"Edit"');
  await fs.writeFile(out, text);
  log.length = 0;
  assert.equal(await runVerify([out, "--json"], { io: eio }), 2);
  assert.equal(JSON.parse(log.join("\n")).ok, false);

  log.length = 0;
  assert.equal(await runSeal(["key"], { home, roots: [home], io: eio }), 0);
  assert.match(log[0], /key id/);
  log.length = 0;
  assert.equal(await runSeal([], { home, roots: [home], io: eio }), 0);
  assert.match(log[0], /nothing new/);

  assert.equal(await runExport(["--bundle", "--out", out, "--follow"], { roots: [home], home, io }), 1);
  assert.equal(await runExport(["--bundle", "--out", out, "--format", "ocsf"], { roots: [home], home, io }), 1);
});
