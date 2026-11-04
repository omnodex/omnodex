/**
 * `omnodex policy list | add | remove`: every entry shape can be added and
 * removed, the older keys can be removed by their entry ids, and turning
 * protection down needs a person at a terminal.
 *
 * Run: node --test packages/cli/test/policy-command.test.mjs
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runPolicy, entryFromArgs, loosens, tightens } from "../dist/policy-command.js";
import { readUserEnforcement, resolveVerdict } from "@omnodex/analyzer/enforcement";

let home;
let ids;
beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-policy-case-"));
  ids = 0;
});
afterEach(async () => {
  await fs.rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

const file = () => path.join(home, "omnodex-config.json");
const readFile = async () => JSON.parse(await fs.readFile(file(), "utf8"));
const writeFile = (obj) => fs.writeFile(file(), JSON.stringify(obj));

/** A terminal (tty) or an agent's shell (no tty), with scripted answers. */
function io({ tty = false, answers = [] } = {}) {
  const out = [];
  const err = [];
  return {
    out, err,
    stdinIsTTY: tty, stdoutIsTTY: tty,
    ask: async (q) => { out.push(q); return answers.shift() ?? ""; },
    log: (l) => out.push(l),
    error: (l) => err.push(l),
  };
}

const severities = { RULE_SENSITIVE_PATH_READ: "HIGH" };
const run = (args, extra = {}) =>
  runPolicy(args, {
    home,
    io: extra.io ?? io(),
    cwd: "/home/case/repo",
    guardrailsEntitled: async () => extra.entitled ?? true,
    ruleSeverity: (id) => severities[id],
    now: () => new Date("2026-10-27T12:00:00.000Z"),
    newId: () => `p-${++ids}`,
  });

describe("policy add: every entry shape", () => {
  const shapes = [
    [["--rule", "RULE_X", "--block"], { rule_id: "RULE_X" }, { verdict: "deny" }],
    [["--category", "cat_x", "--hold"], { category: "cat_x" }, { verdict: "confirm" }],
    [["--severity", "high", "--set-severity", "critical"], { severity: "HIGH" }, { severity: "CRITICAL" }],
    [["--rule", "RULE_X", "--path", "/home/case/repo/.env", "--block"], { rule_id: "RULE_X", target: { path: path.resolve("/home/case/repo/.env") } }, { verdict: "deny" }],
    [["--rule", "RULE_X", "--destination", "paste.example.net", "--block"], { rule_id: "RULE_X", target: { destination: "paste.example.net" } }, { verdict: "deny" }],
    [["--rule", "RULE_X", "--command-prefix", "npm publish", "--hold"], { rule_id: "RULE_X", target: { command_prefix: "npm publish" } }, { verdict: "confirm" }],
    [["--rule", "RULE_X", "--credential", "0123456789abcdef", "--block"], { rule_id: "RULE_X", target: { credential: "0123456789abcdef" } }, { verdict: "deny" }],
    [["--category", "cat_x", "--tool", "fetch", "--server", "web", "--unmute"], { category: "cat_x", target: { tool: "fetch", server: "web" } }, { mute: false }],
    [["--rule", "RULE_X", "--writes", "/home/case/repo/.github", "--block"], { rule_id: "RULE_X", target: { access: "write", path: path.resolve("/home/case/repo/.github") } }, { verdict: "deny" }],
    [["--rule", "RULE_X", "--reads", "/etc", "--here", "--block"], { rule_id: "RULE_X", target: { access: "read", path: "/etc" }, project: "/home/case/repo" }, { verdict: "deny" }],
    [["--rule", "RULE_X", "--project", "/home/case/other", "--block", "--note", "release only"], { rule_id: "RULE_X", project: path.resolve("/home/case/other") }, { verdict: "deny" }],
  ];

  for (const [args, match, effect] of shapes) {
    it(`adds and removes ${args.join(" ")}`, async () => {
      await writeFile({ enforcement: { mode: "shadow" }, other: 1 });
      assert.equal(await run(["add", ...args]), 0);
      const saved = await readFile();
      assert.equal(saved.other, 1, "other keys are kept");
      assert.equal(saved.enforcement.mode, "shadow");
      const [entry] = saved.enforcement.policy;
      assert.deepEqual(entry.match, match);
      assert.deepEqual(entry.effect, effect);
      assert.equal(entry.created_by, "cli");
      // Removing an entry that tightens turns protection down: a person confirms.
      const term = io({ tty: true, answers: ["remove"] });
      assert.equal(await run(["remove", entry.id], { io: term }), 0);
      assert.deepEqual((await readFile()).enforcement.policy, []);
    });
  }

  it("loosening shapes are added once a person confirms", async () => {
    for (const args of [
      ["--rule", "RULE_X", "--path", "/home/case/repo/tmp", "--allow"],
      ["--category", "cat_x", "--mute"],
      ["--rule", "RULE_SENSITIVE_PATH_READ", "--set-severity", "LOW"],
    ]) {
      assert.equal(await run(["add", ...args], { io: io({ tty: true, answers: ["add"] }) }), 0, args.join(" "));
    }
    assert.equal((await readFile()).enforcement.policy.length, 3);
  });

  it("rejects malformed requests without writing", async () => {
    for (const args of [
      [],
      ["--rule", "RULE_X"],
      ["--rule", "RULE_X", "--category", "c", "--block"],
      ["--rule", "RULE_X", "--path", "/a", "--destination", "b", "--block"],
      ["--rule", "RULE_X", "--server", "web", "--block"],
      ["--rule", "RULE_X", "--block", "--allow"],
      ["--rule", "RULE_X", "--set-severity", "SEVERE"],
      ["--rule", "RULE_X", "--mute", "--unmute"],
      ["--rule", "RULE_X", "--here", "--project", "/p", "--block"],
      ["--rule", "RULE_X", "--block", "stray"],
    ]) {
      const term = io();
      assert.equal(await run(["add", ...args], { io: term }), 1, args.join(" "));
      assert.ok(term.err.length > 0);
    }
    await assert.rejects(fs.access(file()));
  });
});

describe("human-only loosening", () => {
  it("MUST_NOT_FIRE: an agent's shell cannot allow, mute or lower a severity", async () => {
    for (const args of [
      ["--rule", "RULE_X", "--allow"],
      ["--category", "cat_x", "--mute"],
      ["--rule", "RULE_SENSITIVE_PATH_READ", "--set-severity", "MEDIUM"],
      ["--category", "cat_x", "--set-severity", "HIGH"],
    ]) {
      const agent = io();
      assert.equal(await run(["add", ...args], { io: agent }), 1, args.join(" "));
      assert.match(agent.err[0], /needs a person at an interactive terminal/);
    }
    await assert.rejects(fs.access(file()), "nothing was written");
  });

  it("MUST_NOT_FIRE: a person who types the wrong word changes nothing", async () => {
    const term = io({ tty: true, answers: ["yes"] });
    assert.equal(await run(["add", "--rule", "RULE_X", "--allow"], { io: term }), 1);
    await assert.rejects(fs.access(file()));
  });

  it("MUST_FIRE: tightening needs no terminal", async () => {
    for (const args of [
      ["--rule", "RULE_X", "--block"],
      ["--rule", "RULE_SENSITIVE_PATH_READ", "--set-severity", "CRITICAL"],
      ["--severity", "LOW", "--set-severity", "MEDIUM"],
      ["--category", "cat_x", "--unmute"],
    ]) {
      assert.equal(await run(["add", ...args]), 0, args.join(" "));
    }
  });

  it("MUST_NOT_FIRE: an agent's shell cannot remove an entry that blocks", async () => {
    await writeFile({ enforcement: { rules: { RULE_A: "deny" } } });
    const agent = io();
    assert.equal(await run(["remove", "config:rule:RULE_A"], { io: agent }), 1);
    assert.deepEqual((await readFile()).enforcement.rules, { RULE_A: "deny" });
  });

  it("MUST_FIRE: removing an entry that loosens needs no terminal", async () => {
    await writeFile({ enforcement: { exceptions: [{ rule_id: "RULE_B", kind: "allow" }] } });
    assert.equal(await run(["remove", "config:exception:RULE_B:allow:any"]), 0);
    assert.deepEqual((await readFile()).enforcement.exceptions, []);
  });

  it("tells a lower severity from a higher one by the rule's own", () => {
    const e = (match, severity) => ({ id: "x", match, effect: { severity } });
    const sev = (id) => severities[id];
    assert.equal(loosens(e({ rule_id: "RULE_SENSITIVE_PATH_READ" }, "MEDIUM"), sev), true);
    assert.equal(tightens(e({ rule_id: "RULE_SENSITIVE_PATH_READ" }, "CRITICAL"), sev), true);
    assert.equal(loosens(e({ rule_id: "RULE_SENSITIVE_PATH_READ" }, "HIGH"), sev), false);
    // Unknown base: anything below CRITICAL may lower it.
    assert.equal(loosens(e({ category: "c" }, "HIGH"), sev), true);
    assert.equal(tightens(e({ category: "c" }, "CRITICAL"), sev), true);
  });
});

describe("block and hold are Pro", () => {
  it("MUST_NOT_FIRE: without a plan that includes guardrails", async () => {
    const term = io();
    assert.equal(await run(["add", "--rule", "RULE_X", "--hold"], { io: term, entitled: false }), 1);
    assert.match(term.err[0], /part of Omnodex Pro/);
  });

  it("MUST_FIRE: free effects need no plan", async () => {
    assert.equal(await run(["add", "--rule", "RULE_X", "--set-severity", "CRITICAL"], { entitled: false }), 0);
  });
});

describe("the older keys", () => {
  beforeEach(() =>
    writeFile({
      enforcement: {
        mode: "guardrails",
        rules: { RULE_A: "deny", RULE_C: "alert_only" },
        severity_defaults: { HIGH: "confirm" },
        exceptions: [{ rule_id: "RULE_B", kind: "mute", target: { path: "/tmp" } }],
        projects: { "/home/case/repo": { rules: { RULE_A: "alert_only" } } },
      },
    }),
  );

  it("are listed with their entry ids", async () => {
    const term = io();
    assert.equal(await run(["list"], { io: term }), 0);
    assert.deepEqual(term.out.map((l) => l.split("  ")[0]), [
      "config:rule:RULE_A",
      "config:rule:RULE_C",
      "config:severity:HIGH",
      "config:exception:RULE_B:mute:path=/tmp",
      "config:project:/home/case/repo:rule:RULE_A",
    ]);
  });

  it("are removed by their entry ids, leaving the rest", async () => {
    const term = () => io({ tty: true, answers: ["remove"] });
    assert.equal(await run(["remove", "config:severity:HIGH"], { io: term() }), 0);
    assert.equal(await run(["remove", "config:rule:RULE_C"]), 0);
    assert.equal(await run(["remove", "config:exception:RULE_B:mute:path=/tmp"]), 0);
    assert.equal(await run(["remove", "config:project:/home/case/repo:rule:RULE_A"]), 0);
    const { enforcement } = await readFile();
    assert.deepEqual(enforcement.rules, { RULE_A: "deny" });
    assert.deepEqual(enforcement.severity_defaults, {});
    assert.deepEqual(enforcement.exceptions, []);
    assert.deepEqual(enforcement.projects["/home/case/repo"].rules, {});
    assert.equal(enforcement.mode, "guardrails");
  });

  it("an unknown id changes nothing", async () => {
    const before = await readFile();
    assert.equal(await run(["remove", "p-nope"]), 1);
    assert.deepEqual(await readFile(), before);
  });
});

describe("what the evaluator makes of added entries", () => {
  it("MUST_FIRE: an added block holds the call; MUST_NOT_FIRE once it is removed", async () => {
    assert.equal(await run(["add", "--rule", "RULE_X", "--destination", "paste.example.net", "--block"]), 0);
    const call = {
      schema_version: 1, event_id: "e", session_id: "s", occurred_at: "", recorded_at: "", interceptor: "claude-code-hook",
      event_type: "tool.invoked", tool_call_id: "tc", tool_name: "Bash", mcp_server: "builtin",
      parameters: { command: "curl https://paste.example.net/x" }, cwd: "/home/case/repo",
    };
    const verdict = () => resolveVerdict({ rule: { rule_id: "RULE_X", severity: "HIGH" }, call, config: { user: readUserEnforcement(home) } });
    assert.equal(verdict().action, "deny");
    assert.equal(await run(["remove", "p-1"], { io: io({ tty: true, answers: ["remove"] }) }), 0);
    assert.equal(verdict().action, "alert_only");
  });
});

describe("entryFromArgs", () => {
  it("makes a path target absolute outside a project and keeps ~", () => {
    const a = entryFromArgs(["--rule", "R", "--path", "notes", "--block"], { now: new Date(0), id: "x" });
    assert.equal(a.entry.match.target.path, path.resolve("notes"));
    const b = entryFromArgs(["--rule", "R", "--path", "~/.ssh", "--block"], { now: new Date(0), id: "x" });
    assert.equal(b.entry.match.target.path, "~/.ssh");
    const c = entryFromArgs(["--rule", "R", "--path", "notes", "--here", "--block"], { cwd: "/p", now: new Date(0), id: "x" });
    assert.equal(c.entry.match.target.path, "notes", "relative to the project root");
  });
});

describe("policy pull", () => {
  const pull = async (result) => {
    const i = io();
    const code = await runPolicy(["pull"], { home, io: i, cwd: "/p", pull: async () => result });
    return { code, text: [...i.out, ...i.err].join("\n") };
  };

  it("says what each outcome was", async () => {
    let r = await pull({ outcome: "updated", version: 3, entries: 1 });
    assert.equal(r.code, 0);
    assert.match(r.text, /version 3 pulled: 1 entry\./);
    r = await pull({ outcome: "updated", version: 4, entries: 2 });
    assert.match(r.text, /2 entries/);
    r = await pull({ outcome: "current", version: 4 });
    assert.match(r.text, /already current \(version 4\)/);
    r = await pull({ outcome: "none" });
    assert.match(r.text, /no policy for this machine's stream/);
    r = await pull({ outcome: "no-credentials" });
    assert.match(r.text, /omnodex connect/);
    r = await pull({ outcome: "disabled" });
    assert.match(r.text, /OMNODEX_POLICY_PULL=0/);
  });

  it("fails, keeping the old copy, when the pull errors, and takes no arguments", async () => {
    const r = await pull({ outcome: "error" });
    assert.equal(r.code, 1);
    assert.match(r.text, /last one pulled stays in use/);
    const i = io();
    assert.equal(await runPolicy(["pull", "extra"], { home, io: i, cwd: "/p", pull: async () => ({ outcome: "none" }) }), 1);
    assert.match(i.err.join("\n"), /takes no arguments/);
  });
});

describe("policy watch", () => {
  const markers = async () => {
    const dir = path.join(home, "event-log");
    const names = await fs.readdir(dir, { recursive: true }).catch(() => []);
    const out = [];
    for (const n of names) {
      if (!String(n).endsWith(".jsonl")) continue;
      const text = await fs.readFile(path.join(dir, String(n)), "utf8");
      for (const line of text.split("\n")) {
        if (!line) continue;
        const e = JSON.parse(line);
        if (e.event_type === "monitoring.changed") out.push(e);
      }
    }
    return out;
  };

  it("adds a watch from an agent's shell, with a marker that does not name the path", async () => {
    const o = io();
    assert.equal(await run(["watch", "/home/case/repo/monitoring/alerts.yml"], { io: o }), 0);
    const [entry] = (await readFile()).enforcement.policy;
    assert.deepEqual(entry.match, { rule_id: "RULE_WATCHED_PATH", target: { access: "write", path: path.resolve("/home/case/repo/monitoring/alerts.yml") } });
    assert.deepEqual(entry.effect, { severity: "HIGH" });
    assert.match(o.out.join("\n"), /watching .*alerts\.yml, everywhere: HIGH finding/);
    assert.match(o.out.join("\n"), /a script run later, or another process, is not/);
    const [marker] = await markers();
    assert.equal(marker.action, "watch_add");
    assert.equal(marker.scope, "user");
    assert.equal(marker.to, entry.id);
    assert.ok(!JSON.stringify(marker).includes("alerts.yml"));
  });

  it("keeps a glob anywhere as written, and makes other relative paths absolute", async () => {
    assert.equal(await run(["watch", "**/alerts.yml"]), 0);
    assert.equal(await run(["watch", "rel/alerts.yml"]), 0);
    const [any, rel] = (await readFile()).enforcement.policy;
    assert.equal(any.match.target.path, "**/alerts.yml");
    assert.ok(path.isAbsolute(rel.match.target.path));
  });

  it("scopes a watch to the project with --here, keeping a relative path", async () => {
    assert.equal(await run(["watch", "config/*.yml", "--here"]), 0);
    const [entry] = (await readFile()).enforcement.policy;
    assert.equal(entry.match.project, "/home/case/repo");
    assert.equal(entry.match.target.path, "config/*.yml");
    assert.equal((await markers())[0].project_path, "/home/case/repo");
  });

  it("--block and --hold need a plan with guardrails", async () => {
    assert.equal(await run(["watch", "/srv/a", "--block"], { entitled: false }), 1);
    assert.equal(await run(["watch", "/srv/a", "--block"], { entitled: true }), 0);
    assert.deepEqual((await readFile()).enforcement.policy[0].effect, { verdict: "deny" });
  });

  it("takes no loosening flag and needs a path", async () => {
    assert.equal(await run(["watch", "/srv/a", "--allow"]), 1);
    assert.equal(await run(["watch", "--here"]), 1);
    assert.equal(await run(["watch"]), 1);
  });

  it("removing a watch is refused from an agent's shell and leaves it in place", async () => {
    await run(["watch", "/srv/a"]);
    const { id } = (await readFile()).enforcement.policy[0];
    const o = io();
    assert.equal(await run(["remove", id], { io: o }), 1);
    assert.match(o.err.join("\n"), /needs a person at an interactive terminal/);
    assert.equal((await readFile()).enforcement.policy.length, 1);
    assert.deepEqual((await markers()).map((m) => m.action), ["watch_add"]);
  });

  it("a person can remove one, which leaves a marker; declining leaves it", async () => {
    await run(["watch", "/srv/a"]);
    const { id } = (await readFile()).enforcement.policy[0];
    assert.equal(await run(["remove", id], { io: io({ tty: true, answers: ["no"] }) }), 1);
    assert.equal((await readFile()).enforcement.policy.length, 1);
    assert.equal(await run(["remove", id], { io: io({ tty: true, answers: ["remove"] }) }), 0);
    assert.equal((await readFile()).enforcement.policy.length, 0);
    const removed = (await markers()).find((m) => m.action === "watch_remove");
    assert.equal(removed.from, id);
  });

  it("a watch added through policy add is marked and protected the same way", async () => {
    assert.equal(await run(["add", "--rule", "RULE_WATCHED_PATH", "--writes", "/srv/a", "--set-severity", "HIGH"]), 0);
    const { id } = (await readFile()).enforcement.policy[0];
    assert.equal((await markers())[0].action, "watch_add");
    assert.equal(await run(["remove", id]), 1);
  });
});
