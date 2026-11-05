/**
 * RULE_WATCHED_PATH: a tool call that changes, moves or deletes a path the
 * user chose to watch raises a finding; reading it never does.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { RuleEngine } from "../../dist/engine.js";
import { createEvaluator } from "../../dist/evaluator.js";
import { RULE_WATCHED_PATH, COMMUNITY_RULES } from "../../dist/rules/index.js";
import { evaluatePolicy } from "../../dist/policy.js";
import { RuleRegistry } from "../../dist/registry.js";

const engine = new RuleEngine([RULE_WATCHED_PATH]);
const HOME = "/home/case";
const CWD = "/home/case/repo";

function watch(p, extra = {}) {
  return {
    id: `w-${p}`,
    match: { rule_id: RULE_WATCHED_PATH.rule_id, target: { access: "write", path: p }, ...(extra.project ? { project: extra.project } : {}) },
    effect: { severity: "HIGH" },
    created_at: extra.created_at ?? "2026-01-01T00:00:00.000Z",
  };
}

function call(tool_name, parameters, extra = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-06-02T00:00:00.000Z",
    recorded_at: "2026-06-02T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name,
    mcp_server: "builtin",
    cwd: CWD,
    parameters,
    ...extra,
  };
}

const bash = (command, extra) => call("Bash", { command }, extra);
const judge = (event, watches) => engine.evaluate(event, { home: HOME, watches });

const ALERTS = [watch("/home/case/repo/config/alerts.yml")];
const FOLDER = [watch("/home/case/repo/monitoring")];

describe("RULE_WATCHED_PATH", () => {
  it("is a HIGH community rule, in the shipped set, that blocks nothing by itself", () => {
    assert.equal(RULE_WATCHED_PATH.severity, "HIGH");
    assert.equal(RULE_WATCHED_PATH.tier, "community");
    assert.equal(RULE_WATCHED_PATH.blocking_hint, undefined);
    assert.ok(COMMUNITY_RULES.includes(RULE_WATCHED_PATH));
  });

  const MUST_FIRE = [
    ["Write names the file", call("Write", { file_path: "/home/case/repo/config/alerts.yml", content: "x" }), ALERTS],
    ["Edit with a relative path", call("Edit", { file_path: "config/alerts.yml", old_string: "a", new_string: "b" }), ALERTS],
    ["apply_patch update", call("apply_patch", { input: "*** Begin Patch\n*** Update File: config/alerts.yml\n*** End Patch" }), ALERTS],
    ["apply_patch delete", call("apply_patch", { input: "*** Begin Patch\n*** Delete File: config/alerts.yml\n*** End Patch" }), ALERTS],
    ["MCP write_file", call("mcp__fs__write_file", { path: "/home/case/repo/config/alerts.yml", content: "x" }), ALERTS],
    ["MCP move_file source", call("mcp__fs__move_file", { source: "/home/case/repo/config/alerts.yml", destination: "/tmp/a" }), ALERTS],
    ["MCP delete_file", call("mcp__fs__delete_file", { path: "/home/case/repo/config/alerts.yml" }), ALERTS],
    ["redirect", bash("echo off > config/alerts.yml"), ALERTS],
    ["append", bash("echo off >> /home/case/repo/config/alerts.yml"), ALERTS],
    ["tee", bash("echo off | tee config/alerts.yml"), ALERTS],
    ["cp over it", bash("cp /tmp/empty config/alerts.yml"), ALERTS],
    ["mv away", bash("mv config/alerts.yml /tmp/alerts.yml"), ALERTS],
    ["mv onto it", bash("mv /tmp/alerts.yml config/alerts.yml"), ALERTS],
    ["rm", bash("rm -f config/alerts.yml"), ALERTS],
    ["rm after another command", bash("ls && rm config/alerts.yml"), ALERTS],
    ["sudo rm", bash("sudo rm config/alerts.yml"), ALERTS],
    ["rm of a folder holding it", bash("rm -rf config"), ALERTS],
    ["mv of a folder holding it", bash("mv config /tmp/config"), ALERTS],
    ["rm with the command's own wildcard", bash("rm config/*.yml"), ALERTS],
    ["sed in place", bash("sed -i 's/on/off/' config/alerts.yml"), ALERTS],
    ["truncate", bash("truncate -s 0 config/alerts.yml"), ALERTS],
    ["chmod", bash("chmod 000 config/alerts.yml"), ALERTS],
    ["git rm", bash("git rm config/alerts.yml"), ALERTS],
    ["git checkout paths", bash("git checkout -- config/alerts.yml"), ALERTS],
    ["git restore", bash("git restore config/alerts.yml"), ALERTS],
    ["find delete", bash("find config/alerts.yml -delete"), ALERTS],
    ["inline python write", bash(`python3 -c "open('config/alerts.yml','w').write('')"`), ALERTS],
    ["inline node write", bash(`node -e "require('fs').writeFileSync('config/alerts.yml','')"`), ALERTS],
    ["PowerShell Remove-Item", call("powershell", { command: "Remove-Item -Force config/alerts.yml" }), ALERTS],
    ["PowerShell Set-Content", call("powershell", { command: "Set-Content config/alerts.yml off" }), ALERTS],
    ["a file under a watched folder", call("Write", { file_path: "/home/case/repo/monitoring/check.py", content: "" }), FOLDER],
    ["a file deep under a watched folder", bash("rm monitoring/a/b/check.py"), FOLDER],
    ["the watched folder itself", bash("rm -rf monitoring"), FOLDER],
    ["a glob on one segment", bash("rm config/alerts.yml"), [watch("/home/case/repo/config/*.yml")]],
    ["a glob across segments", call("Write", { file_path: "/home/case/repo/a/b/alerts.yml", content: "" }), [watch("/home/case/repo/**/alerts.yml")]],
    ["a glob anywhere on the machine", call("Write", { file_path: "/srv/other/alerts.yml", content: "" }), [watch("**/alerts.yml")]],
    ["a file under what a glob matches", call("Write", { file_path: "/home/case/repo/svc/alerts/rules.yml", content: "" }), [watch("/home/case/repo/*/alerts")]],
    ["a ~ watch", call("Write", { file_path: "/home/case/.config/alerts.yml", content: "" }), [watch("~/.config/alerts.yml")]],
    ["$HOME in a command", bash("rm $HOME/.config/alerts.yml"), [watch("~/.config/alerts.yml")]],
    ["rm of a folder a glob starts in", bash("rm -rf config"), [watch("/home/case/repo/config/*.yml")]],
    ["in its project", bash("rm config/alerts.yml"), [watch("config/alerts.yml", { project: CWD })]],
  ];
  for (const [name, event, watches] of MUST_FIRE) {
    it(`MUST_FIRE: ${name}`, () => {
      const found = judge(event, watches);
      assert.equal(found.length, 1, name);
      assert.equal(found[0].rule_id, "RULE_WATCHED_PATH");
      assert.equal(found[0].severity, "HIGH");
    });
  }

  const MUST_NOT_FIRE = [
    ["Read", call("Read", { file_path: "/home/case/repo/config/alerts.yml" }), ALERTS],
    ["cat", bash("cat config/alerts.yml"), ALERTS],
    ["grep", bash("grep -n off config/alerts.yml"), ALERTS],
    ["ls", bash("ls -la config"), ALERTS],
    ["wc", bash("wc -l config/alerts.yml"), ALERTS],
    ["git diff", bash("git diff config/alerts.yml"), ALERTS],
    ["git log", bash("git log -- config/alerts.yml"), ALERTS],
    ["cp from it", bash("cp config/alerts.yml /tmp/copy.yml"), ALERTS],
    ["redirect from it", bash("sort < config/alerts.yml > /tmp/sorted"), ALERTS],
    ["sed without -i", bash("sed 's/a/b/' config/alerts.yml"), ALERTS],
    ["find without delete", bash("find config -name alerts.yml"), ALERTS],
    ["inline python read", bash(`python3 -c "print(open('config/alerts.yml').read())"`), ALERTS],
    ["echoing its name", bash("echo config/alerts.yml"), ALERTS],
    ["naming it in a message", bash(`git commit -m "rm config/alerts.yml > old"`), ALERTS],
    ["a heredoc mentioning it", bash("cat > /tmp/notes <<EOF\nrm config/alerts.yml\nEOF"), ALERTS],
    ["writing a neighbor", call("Write", { file_path: "/home/case/repo/config/alerts.yml.bak", content: "" }), ALERTS],
    ["rm of a sibling folder", bash("rm -rf configs"), ALERTS],
    ["rm with a wildcard that misses it", bash("rm config/*.log"), ALERTS],
    ["writing inside a folder a removed path does not hold", bash("rm monitoring-old/a"), FOLDER],
    ["a glob on one segment does not cross", call("Write", { file_path: "/home/case/repo/config/sub/a.yml", content: "" }), [watch("/home/case/repo/config/?.yml")]],
    ["another project", bash("rm config/alerts.yml"), [watch("config/alerts.yml", { project: "/home/case/other" })]],
    ["a call from before the watch", bash("rm config/alerts.yml"), [watch("/home/case/repo/config/alerts.yml", { created_at: "2026-07-01T00:00:00.000Z" })]],
    ["no watches", bash("rm config/alerts.yml"), []],
  ];
  for (const [name, event, watches] of MUST_NOT_FIRE) {
    it(`MUST_NOT_FIRE: ${name}`, () => assert.deepEqual(judge(event, watches), [], name));
  }
});

describe("watch entries and guardrails", () => {
  const finding = { rule_id: "RULE_WATCHED_PATH", category: "self_protection", severity: "HIGH" };
  const blocking = { ...watch("/home/case/repo/config/*.yml"), effect: { verdict: "deny" } };
  const verdictFor = (event, machine) => evaluatePolicy({ finding, call: event, machine, home: HOME }).verdict;

  it("a watch with --block denies a glob match, a delete and a removed parent", () => {
    assert.equal(verdictFor(call("Write", { file_path: "config/a.yml", content: "" }), [blocking]), "deny");
    assert.equal(verdictFor(bash("rm config/a.yml"), [blocking]), "deny");
    assert.equal(verdictFor(bash("rm -rf config"), [blocking]), "deny");
  });

  it("a plain watch does not hold the call", () => {
    assert.equal(verdictFor(bash("rm config/alerts.yml"), ALERTS), "alert_only");
  });

  it("a watched path's allow covers the whole call or nothing", () => {
    const allow = { ...watch("/home/case/repo/config"), effect: { verdict: "allow" } };
    const deny = { ...watch("/home/case/repo/config/alerts.yml"), id: "d", effect: { verdict: "deny" } };
    assert.equal(verdictFor(bash("rm config/a.yml /tmp/other"), [allow]), "alert_only");
    assert.equal(evaluatePolicy({ finding, call: bash("rm config/a.yml"), machine: [allow], home: HOME }).decided.verdict?.entry, allow);
    assert.equal(verdictFor(bash("rm config/alerts.yml"), [allow, deny]), "deny");
  });
});

describe("the evaluator reads watches from the user's files", () => {
  const registry = new RuleRegistry([RULE_WATCHED_PATH]);
  const make = (home) => {
    let n = 0;
    return createEvaluator({ host: "hook", home, registry, newEventId: () => `e${n++}`, fingerprint: null, workspaceRoots: () => [] });
  };
  const write = (home, entries) =>
    fs.writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement: { policy: entries } }));

  it("fires from the machine's file, notices a new watch, and ignores a non-watch entry", async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-watch-case-"));
    try {
      const ev = make(home);
      assert.deepEqual(ev.evaluate(bash("rm /srv/case/alerts.yml", { tool_call_id: "a" })), []);
      await write(home, [{ ...watch("/srv/case/alerts.yml"), id: "w1", effect: { verdict: "allow" } }]);
      assert.deepEqual(ev.evaluate(bash("rm /srv/case/alerts.yml", { tool_call_id: "b" })), []);
      await new Promise((r) => setTimeout(r, 30));
      await write(home, [{ ...watch("/srv/case/alerts.yml"), id: "w1" }]);
      const found = ev.evaluate(bash("rm /srv/case/alerts.yml", { tool_call_id: "c" }));
      assert.equal(found.length, 1);
      assert.match(found[0].description, /alerts\.yml, a path you are watching/);
      assert.deepEqual(ev.evaluate(call("Read", { file_path: "/srv/case/alerts.yml" }, { tool_call_id: "d" })), []);
    } finally {
      await fs.rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });

  it("fires from the account's pulled policy", async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-watch-case-"));
    try {
      await fs.writeFile(path.join(home, "account-policy.json"), JSON.stringify({ version: 1, entries: [{ ...watch("/srv/case/alerts.yml"), id: "a1" }] }));
      assert.equal(make(home).evaluate(bash("rm /srv/case/alerts.yml")).length, 1);
    } finally {
      await fs.rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });
});
