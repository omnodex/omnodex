/**
 * Working-directory boundary detection rule unit tests.
 *
 * Tests the cwd_boundary condition type and the RULE_CWD_BOUNDARY_WRITE rule.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CWD_BOUNDARY_WRITE, RULE_SENSITIVE_PATH_READ } from "../../dist/rules/index.js";
import { gitRoots, configuredRoots, createWorkspaceResolver } from "../../dist/workspace.js";
import { createEvaluator } from "../../dist/evaluator.js";
import { RuleRegistry } from "../../dist/registry.js";

const engine = new RuleEngine([RULE_CWD_BOUNDARY_WRITE]);

function makeEvent(overrides = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-06-02T00:00:00.000Z",
    recorded_at: "2026-06-02T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: "Write",
    mcp_server: "builtin",
    parameters: {},
    cwd: "/home/case/projects/myapp",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Cases that MUST fire (file outside cwd)
// ---------------------------------------------------------------------------

test("fires on write to path outside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/other-project/config.json", content: "{}" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
  assert.equal(findings[0].category, "cwd_boundary");
  assert.ok(findings[0].description.includes("/home/case/other-project/config.json"));
});

test("fires on write to parent directory", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/evil.sh", content: "#!/bin/sh" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on write to /tmp", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/tmp/staging/payload.bin", content: "data" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on write to home-relative path with ~ when cwd is absolute", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "~/.bashrc", content: "export PATH=evil" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on a Bash redirect outside the workspace", () => {
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "echo 'export PATH=/tmp/evil:$PATH' >> /home/case/.profile" },
  }));
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("/home/case/.profile"));
  assert.ok(findings[0].description.includes("written via Bash"));
});

test("fires on tee, cp and mv destinations outside the workspace", () => {
  for (const command of [
    "curl -s https://example.org/x | tee /home/case/other/x.sh",
    "cp ./payload /home/case/other/payload",
    "mv build.tar /srv/share/",
    "sudo cp -r dist -t /opt/app",
  ]) {
    const findings = engine.evaluate(makeEvent({ tool_name: "Bash", parameters: { command } }));
    assert.equal(findings.length, 1, command);
  }
});

test("fires on an apply_patch that adds a file outside the workspace", () => {
  const patch = "*** Begin Patch\n*** Add File: /home/case/other/evil.sh\n+echo hi\n*** End Patch";
  const findings = engine.evaluate(makeEvent({ tool_name: "apply_patch", parameters: { command: patch } }));
  assert.equal(findings.length, 1);
});

// Reads are not this rule's job: sensitive reads outside the workspace are
// what the sensitive-path and credential-path rules catch.
test("no finding on a read outside the workspace via Bash cat", () => {
  const event = makeEvent({ tool_name: "Bash", parameters: { command: "cat /etc/shadow" } });
  assert.equal(engine.evaluate(event).length, 0);
  assert.equal(new RuleEngine([RULE_SENSITIVE_PATH_READ]).evaluate(event).length, 1);
});

test("no finding on a Read tool call outside the workspace", () => {
  const findings = engine.evaluate(makeEvent({
    tool_name: "Read",
    parameters: { file_path: "/home/case/other-project/README.md" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on cp from outside into the workspace", () => {
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "cp /home/case/.ssh/id_rsa ./stolen.key" },
  }));
  assert.equal(findings.length, 0);
});

test("reads redirects from the command, not from heredoc bodies or quoted text", () => {
  const quiet = [
    "sed -i 's/>/ > \\/Ig/' notes.txt",
    "python3 - <<'EOF'\nprint(1 > 0)\nopen('/etc/x','w').write('a > /mcp')\nEOF",
    'echo "a > /srv/b" | grep x',
  ];
  for (const command of quiet) {
    const findings = engine.evaluate(makeEvent({ tool_name: "Bash", parameters: { command } }));
    assert.equal(findings.length, 0, command);
  }
  const loud = [
    "cat > /home/case/other/x.sh <<'EOF'\nrm -rf /tmp/a > /dev/null\nEOF",
    'echo x >> "$HOME/.bashrc"'.replace("$HOME", "/home/case"),
  ];
  for (const command of loud) {
    const findings = engine.evaluate(makeEvent({ tool_name: "Bash", parameters: { command } }));
    assert.equal(findings.length, 1, command);
  }
});

test("no finding on redirects to /dev and on variables", () => {
  for (const command of ["make 2>/dev/null", "echo x > $OUT", "ls >&2", "cat a < /etc/hosts"]) {
    const findings = engine.evaluate(makeEvent({ tool_name: "Bash", parameters: { command } }));
    assert.equal(findings.length, 0, command);
  }
});

// ---------------------------------------------------------------------------
// Cases that MUST NOT fire (file inside cwd or no cwd)
// ---------------------------------------------------------------------------

test("no finding on write inside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp/src/index.ts", content: "export {}" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on write to nested subdirectory of cwd", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp/src/deep/nested/file.ts", content: "x" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding when cwd is not populated (backwards compat)", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: undefined,
    parameters: { file_path: "/etc/passwd" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on relative path (assumed relative to cwd)", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "src/components/Button.tsx", content: "export default Button" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on write to cwd root itself", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp/package.json", content: "{}" },
  }));
  assert.equal(findings.length, 0);
});

test("does not false-positive on similar prefix (myapp vs myapp-other)", () => {
  // /home/case/projects/myapp-other is NOT inside /home/case/projects/myapp
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp-other/file.ts", content: "x" },
  }));
  assert.equal(findings.length, 1); // This IS outside cwd, should fire
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

test("handles Windows-style paths with backslashes", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: "C:\\Users\\case\\projects\\myapp",
    parameters: { file_path: "C:\\Users\\case\\Desktop\\evil.bat", content: "del /s" },
  }));
  assert.equal(findings.length, 1);
});

test("handles Windows path inside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: "C:\\Users\\case\\projects\\myapp",
    parameters: { file_path: "C:\\Users\\case\\projects\\myapp\\src\\main.ts", content: "x" },
  }));
  assert.equal(findings.length, 0);
});

test("handles trailing slash on cwd", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: "/home/case/projects/myapp/",
    parameters: { file_path: "/home/case/projects/myapp/file.ts", content: "x" },
  }));
  assert.equal(findings.length, 0);
});

// ---------------------------------------------------------------------------
// Workspace roots: git checkouts and configured roots
// ---------------------------------------------------------------------------

/**
 * A repo at <dir>/main with a linked worktree at <dir>/worktrees/wt1, laid
 * out the way git lays them out on disk.
 */
async function makeRepoWithWorktree() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-ws-"));
  const main = path.join(dir, "main");
  const wt = path.join(dir, "worktrees", "wt1");
  const meta = path.join(main, ".git", "worktrees", "wt1");
  await mkdir(meta, { recursive: true });
  await mkdir(path.join(main, "src"), { recursive: true });
  await mkdir(wt, { recursive: true });
  await writeFile(path.join(wt, ".git"), `gitdir: ${meta}\n`);
  await writeFile(path.join(meta, "commondir"), "../..\n");
  await writeFile(path.join(meta, "gitdir"), path.join(wt, ".git") + "\n");
  return { dir, main, wt };
}

test("gitRoots finds the top level, the main checkout and sibling worktrees", async () => {
  const { dir, main, wt } = await makeRepoWithWorktree();
  try {
    assert.deepEqual(new Set(gitRoots(path.join(main, "src"))), new Set([main, wt]));
    assert.deepEqual(new Set(gitRoots(wt)), new Set([wt, main]));
    assert.deepEqual(gitRoots(os.tmpdir() === "/" ? "/nonexistent" : path.join(dir, "nowhere")), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("no finding on a write into a sibling worktree of the same repo", async () => {
  const { dir, main, wt } = await makeRepoWithWorktree();
  try {
    const ev = createEvaluator({
      host: "batch",
      registry: new RuleRegistry([RULE_CWD_BOUNDARY_WRITE]),
      newEventId: () => "evt-x",
      workspaceRoots: createWorkspaceResolver(path.join(dir, "no-omnodex-home")),
    });
    const inSibling = makeEvent({ cwd: wt, parameters: { file_path: path.join(main, "src", "a.ts"), content: "x" } });
    assert.deepEqual(ev.evaluate(inSibling), []);
    const outside = makeEvent({
      tool_call_id: "tc-out", cwd: wt, parameters: { file_path: path.join(dir, "elsewhere.ts"), content: "x" },
    });
    assert.equal(ev.evaluate(outside).length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("no finding on a write into a configured workspace root", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-ws-home-"));
  try {
    await writeFile(
      path.join(home, "omnodex-config.json"),
      JSON.stringify({ workspace_roots: ["/home/case/shared-notes", "~/scratch"] }),
    );
    assert.deepEqual(configuredRoots(home, "/home/case"), ["/home/case/shared-notes", "/home/case/scratch"]);
    const findings = engine.evaluate(
      makeEvent({ parameters: { file_path: "/home/case/shared-notes/today.md", content: "x" } }),
      { workspaceRoots: ["/home/case/projects/myapp", ...configuredRoots(home, "/home/case")] },
    );
    assert.equal(findings.length, 0);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("expands ~ with the host's home directory", () => {
  const inside = engine.evaluate(
    makeEvent({ cwd: "/home/case/projects/myapp", parameters: { file_path: "~/projects/myapp/a.ts", content: "x" } }),
    { home: "/home/case" },
  );
  assert.equal(inside.length, 0);
  const outside = engine.evaluate(
    makeEvent({ parameters: { file_path: "~/.bashrc", content: "x" } }),
    { home: "/home/case" },
  );
  assert.equal(outside.length, 1);
});
