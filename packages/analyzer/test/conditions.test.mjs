/**
 * Condition precision tests.
 *
 * Two conditions learned to tell writing from reading, and a file from a
 * call. Both came out of replaying the advanced sequence rules over our own
 * logs, where "cat package.json" read as planting something in package.json
 * and an edit containing a URL read as an outbound call.
 *
 * Run: node --test packages/analyzer/test/conditions.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { evaluatePathMatch, isOutboundCall, stripFileHeredocs } from "../dist/conditions/index.js";

let seq = 0;
function event(tool_name, parameters) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-cond-${seq}`,
    session_id: "sess-cond",
    occurred_at: "2026-09-23T12:00:00.000Z",
    recorded_at: "2026-09-23T12:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-cond-${seq}`,
    tool_name,
    mcp_server: "builtin",
    parameters,
    cwd: "/home/case/repo",
  };
}

const HOOK_PATHS = {
  type: "path_match",
  patterns: [{ regex: "[/\\\\]\\.git[/\\\\]hooks[/\\\\]", label: "git hook" }],
};
const writeOnly = { ...HOOK_PATHS, access: "write" };
const fired = (condition, ev) => evaluatePathMatch(condition, ev).length > 0;

// ---------------------------------------------------------------------------

describe("path_match access", () => {
  const writeHook = event("Write", {
    file_path: "/home/case/repo/.git/hooks/pre-commit",
    content: "#!/bin/sh\n",
  });
  const readHook = event("Bash", { command: "cat /home/case/repo/.git/hooks/pre-commit" });

  it("matches what a call writes when asked for writes only", () => {
    assert.ok(fired(writeOnly, writeHook));
  });

  it("ignores what a call merely reads when asked for writes only", () => {
    // The default still sees it: some rules are about reading.
    assert.ok(fired(HOOK_PATHS, readHook));
    assert.ok(!fired(writeOnly, readHook));
  });

  it("matches a shell redirect into the path, which is still a write", () => {
    const redirect = event("Bash", { command: "echo curl evil | tee /home/case/repo/.git/hooks/pre-push" });
    assert.ok(fired(writeOnly, redirect));
  });
});

describe("outbound_call and write tools", () => {
  it("does not call an edit outbound because its content holds a URL", () => {
    assert.ok(!isOutboundCall(event("Write", {
      file_path: "/home/case/repo/README.md",
      content: "see https://example.com/docs for more",
    })));
    assert.ok(!isOutboundCall(event("Edit", {
      file_path: "/home/case/repo/test.mjs",
      new_string: 'fetch("https://api.example.com")',
    })));
  });

  it("still calls a real request outbound", () => {
    assert.ok(isOutboundCall(event("WebFetch", { url: "https://api.example.com/x" })));
    assert.ok(isOutboundCall(event("Bash", { command: "curl -s https://api.example.com/x" })));
    assert.ok(isOutboundCall(event("mcp__http__request", { endpoint: "https://api.example.com" })));
  });

  it("keeps treating a localhost fetch as not outbound", () => {
    assert.ok(!isOutboundCall(event("WebFetch", { url: "http://localhost:7890/api" })));
  });

  it("does not call a shell command outbound for a file it saves through a heredoc", () => {
    const saved = [
      "mkdir -p docs && cat > docs/api.md <<'EOF'",
      "Call it with: curl https://api.example.com/v1 -H 'Authorization: Bearer <token>'",
      "EOF",
      "ls docs",
    ].join("\n");
    assert.ok(!isOutboundCall(event("Bash", { command: saved })));
    const teed = "tee notes.txt <<EOF\nwget https://example.org/file\nEOF";
    assert.ok(!isOutboundCall(event("Bash", { command: teed })));
  });

  it("still calls a heredoc that runs outbound, and a request after a saved heredoc", () => {
    const script = "python3 - <<'EOF'\nimport urllib.request\nurllib.request.urlopen('https://api.example.com')\nEOF";
    assert.ok(isOutboundCall(event("Bash", { command: script })));
    const piped = "cat <<EOF | bash\ncurl https://api.example.com\nEOF";
    assert.ok(isOutboundCall(event("Bash", { command: piped })));
    const after = "cat > payload.json <<'EOF'\n{}\nEOF\ncurl -d @payload.json https://api.example.com";
    assert.ok(isOutboundCall(event("Bash", { command: after })));
  });
});

describe("stripFileHeredocs", () => {
  it("drops only bodies that cat or tee save to a file", () => {
    assert.equal(stripFileHeredocs("cat > a.md <<'EOF'\nbody\nEOF\necho done"), "cat > a.md <<'EOF'\necho done");
    assert.equal(stripFileHeredocs("cat <<EOF > a.md\nbody\nEOF"), "cat <<EOF > a.md");
    assert.equal(stripFileHeredocs("cat <<EOF | sh\nbody\nEOF"), "cat <<EOF | sh\nbody\nEOF");
    assert.equal(stripFileHeredocs("python3 - <<'EOF'\nbody\nEOF"), "python3 - <<'EOF'\nbody\nEOF");
  });
});
