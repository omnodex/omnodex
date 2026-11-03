/**
 * Policy entries: how they combine (every precedence level, loosening and
 * tightening), what each target matches, credential fingerprints on
 * findings, and the older per-rule keys read as entries with the same
 * effect as before.
 *
 * Run: node --test packages/analyzer/test/policy.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { evaluatePolicy, targetMatches, normalizePath, credentialFingerprinter, RuleEngine, detectEventLogs } from "../dist/index.js";
import { resolveVerdict, targetCovers, annotateFindings, enforceCaptured } from "../dist/enforcement/index.js";
import { EventLog } from "@omnodex/event-log";
import { policyEntries, parsePolicy, parseRepoEnforcementConfig } from "@omnodex/shared";

let seq = 0;
function call(parameters, overrides = {}) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-pol-${seq}`,
    session_id: "sess-pol",
    occurred_at: "2026-10-27T12:00:00.000Z",
    recorded_at: "2026-10-27T12:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-pol-${seq}`,
    tool_name: "Bash",
    mcp_server: "builtin",
    parameters,
    cwd: "/home/case/repo",
    ...overrides,
  };
}
const bash = (command, overrides) => call({ command }, overrides);
const read = (file_path, overrides) => call({ file_path }, { tool_name: "Read", ...overrides });
const write = (file_path) => call({ file_path, content: "x" }, { tool_name: "Write" });

const finding = (overrides = {}) => ({ rule_id: "RULE_X", category: "cat_x", severity: "HIGH", ...overrides });
let ids = 0;
const entry = (match, effect, extra = {}) => ({ id: `e${++ids}`, match: { rule_id: "RULE_X", ...match }, effect, ...extra });

describe("evaluatePolicy: precedence", () => {
  it("MUST_NOT_FIRE: no entries leave the default verdict, the rule's severity and no mute", () => {
    const r = evaluatePolicy({ finding: finding(), defaultVerdict: "confirm" });
    assert.deepEqual([r.verdict, r.severity, r.muted, r.decided], ["confirm", "HIGH", false, {}]);
  });

  it("MUST_FIRE: an entry with a target beats one without, both ways", () => {
    const c = read("/home/case/repo/.env");
    const loosen = evaluatePolicy({
      finding: finding(),
      call: c,
      machine: [entry({}, { verdict: "deny" }), entry({ target: { path: "/home/case/repo/.env" } }, { verdict: "allow" })],
    });
    assert.equal(loosen.verdict, "alert_only");
    assert.equal(loosen.decided.verdict.source, "user-exception");
    const tighten = evaluatePolicy({
      finding: finding(),
      call: c,
      machine: [entry({}, { verdict: "allow" }), entry({ target: { path: "/home/case/repo" } }, { verdict: "deny" })],
    });
    assert.equal(tighten.verdict, "deny");
    assert.equal(tighten.decided.verdict.source, "user-target");
  });

  it("MUST_FIRE: a rule beats a category, which beats a severity, both ways", () => {
    const sev = { rule_id: undefined, severity: "HIGH" };
    const cat = { rule_id: undefined, category: "cat_x" };
    const e = (match, verdict) => entry(match, { verdict });
    assert.equal(evaluatePolicy({ finding: finding(), machine: [e(sev, "deny"), e(cat, "allow")] }).verdict, "alert_only");
    assert.equal(evaluatePolicy({ finding: finding(), machine: [e(sev, "allow"), e(cat, "deny")] }).verdict, "deny");
    assert.equal(evaluatePolicy({ finding: finding(), machine: [e(cat, "deny"), e({}, "allow")] }).verdict, "alert_only");
    assert.equal(evaluatePolicy({ finding: finding(), machine: [e(cat, "allow"), e({}, "confirm")] }).verdict, "confirm");
    const r = evaluatePolicy({ finding: finding(), machine: [e(cat, "deny")] });
    assert.equal(r.decided.verdict.source, "user-category");
  });

  it("MUST_FIRE: a project entry beats an everywhere entry, and a deeper root beats its parent", () => {
    const c = bash("ls", { cwd: "/home/case/repo/pkg/a" });
    const r = evaluatePolicy({
      finding: finding(),
      call: c,
      machine: [
        entry({}, { verdict: "deny" }),
        entry({ project: "/home/case/repo" }, { verdict: "allow" }),
      ],
    });
    assert.equal(r.verdict, "alert_only");
    assert.equal(r.decided.verdict.source, "project-rule");
    const deeper = evaluatePolicy({
      finding: finding(),
      call: c,
      machine: [
        entry({ project: "/home/case/repo/pkg" }, { verdict: "confirm" }),
        entry({ project: "/home/case/repo" }, { verdict: "allow" }),
      ],
    });
    assert.equal(deeper.verdict, "confirm");
  });

  it("MUST_NOT_FIRE: a project entry for another project, or a sibling with the same prefix", () => {
    for (const cwd of ["/home/case/other", "/home/case/repo-two"]) {
      const r = evaluatePolicy({
        finding: finding(),
        call: bash("ls", { cwd }),
        machine: [entry({ project: "/home/case/repo" }, { verdict: "deny" })],
      });
      assert.equal(r.verdict, "alert_only", cwd);
    }
  });

  it("MUST_FIRE: a machine entry beats an account entry at equal specificity, both ways", () => {
    const loosen = evaluatePolicy({
      finding: finding(),
      machine: [entry({}, { verdict: "allow" })],
      account: [entry({}, { verdict: "deny" })],
    });
    assert.equal(loosen.verdict, "alert_only");
    assert.equal(loosen.decided.verdict.layer, "machine");
    const tighten = evaluatePolicy({
      finding: finding(),
      machine: [entry({}, { verdict: "deny" })],
      account: [entry({}, { verdict: "allow" })],
    });
    assert.equal(tighten.verdict, "deny");
  });

  it("MUST_FIRE: a more specific account entry beats a machine entry", () => {
    const r = evaluatePolicy({
      finding: finding(),
      call: read("/home/case/repo/.env"),
      machine: [entry({}, { verdict: "deny" })],
      account: [entry({ target: { path: "/home/case/repo/.env" } }, { verdict: "allow" })],
    });
    assert.equal(r.verdict, "alert_only");
    assert.equal(r.decided.verdict.source, "account-exception");
  });

  it("MUST_FIRE: between equal entries the stricter verdict wins, in either order", () => {
    const a = entry({}, { verdict: "allow" });
    const d = entry({}, { verdict: "confirm" });
    assert.equal(evaluatePolicy({ finding: finding(), machine: [a, d] }).verdict, "confirm");
    assert.equal(evaluatePolicy({ finding: finding(), machine: [d, a] }).verdict, "confirm");
  });

  it("MUST_FIRE: between equal entries the most recent severity wins, then the later one", () => {
    const older = entry({}, { severity: "LOW" }, { created_at: "2026-10-01T00:00:00Z" });
    const newer = entry({}, { severity: "CRITICAL" }, { created_at: "2026-10-20T00:00:00Z" });
    assert.equal(evaluatePolicy({ finding: finding(), machine: [newer, older] }).severity, "CRITICAL");
    const undated = [entry({}, { severity: "LOW" }), entry({}, { severity: "MEDIUM" })];
    assert.equal(evaluatePolicy({ finding: finding(), machine: undated }).severity, "MEDIUM");
  });

  it("MUST_FIRE: between equal entries not muting wins", () => {
    const r = evaluatePolicy({ finding: finding(), machine: [entry({}, { mute: true }), entry({}, { mute: false })] });
    assert.equal(r.muted, false);
  });

  it("decides each effect on its own: a narrower entry's severity leaves a wider entry's verdict alone", () => {
    const r = evaluatePolicy({
      finding: finding(),
      call: read("/home/case/repo/.env"),
      machine: [
        entry({}, { verdict: "deny", mute: true }),
        entry({ target: { path: "/home/case/repo/.env" } }, { severity: "LOW" }),
      ],
    });
    assert.deepEqual([r.verdict, r.severity, r.muted], ["deny", "LOW", true]);
    assert.equal(r.decided.severity.source, "user-exception");
    assert.equal(r.decided.verdict.source, "user-rule");
  });

  it("MUST_NOT_FIRE: entries for another rule, category or severity", () => {
    const r = evaluatePolicy({
      finding: finding(),
      machine: [
        entry({ rule_id: "RULE_Y" }, { verdict: "deny" }),
        entry({ rule_id: undefined, category: "cat_y" }, { verdict: "deny" }),
        entry({ rule_id: undefined, severity: "LOW" }, { verdict: "deny" }),
      ],
    });
    assert.equal(r.verdict, "alert_only");
  });
});

describe("evaluatePolicy: severity", () => {
  it("MUST_FIRE: raises on any matching target, lowers only when the whole call is covered", () => {
    const c = bash("cp /home/case/repo/a.txt /tmp/a.txt");
    const raise = entry({ target: { path: "/home/case/repo" } }, { severity: "CRITICAL" });
    const lower = entry({ target: { path: "/home/case/repo" } }, { severity: "LOW" });
    assert.equal(evaluatePolicy({ finding: finding(), call: c, machine: [raise] }).severity, "CRITICAL");
    assert.equal(evaluatePolicy({ finding: finding(), call: c, machine: [lower] }).severity, "HIGH");
    const inside = bash("cat /home/case/repo/a.txt");
    assert.equal(evaluatePolicy({ finding: finding(), call: inside, machine: [lower] }).severity, "LOW");
  });

  it("matches a severity entry on the rule's own severity, not on another entry's", () => {
    const r = evaluatePolicy({
      finding: finding(),
      machine: [entry({}, { severity: "LOW" }), entry({ rule_id: undefined, severity: "LOW" }, { verdict: "deny" })],
    });
    assert.deepEqual([r.severity, r.verdict], ["LOW", "alert_only"]);
  });
});

describe("evaluatePolicy: the repository only tightens", () => {
  it("MUST_FIRE: a stricter repository verdict and a higher repository severity apply", () => {
    const r = evaluatePolicy({
      finding: finding(),
      machine: [entry({ rule_id: undefined, category: "cat_x" }, { verdict: "confirm", severity: "MEDIUM" })],
      repo: [entry({}, { verdict: "deny", severity: "CRITICAL" })],
    });
    assert.deepEqual([r.verdict, r.severity], ["deny", "CRITICAL"]);
    assert.equal(r.decided.verdict.source, "repo-rule");
  });

  it("MUST_NOT_FIRE: a looser repository verdict or a lower repository severity", () => {
    const r = evaluatePolicy({
      finding: finding(),
      machine: [entry({}, { verdict: "deny" })],
      repo: [entry({}, { verdict: "confirm", severity: "LOW" })],
    });
    assert.deepEqual([r.verdict, r.severity], ["deny", "HIGH"]);
  });

  it("MUST_NOT_FIRE: over the user's own allow", () => {
    const r = evaluatePolicy({
      finding: finding(),
      call: read("/home/case/repo/.env"),
      machine: [entry({ target: { path: "/home/case/repo/.env" } }, { verdict: "allow" })],
      repo: [entry({}, { verdict: "deny" })],
    });
    assert.equal(r.verdict, "alert_only");
  });

  it("the repository file cannot carry allow, mute or a project scope", () => {
    const cfg = parseRepoEnforcementConfig({
      policy: [
        { id: "a", match: { rule_id: "RULE_X" }, effect: { verdict: "allow" } },
        { id: "m", match: { rule_id: "RULE_X" }, effect: { mute: true } },
        { id: "d", match: { rule_id: "RULE_X", project: "/elsewhere" }, effect: { verdict: "deny", mute: true } },
      ],
    });
    assert.deepEqual(cfg.policy, [{ id: "d", match: { rule_id: "RULE_X" }, effect: { verdict: "deny" } }]);
  });
});

describe("targets", () => {
  const all = (t, c, opts) => targetMatches(t, { call: c }, "all", opts);
  const any = (t, c, opts) => targetMatches(t, { call: c }, "any", opts);

  it("path: MUST_FIRE on every path covered (all) or one (any)", () => {
    const t = { path: "/home/case/repo/src" };
    assert.equal(all(t, read("/home/case/repo/src/a.ts")), true);
    assert.equal(all(t, read("src/a.ts")), true);
    assert.equal(any(t, bash("cp /home/case/repo/src/a.ts /tmp/a.ts")), true);
  });

  it("path: MUST_NOT_FIRE on a sibling with the same prefix, or (all) a call that also touches another path", () => {
    const t = { path: "/home/case/repo/src" };
    assert.equal(any(t, read("/home/case/repo/srcx/a.ts")), false);
    assert.equal(all(t, bash("cp /home/case/repo/src/a.ts /tmp/a.ts")), false);
  });

  it("path: ~ and relative paths resolve against the home and base folders", () => {
    assert.equal(all({ path: "~/.ssh" }, read("/home/case/.ssh/id_rsa"), { home: "/home/case" }), true);
    assert.equal(all({ path: "src" }, read("/home/case/repo/src/a.ts"), { base: "/home/case/repo" }), true);
  });

  it("destination: MUST_FIRE on the host and subdomains, MUST_NOT_FIRE on a lookalike", () => {
    const t = { destination: "example.com" };
    assert.equal(all(t, bash("curl https://api.example.com/x")), true);
    assert.equal(any(t, bash("curl https://example.com/x https://other.net/")), true);
    assert.equal(all(t, bash("curl https://example.com/x https://other.net/")), false);
    assert.equal(any(t, bash("curl https://badexample.com/")), false);
  });

  it("command_prefix: whole words; (all) never across substitution; (any) one segment is enough", () => {
    const t = { command_prefix: "npm test" };
    assert.equal(all(t, bash("npm test -- --watch")), true);
    assert.equal(all(t, bash("npm test && curl https://x.example/")), false);
    assert.equal(all(t, bash("npm test $(curl https://x.example/)")), false);
    assert.equal(any(t, bash("npm ci && npm test")), true);
    assert.equal(any(t, bash("npm testing")), false);
  });

  it("tool: MUST_FIRE on the tool, on its server when one is named", () => {
    const mcp = call({ q: "x" }, { tool_name: "search", mcp_server: "web" });
    assert.equal(all({ tool: "search" }, mcp), true);
    assert.equal(all({ tool: "search", server: "web" }, mcp), true);
    assert.equal(all({ tool: "search", server: "files" }, mcp), false);
    assert.equal(any({ tool: "fetch" }, mcp), false);
  });

  it("access: read and write are told apart", () => {
    const reads = { access: "read", path: "/home/case/repo/.env" };
    const writes = { access: "write", path: "/home/case/repo/.env" };
    assert.equal(all(reads, read("/home/case/repo/.env")), true);
    assert.equal(any(writes, read("/home/case/repo/.env")), false);
    assert.equal(all(writes, write("/home/case/repo/.env")), true);
    assert.equal(any(reads, write("/home/case/repo/.env")), false);
    // Allowing reads never allows a call that also writes somewhere.
    assert.equal(all({ access: "read", path: "/home/case/repo" }, bash("cp /home/case/repo/a /tmp/b")), false);
    assert.equal(any({ access: "read", path: "/home/case/repo" }, bash("cp /home/case/repo/a /tmp/b")), true);
  });

  it("credential: matches the finding's fingerprints, and needs no call", () => {
    const t = { credential: "abcd1234abcd1234" };
    assert.equal(targetMatches(t, { finding: { credential_fingerprints: ["abcd1234abcd1234"] } }, "all"), true);
    assert.equal(targetMatches(t, { finding: { credential_fingerprints: ["abcd1234abcd1234", "ffff"] } }, "all"), false);
    assert.equal(targetMatches(t, { finding: { credential_fingerprints: ["abcd1234abcd1234", "ffff"] } }, "any"), true);
    assert.equal(targetMatches(t, { finding: {} }, "any"), false);
  });

  it("a target with no call matches nothing but a credential", () => {
    assert.equal(targetMatches({ path: "/" }, {}, "any"), false);
    assert.equal(targetMatches({ tool: "Bash" }, {}, "any"), false);
  });

  it("normalizePath works without the platform path module", () => {
    assert.equal(normalizePath("/a/./b/../c/", undefined, undefined), "/a/c");
    assert.equal(normalizePath("C:\\Users\\Case\\Repo", undefined, undefined), "c:/users/case/repo");
    assert.equal(normalizePath("../x", "/home/case/repo", undefined), "/home/case/x");
    assert.equal(normalizePath("/..", undefined, undefined), "/");
  });
});

describe("credential fingerprints on findings", () => {
  const rule = {
    rule_id: "RULE_FP",
    name: "fp",
    event_types: ["tool.invoked"],
    conditions: [{ type: "credential_match", patterns: [{ regex: "AKIA[A-Z0-9]{16}", type: "aws-key" }] }],
    severity: "HIGH",
    category: "credential",
    description_template: "Credential in {{tool_name}}",
    tier: "community",
  };
  const key = "AKIAIOSFODNN7EXAMPLE";

  it("MUST_FIRE: a finding carries a short fingerprint, never the value", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-fp-"));
    try {
      const fp = credentialFingerprinter(home);
      const engine = new RuleEngine([rule], { fingerprint: fp });
      const [f] = engine.evaluate(call({ api_key: key, again: key }));
      assert.deepEqual(f.credential_fingerprints, [fp(key)]);
      assert.match(f.credential_fingerprints[0], /^[0-9a-f]{16}$/);
      assert.equal(JSON.stringify(f).includes(key), false);
      // Stable on this machine; different with another machine's key.
      assert.equal(credentialFingerprinter(home)(key), fp(key));
      const other = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-fp-"));
      try {
        assert.notEqual(credentialFingerprinter(other)(key), fp(key));
      } finally {
        fs.rmSync(other, { recursive: true, force: true });
      }
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it("MUST_NOT_FIRE: no fingerprint function, or nothing matched, records none", () => {
    const [f] = new RuleEngine([rule]).evaluate(call({ api_key: key }));
    assert.equal(f.credential_fingerprints, undefined);
    const pathRule = { ...rule, conditions: [{ type: "tool_name_match", patterns: [{ tool_name_regex: "^Bash$", label: "shell" }] }] };
    const [g] = new RuleEngine([pathRule], { fingerprint: () => "x" }).evaluate(call({ api_key: key }));
    assert.equal(g?.credential_fingerprints, undefined);
  });

  it("a credential entry holds or allows the call the finding is about", () => {
    const r = resolveVerdict({
      rule: { rule_id: "RULE_FP", severity: "HIGH" },
      credential_fingerprints: ["0123456789abcdef"],
      config: { user: { policy: [entry({ rule_id: "RULE_FP", target: { credential: "0123456789abcdef" } }, { verdict: "deny" })] } },
    });
    assert.equal(r.action, "deny");
  });
});

describe("parsePolicy", () => {
  it("keeps well-formed entries and drops the rest one by one", () => {
    const parsed = parsePolicy([
      { id: "ok", match: { category: "x", target: { tool: "t", server: "s" } }, effect: { verdict: "confirm" }, created_by: "cli" },
      { id: "two-kinds", match: { rule_id: "R", category: "x" }, effect: { verdict: "deny" } },
      { id: "no-kind", match: {}, effect: { verdict: "deny" } },
      { id: "no-effect", match: { rule_id: "R" }, effect: {} },
      { id: "bad-verdict", match: { rule_id: "R" }, effect: { verdict: "alert_only" } },
      { id: "two-targets", match: { rule_id: "R", target: { path: "/a", destination: "b" } }, effect: { mute: true } },
      { id: "bad-access", match: { rule_id: "R", target: { access: "exec", path: "/a" } }, effect: { mute: true } },
      { id: "ok", match: { rule_id: "R" }, effect: { mute: true } },
      { match: { rule_id: "R" }, effect: { mute: true } },
    ]);
    assert.deepEqual(parsed, [
      { id: "ok", match: { category: "x", target: { tool: "t", server: "s" } }, effect: { verdict: "confirm" }, created_by: "cli" },
    ]);
  });
});

// ---------------------------------------------------------------------------
// The older keys, read as entries
// ---------------------------------------------------------------------------

describe("the older keys as entries", () => {
  it("turns rules, severity defaults, exceptions and per-project sections into entries", () => {
    const entries = policyEntries({
      rules: { RULE_A: "deny" },
      severity_defaults: { HIGH: "confirm" },
      exceptions: [{ rule_id: "RULE_B", kind: "mute", target: { path: "/tmp" }, note: "scratch", created_at: "2026-10-01T00:00:00Z" }],
      projects: { "/home/case/repo": { rules: { RULE_A: "alert_only" } } },
      policy: [{ id: "p1", match: { rule_id: "RULE_C" }, effect: { severity: "LOW" } }],
    });
    assert.deepEqual(entries, [
      { id: "config:rule:RULE_A", match: { rule_id: "RULE_A" }, effect: { verdict: "deny" }, created_by: "config" },
      { id: "config:severity:HIGH", match: { severity: "HIGH" }, effect: { verdict: "confirm" }, created_by: "config" },
      {
        id: "config:exception:RULE_B:mute:path=/tmp",
        match: { rule_id: "RULE_B", target: { path: "/tmp" } },
        effect: { verdict: "allow", mute: true },
        created_by: "config",
        note: "scratch",
        created_at: "2026-10-01T00:00:00Z",
      },
      {
        id: "config:project:/home/case/repo:rule:RULE_A",
        match: { rule_id: "RULE_A", project: "/home/case/repo" },
        effect: { verdict: "allow" },
        created_by: "config",
      },
      { id: "p1", match: { rule_id: "RULE_C" }, effect: { severity: "LOW" } },
    ]);
  });

  /**
   * The verdict chain as it was before policy entries, kept here as the
   * reference: per-section exceptions first (project, then user), then
   * per-rule and per-severity verdicts (project, then user), then the rule's
   * hint, with the repository's verdicts on top when stricter.
   */
  function oldChain(rule, call, config) {
    const S = { alert_only: 0, confirm: 1, deny: 2 };
    for (const [cfg, base] of [[config.userProject, config.projectRoot], [config.user, undefined]]) {
      const hit = cfg?.exceptions?.find((e) => e.rule_id === rule.rule_id && (!e.target || (call && targetCovers(e.target, call, base))));
      if (hit) return { action: "alert_only", muted: hit.kind === "mute" };
    }
    let action =
      config.userProject?.rules?.[rule.rule_id] ??
      config.user?.rules?.[rule.rule_id] ??
      config.userProject?.severity_defaults?.[rule.severity] ??
      config.user?.severity_defaults?.[rule.severity];
    if (!action) {
      const hint = rule.blocking_hint ?? "alert_only";
      action = hint !== "alert_only" && !rule.safe_alternative ? "alert_only" : hint;
    }
    const byRule = config.repo?.rules?.[rule.rule_id];
    const bySev = config.repo?.severity_defaults?.[rule.severity];
    const repo = byRule && bySev ? (S[byRule] >= S[bySev] ? byRule : bySev) : (byRule ?? bySev);
    if (repo && S[repo] > S[action]) action = repo;
    return { action, muted: false };
  }

  const VERDICTS = [undefined, "deny", "confirm", "alert_only"];
  const EXCEPTIONS = [
    undefined,
    { rule_id: "RULE_X", kind: "allow" },
    { rule_id: "RULE_X", kind: "mute" },
    { rule_id: "RULE_X", kind: "allow", target: { path: "/home/case/repo" } },
    { rule_id: "RULE_X", kind: "mute", target: { path: "/elsewhere" } },
  ];
  const HINTS = [{}, { blocking_hint: "deny" }, { blocking_hint: "confirm", safe_alternative: { suggestion: "x" } }];

  function* sections() {
    for (const r of VERDICTS) for (const s of VERDICTS) for (const e of EXCEPTIONS) {
      const cfg = {};
      if (r) cfg.rules = { RULE_X: r };
      if (s) cfg.severity_defaults = { HIGH: s };
      if (e) cfg.exceptions = [e];
      yield cfg;
    }
  }

  /**
   * The cases decided differently on purpose, each pinned by its own test
   * below: a user-wide exception for the whole rule against a per-rule
   * verdict for this project; the user's allow against the repository; and
   * a mute that a narrower allow no longer lifts.
   */
  function documentedChange(user, project, repo) {
    const wholeRule = (c) => c.exceptions?.some((e) => !e.target);
    if (wholeRule(user) && project.rules) return true;
    const repoTightens = Boolean(repo.rules || repo.severity_defaults);
    const allows = (c) => Object.values(c.rules ?? {}).includes("alert_only") || Object.values(c.severity_defaults ?? {}).includes("alert_only");
    if (repoTightens && (allows(user) || allows(project))) return true;
    const mutes = (c) => c.exceptions?.some((e) => e.kind === "mute");
    if (mutes(user) && project.exceptions) return true;
    return false;
  }

  it("migrate unchanged in effect: every combination of the older keys gives the verdict and mute it gave before", () => {
    const c = read("/home/case/repo/a.txt");
    const repos = [{}, { rules: { RULE_X: "deny" } }, { severity_defaults: { HIGH: "confirm" } }];
    let compared = 0;
    for (const user of sections()) for (const project of sections()) for (const repo of repos) {
      if (documentedChange(user, project, repo)) continue;
      for (const hint of HINTS) {
        const rule = { rule_id: "RULE_X", severity: "HIGH", ...hint };
        const config = { user, userProject: project, repo, projectRoot: "/home/case/repo" };
        const before = oldChain(rule, c, config);
        const after = resolveVerdict({ rule, call: c, config });
        if (after.action !== before.action || after.muted !== before.muted) {
          assert.fail(`changed: ${JSON.stringify({ config, hint })} was ${JSON.stringify(before)}, now ${after.action}/${after.muted}`);
        }
        compared++;
      }
    }
    assert.ok(compared > 15000, `compared ${compared}`);
  });

  it("documented change: a per-rule verdict for this project beats a user-wide exception for the whole rule", () => {
    const v = resolveVerdict({
      rule: { rule_id: "RULE_X", severity: "HIGH" },
      config: { user: { exceptions: [{ rule_id: "RULE_X", kind: "allow" }] }, userProject: { rules: { RULE_X: "deny" } }, projectRoot: "/p" },
    });
    assert.equal(v.action, "deny");
  });

  it("documented change: the user's own allow is no longer overruled by the repository", () => {
    const v = resolveVerdict({
      rule: { rule_id: "RULE_X", severity: "HIGH" },
      config: { user: { rules: { RULE_X: "alert_only" } }, repo: { rules: { RULE_X: "deny" } } },
    });
    assert.equal(v.action, "alert_only");
  });

  it("documented change: a narrower allow does not lift a wider mute", () => {
    const v = resolveVerdict({
      rule: { rule_id: "RULE_X", severity: "HIGH" },
      config: {
        user: { exceptions: [{ rule_id: "RULE_X", kind: "mute" }] },
        userProject: { exceptions: [{ rule_id: "RULE_X", kind: "allow" }] },
        projectRoot: "/p",
      },
    });
    assert.deepEqual([v.action, v.muted], ["alert_only", true]);
  });
});

// ---------------------------------------------------------------------------
// Severity at capture
// ---------------------------------------------------------------------------

describe("a policy severity at capture", () => {
  const risk = (c, overrides = {}) => ({
    schema_version: 1, event_id: `f-${c.tool_call_id}`, session_id: c.session_id, occurred_at: c.occurred_at,
    recorded_at: c.recorded_at, interceptor: "analyzer", event_type: "risk.detected", severity: "HIGH",
    category: "cat_x", description: "something", related_event_id: c.tool_call_id, rule_id: "RULE_X", ...overrides,
  });
  const lower = { policy: [entry({ target: { path: "/home/case/repo/.env" } }, { severity: "LOW" })] };
  const loaded = (mode, user) => () => ({ mode, on_error: "allow", user });

  it("MUST_FIRE: in monitor mode too, with the rule's severity kept as recommended", () => {
    const c = read("/home/case/repo/.env");
    const [f] = annotateFindings([risk(c)], [c], { loaded: loaded("monitor", lower) });
    assert.deepEqual([f.severity, f.recommended_severity, f.enforcement], ["LOW", "HIGH", undefined]);
  });

  it("MUST_FIRE: a category entry raises the severity and stamps alongside the shadow record", () => {
    const c = bash("echo hi");
    const user = { policy: [entry({ rule_id: undefined, category: "cat_x" }, { severity: "CRITICAL", verdict: "confirm" })] };
    const [f] = annotateFindings([risk(c)], [c], { loaded: loaded("shadow", user) });
    assert.deepEqual([f.severity, f.recommended_severity, f.enforcement.action], ["CRITICAL", "HIGH", "confirm"]);
  });

  it("MUST_NOT_FIRE: no severity entry, an entry giving the same severity, or a call the target does not cover", () => {
    const c = read("/home/case/repo/.env");
    const findings = [risk(c)];
    assert.equal(annotateFindings(findings, [c], { loaded: loaded("monitor", {}) }), findings);
    const same = { policy: [entry({}, { severity: "HIGH" })] };
    assert.equal(annotateFindings(findings, [c], { loaded: loaded("monitor", same) }), findings);
    const other = read("/home/case/repo/README.md");
    const [f] = annotateFindings([risk(other)], [other], { loaded: loaded("monitor", lower) });
    assert.equal(f.recommended_severity, undefined);
  });

  it("MUST_NOT_FIRE: a finding recorded below its rule's severity is not put back up by no entry", () => {
    // Staged findings run one step below the rule; only an entry may change them.
    const c = bash("echo hi");
    const rule = () => ({ rule_id: "RULE_X", severity: "CRITICAL" });
    const findings = [risk(c, { severity: "HIGH" })];
    assert.equal(annotateFindings(findings, [c], { loaded: loaded("shadow", {}), rule }), findings);
  });

  it("keeps the first recommended severity when a finding is judged twice", () => {
    const c = read("/home/case/repo/.env");
    const [once] = annotateFindings([risk(c)], [c], { loaded: loaded("monitor", lower) });
    const raise = { policy: [entry({}, { severity: "MEDIUM" })] };
    const [twice] = annotateFindings([once], [c], { loaded: loaded("monitor", raise) });
    assert.equal(twice.recommended_severity, "HIGH");
  });

  it("MUST_FIRE: guardrails applies it to the findings it stamps", async () => {
    const c = read("/home/case/repo/.env");
    const module = { GUARDRAILS_INTERFACE: 1, decide: () => ({ action: "alert_only", held: [], output: null }) };
    const r = await enforceCaptured([risk(c)], [c], {
      host: "claude-code", newEventId: () => "x", module,
      loaded: { mode: "guardrails", on_error: "allow", user: lower },
    });
    assert.deepEqual([r.findings[0].severity, r.findings[0].recommended_severity], ["LOW", "HIGH"]);
  });

  it("MUST_FIRE: the background pass applies the home's entries to new findings, and records them once", async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-pol-"));
    try {
      const root = path.join(home, "event-log");
      const log = new EventLog({ root });
      await log.init();
      const c = read("/home/case/repo/.env", { session_id: "sess-bg" });
      await log.append(c);
      await log.close();
      fs.writeFileSync(path.join(home, "omnodex-config.json"), JSON.stringify({
        enforcement: { policy: [{ id: "bg", match: { category: "sensitive_path_read" }, effect: { severity: "LOW" } }] },
      }));
      const first = await detectEventLogs({ roots: [root], policyHome: home, newEventId: () => `bg-${++seq}` });
      const found = first.newEvents.filter((e) => e.category === "sensitive_path_read");
      assert.ok(found.length > 0, "the read of .env is a finding");
      for (const f of found) assert.deepEqual([f.severity, f.recommended_severity === undefined], ["LOW", false]);
      const again = await detectEventLogs({ roots: [root], policyHome: home, newEventId: () => `bg-${++seq}` });
      assert.equal(again.newEvents.length, 0, "a changed severity does not make a finding new");
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
