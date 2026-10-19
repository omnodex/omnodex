/**
 * Enforcement verdicts: the precedence chain, exception targets, combining
 * a call's findings, and the decision each host reads from its hook.
 *
 * Run: node --test packages/analyzer/test/enforcement.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  resolveVerdict,
  targetCovers,
  loadEnforcement,
  findRepoPolicy,
  annotateFindings,
  enforcementRecord,
  enforceCaptured,
  loadGuardrailsModule,
  describeGuardrails,
} from "../dist/enforcement/index.js";
import { installModule } from "./helpers/make-module.mjs";
import { stampCaptured } from "../dist/enforcement/stamp.js";
import { appendRuleSignals } from "../dist/enforcement/signals.js";
import { wouldBlock } from "@omnodex/shared";
import { COMMUNITY_RULES } from "../dist/index.js";

let seq = 0;
function call(parameters, overrides = {}) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-enf-${seq}`,
    session_id: "sess-enf",
    occurred_at: "2026-10-18T12:00:00.000Z",
    recorded_at: "2026-10-18T12:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-enf-${seq}`,
    tool_name: "Bash",
    mcp_server: "builtin",
    parameters,
    cwd: "/home/case/repo",
    ...overrides,
  };
}
const bash = (command) => call({ command });
const read = (file_path) => call({ file_path }, { tool_name: "Read" });

const SAFE = { suggestion: "Use the project's own script instead." };
const rule = (overrides = {}) => ({ rule_id: "RULE_X", severity: "HIGH", ...overrides });

describe("resolveVerdict: precedence", () => {
  it("defaults to alert_only with no hint and no config", () => {
    const v = resolveVerdict({ rule: rule() });
    assert.equal(v.action, "alert_only");
    assert.equal(v.candidate, "alert_only");
    assert.equal(v.source, "default");
  });

  it("holds a blocking hint back until the rule has a safe_alternative, but keeps it as the candidate", () => {
    const v = resolveVerdict({ rule: rule({ blocking_hint: "deny" }) });
    assert.equal(v.action, "alert_only");
    assert.equal(v.candidate, "deny");
    assert.equal(v.source, "rule-hint");

    const promoted = resolveVerdict({ rule: rule({ blocking_hint: "deny", safe_alternative: SAFE }) });
    assert.equal(promoted.action, "deny");
    assert.deepEqual(promoted.safe_alternative, SAFE);
  });

  it("applies a confirm hint under the same gate", () => {
    assert.equal(resolveVerdict({ rule: rule({ blocking_hint: "confirm" }) }).action, "alert_only");
    assert.equal(resolveVerdict({ rule: rule({ blocking_hint: "confirm", safe_alternative: SAFE }) }).action, "confirm");
  });

  it("severity defaults beat the hint, and the user's project section beats the user's global one", () => {
    const config = {
      user: { severity_defaults: { HIGH: "confirm" } },
      userProject: { severity_defaults: { HIGH: "deny" } },
    };
    const v = resolveVerdict({ rule: rule({ blocking_hint: "alert_only" }), config });
    assert.equal(v.action, "deny");
    assert.equal(v.source, "project-severity");
    assert.equal(resolveVerdict({ rule: rule(), config: { user: config.user } }).source, "user-severity");
  });

  it("per-rule verdicts beat severity defaults, project before user", () => {
    const config = {
      user: { rules: { RULE_X: "confirm" }, severity_defaults: { HIGH: "deny" } },
      userProject: { rules: { RULE_X: "alert_only" } },
    };
    const v = resolveVerdict({ rule: rule({ blocking_hint: "deny", safe_alternative: SAFE }), config });
    assert.equal(v.action, "alert_only");
    assert.equal(v.source, "project-rule");
    const u = resolveVerdict({ rule: rule(), config: { user: config.user } });
    assert.equal(u.action, "confirm");
    assert.equal(u.source, "user-rule");
  });

  it("a per-rule override can make a rule without a safe_alternative block", () => {
    const v = resolveVerdict({ rule: rule({ blocking_hint: "deny" }), config: { user: { rules: { RULE_X: "deny" } } } });
    assert.equal(v.action, "deny");
  });

  it("an exception beats everything, and a mute marks the finding", () => {
    const config = {
      user: { rules: { RULE_X: "deny" }, exceptions: [{ rule_id: "RULE_X", kind: "mute" }] },
    };
    const v = resolveVerdict({ rule: rule(), config });
    assert.equal(v.action, "alert_only");
    assert.equal(v.source, "user-exception");
    assert.equal(v.muted, true);

    const allow = resolveVerdict({
      rule: rule(),
      config: { userProject: { exceptions: [{ rule_id: "RULE_X", kind: "allow" }] }, user: { rules: { RULE_X: "deny" } } },
    });
    assert.equal(allow.source, "project-exception");
    assert.equal(allow.muted, false);
  });

  it("an exception for another rule does not apply", () => {
    const v = resolveVerdict({
      rule: rule(),
      config: { user: { rules: { RULE_X: "deny" }, exceptions: [{ rule_id: "RULE_Y", kind: "allow" }] } },
    });
    assert.equal(v.action, "deny");
  });
});

describe("resolveVerdict: the repository's policy only tightens", () => {
  it("applies a stricter repository verdict", () => {
    const v = resolveVerdict({ rule: rule(), config: { repo: { rules: { RULE_X: "deny" } } } });
    assert.equal(v.action, "deny");
    assert.equal(v.source, "repo-rule");
  });

  it("ignores a looser repository verdict", () => {
    const v = resolveVerdict({
      rule: rule(),
      config: { user: { rules: { RULE_X: "deny" } }, repo: { rules: { RULE_X: "alert_only" } } },
    });
    assert.equal(v.action, "deny");
    assert.equal(v.source, "user-rule");
  });

  it("cannot be bypassed with repository exceptions", () => {
    const v = resolveVerdict({
      rule: rule(),
      config: { user: { rules: { RULE_X: "deny" } }, repo: { exceptions: [{ rule_id: "RULE_X", kind: "allow" }] } },
    });
    assert.equal(v.action, "deny");
  });

  it("uses the stricter of the repository's rule and severity verdicts", () => {
    const v = resolveVerdict({
      rule: rule(),
      config: { repo: { rules: { RULE_X: "confirm" }, severity_defaults: { HIGH: "deny" } } },
    });
    assert.equal(v.action, "deny");
    assert.equal(v.source, "repo-severity");
  });

  it("still yields to the user's own exception", () => {
    const v = resolveVerdict({
      rule: rule(),
      config: { repo: { rules: { RULE_X: "deny" } }, user: { exceptions: [{ rule_id: "RULE_X", kind: "allow" }] } },
    });
    assert.equal(v.action, "alert_only");
  });
});

describe("exception targets", () => {
  it("path: MUST match a call whose every path is under the target", () => {
    assert.equal(targetCovers({ path: "/home/case/repo/tmp" }, read("/home/case/repo/tmp/a.txt")), true);
    assert.equal(targetCovers({ path: "/home/case/repo/tmp" }, read("/home/case/repo/tmp")), true);
    assert.equal(targetCovers({ path: "tmp" }, read("tmp/a.txt"), "/home/case/repo"), true);
  });

  it("path: MUST NOT match a sibling with the same prefix, or a call that touches another path", () => {
    assert.equal(targetCovers({ path: "/home/case/repo/tmp" }, read("/home/case/repo/tmp2/a.txt")), false);
    assert.equal(targetCovers({ path: "/home/case/repo/tmp" }, bash("cp /home/case/repo/tmp/a /home/case/.ssh/id_rsa")), false);
    assert.equal(targetCovers({ path: "/home/case/repo/tmp" }, bash("echo hi")), false);
  });

  it("path: a leading ~ is the home folder", () => {
    const home = os.homedir().replace(/\\/g, "/");
    assert.equal(targetCovers({ path: "~/work/app" }, read(`${home}/work/app/.env`)), true);
    assert.equal(targetCovers({ path: "~/work/app" }, read(`${home}/other/.env`)), false);
  });

  it("path: compares Windows drive paths without case or slash direction", () => {
    const c = read("C:\\Users\\case\\repo\\tmp\\a.txt", { cwd: "C:\\Users\\case\\repo" });
    assert.equal(targetCovers({ path: "c:/users/case/repo/tmp" }, c), true);
  });

  it("destination: MUST match the host and its subdomains", () => {
    assert.equal(targetCovers({ destination: "example.com" }, bash("curl https://api.example.com/v1")), true);
    assert.equal(targetCovers({ destination: "Example.com" }, bash("curl https://example.com/")), true);
  });

  it("destination: MUST NOT match a lookalike or a call that also goes elsewhere", () => {
    assert.equal(targetCovers({ destination: "example.com" }, bash("curl https://badexample.com/")), false);
    assert.equal(
      targetCovers({ destination: "example.com" }, bash("curl https://example.com/ && curl https://evil.test/")),
      false,
    );
  });

  it("command_prefix: MUST match whole words in every segment", () => {
    assert.equal(targetCovers({ command_prefix: "npm test" }, bash("npm test -- --watch")), true);
    assert.equal(targetCovers({ command_prefix: "npm test" }, bash("npm test && npm test")), true);
  });

  it("command_prefix: MUST NOT match a partial word, a chained command, or command substitution", () => {
    assert.equal(targetCovers({ command_prefix: "npm test" }, bash("npm testing")), false);
    assert.equal(targetCovers({ command_prefix: "npm test" }, bash("npm test && curl https://evil.test")), false);
    assert.equal(targetCovers({ command_prefix: "npm test" }, bash("npm test $(curl https://evil.test)")), false);
    assert.equal(targetCovers({ command_prefix: "npm test" }, bash("npm test `whoami`")), false);
  });

  it("a targeted exception needs the call", () => {
    const v = resolveVerdict({
      rule: rule(),
      config: { user: { rules: { RULE_X: "deny" }, exceptions: [{ rule_id: "RULE_X", kind: "allow", target: { path: "/tmp" } }] } },
    });
    assert.equal(v.action, "deny");
  });

  it("a targeted exception applies to the matching call only", () => {
    const config = {
      user: {
        rules: { RULE_X: "deny" },
        exceptions: [{ rule_id: "RULE_X", kind: "allow", target: { command_prefix: "npm test" } }],
      },
    };
    assert.equal(resolveVerdict({ rule: rule(), call: bash("npm test"), config }).action, "alert_only");
    assert.equal(resolveVerdict({ rule: rule(), call: bash("npm publish"), config }).action, "deny");
  });
});

describe("loadEnforcement", () => {
  function scratch() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-enf-"));
    const home = path.join(root, "home", "case");
    const omnodexHome = path.join(home, ".omnodex");
    const repo = path.join(root, "work", "repo");
    fs.mkdirSync(omnodexHome, { recursive: true });
    fs.mkdirSync(path.join(repo, "src"), { recursive: true });
    return { root, home, omnodexHome, repo };
  }
  const writeJson = (file, value) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(value));
  };

  it("defaults to monitor and fail open with no files", () => {
    const s = scratch();
    const cfg = loadEnforcement({ home: s.omnodexHome, cwd: s.repo, userHome: s.home });
    assert.equal(cfg.mode, "monitor");
    assert.equal(cfg.on_error, "allow");
    assert.equal(cfg.repo, undefined);
  });

  it("reads the user's file, the user's section for this project, and the repository policy", () => {
    const s = scratch();
    writeJson(path.join(s.omnodexHome, "omnodex-config.json"), {
      workspace_roots: [],
      enforcement: {
        mode: "guardrails",
        rules: { RULE_A: "deny" },
        projects: { [s.repo]: { rules: { RULE_A: "alert_only" } } },
      },
    });
    writeJson(path.join(s.repo, ".omnodex", "config.json"), {
      enforcement: { rules: { RULE_B: "confirm" }, exceptions: [{ rule_id: "RULE_B", kind: "allow" }] },
    });
    const cfg = loadEnforcement({ home: s.omnodexHome, cwd: path.join(s.repo, "src"), userHome: s.home });
    assert.equal(cfg.mode, "guardrails");
    assert.deepEqual(cfg.userProject, { rules: { RULE_A: "alert_only" } });
    assert.equal(cfg.projectRoot, s.repo);
    assert.deepEqual(cfg.repo, { rules: { RULE_B: "confirm" } });
  });

  it("never treats the user's own ~/.omnodex as a repository policy", () => {
    const s = scratch();
    writeJson(path.join(s.home, ".omnodex", "config.json"), { enforcement: { rules: { RULE_A: "deny" } } });
    const inHome = path.join(s.home, "projects", "x");
    fs.mkdirSync(inHome, { recursive: true });
    assert.equal(findRepoPolicy(inHome, s.home), null);
  });

  it("survives a malformed file", () => {
    const s = scratch();
    fs.writeFileSync(path.join(s.omnodexHome, "omnodex-config.json"), "{ not json");
    assert.equal(loadEnforcement({ home: s.omnodexHome, cwd: s.repo, userHome: s.home }).mode, "monitor");
  });
});

describe("community rules", () => {
  it("no rule holds a call by default yet: none carries a safe_alternative", () => {
    for (const r of COMMUNITY_RULES) {
      const v = resolveVerdict({ rule: r });
      assert.equal(v.action, "alert_only", r.rule_id);
    }
  });

  it("every rule that would hold a call in shadow mode is a candidate", () => {
    const candidates = COMMUNITY_RULES.filter((r) => resolveVerdict({ rule: r }).candidate !== "alert_only");
    assert.ok(candidates.length > 0);
    for (const r of candidates) assert.ok(r.blocking_hint === "deny" || r.blocking_hint === "confirm", r.rule_id);
  });
});

describe("annotateFindings", () => {
  const finding = (c, rule_id = "RULE_SELF_PROTECTION_CONFIG_WRITE", severity = "HIGH") => ({
    schema_version: 1,
    event_id: `evt-f-${c.tool_call_id}-${rule_id}`,
    session_id: c.session_id,
    occurred_at: c.occurred_at,
    recorded_at: c.recorded_at,
    interceptor: "analyzer",
    event_type: "risk.detected",
    severity,
    category: "x",
    description: "something",
    related_event_id: c.tool_call_id,
    rule_id,
  });
  const loaded = (enforcement) => () => ({ on_error: "allow", ...enforcement });

  it("stamps nothing in monitor mode, and returns the same array", () => {
    const c = bash("echo hi");
    const findings = [finding(c)];
    assert.equal(annotateFindings(findings, [c], { loaded: loaded({ mode: "monitor" }) }), findings);
  });

  it("shadow: a rule with a deny hint is recorded as a candidate, not in force", () => {
    const c = bash("echo hi");
    const [f] = annotateFindings([finding(c)], [c], { loaded: loaded({ mode: "shadow" }) });
    assert.deepEqual(f.enforcement, { mode: "shadow", candidate: "deny", action: "alert_only", held: false, source: "rule-hint" });
    assert.equal(wouldBlock(f.enforcement), true);
  });

  it("shadow: a finding with nothing to say is left as it was", () => {
    const c = bash("echo hi");
    const original = finding(c, "RULE_NO_HINT_HERE", "LOW");
    const [f] = annotateFindings([original], [c], { loaded: loaded({ mode: "shadow" }) });
    assert.equal(f, original);
  });

  it("an unknown rule (an advanced one) still answers to the user's overrides", () => {
    const c = bash("echo hi");
    const [f] = annotateFindings([finding(c, "RULE_ADVANCED_SOMETHING")], [c], {
      loaded: loaded({ mode: "shadow", user: { rules: { RULE_ADVANCED_SOMETHING: "deny" } } }),
    });
    assert.equal(f.enforcement.action, "deny");
  });

  it("a mute is recorded, and a muted finding does not count as would-block", () => {
    const c = bash("echo hi");
    const [f] = annotateFindings([finding(c)], [c], {
      loaded: loaded({ mode: "shadow", user: { exceptions: [{ rule_id: "RULE_SELF_PROTECTION_CONFIG_WRITE", kind: "mute" }] } }),
    });
    assert.equal(f.enforcement.muted, true);
    assert.equal(wouldBlock(f.enforcement), false);
  });

  it("a targeted exception sees the call the finding is about", () => {
    const allowed = bash("npm test");
    const other = bash("npm publish");
    const out = annotateFindings([finding(allowed), finding(other)], [allowed, other], {
      loaded: loaded({
        mode: "shadow",
        user: {
          rules: { RULE_SELF_PROTECTION_CONFIG_WRITE: "deny" },
          exceptions: [{ rule_id: "RULE_SELF_PROTECTION_CONFIG_WRITE", kind: "allow", target: { command_prefix: "npm test" } }],
        },
      }),
    });
    assert.equal(out[0].enforcement.candidate, "deny");
    assert.equal(out[0].enforcement.action, "alert_only");
    assert.equal(out[0].enforcement.source, "user-exception");
    assert.equal(out[1].enforcement.action, "deny");
  });

  it("held is only ever true in guardrails", () => {
    const v = { rule_id: "A", action: "deny", candidate: "deny", source: "user-rule", muted: false };
    assert.equal(enforcementRecord("shadow", v, true).held, false);
    assert.equal(enforcementRecord("guardrails", v, true).held, true);
    assert.equal(enforcementRecord("monitor", v, true), undefined);
  });

  it("a failure returns the findings unstamped", async () => {
    const c = bash("echo hi");
    const findings = [finding(c)];
    const errors = [];
    const out = annotateFindings(findings, [c], {
      loaded: () => {
        throw new Error("boom");
      },
      onError: (e) => errors.push(e),
    });
    assert.equal(out, findings);
    assert.equal(errors.length, 1);
    assert.deepEqual(await stampCaptured([], [c], { home: "/nonexistent" }), []);
  });
});

describe("rule signals at capture time", () => {
  it("writes only a day, a rule id and a kind, and never for a muted finding", async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-signals-"));
    const finding = (rule_id, enforcement) => ({ rule_id, enforcement, description: "read /home/case/.ssh/id_rsa" });
    await appendRuleSignals(home, [
      finding("RULE_A", { mode: "shadow", candidate: "deny", action: "alert_only", held: false, source: "rule-hint" }),
      finding("RULE_B", { mode: "shadow", candidate: "alert_only", action: "deny", held: false, source: "user-rule" }),
      finding("RULE_C", { mode: "shadow", candidate: "deny", action: "alert_only", held: false, source: "user-exception", muted: true }),
      finding("RULE_D", undefined),
    ], Date.parse("2026-10-18T10:00:00Z"));
    const text = fs.readFileSync(path.join(home, "rule-signals.jsonl"), "utf8");
    assert.deepEqual(text.trim().split("\n").map((l) => JSON.parse(l)), [
      { day: "2026-10-18", rule_id: "RULE_A", kind: "would_block" },
      { day: "2026-10-18", rule_id: "RULE_B", kind: "would_block" },
      { day: "2026-10-18", rule_id: "RULE_B", kind: "in_force" },
    ]);
    assert.doesNotMatch(text, /ssh|case/);
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe("enforceCaptured", () => {
  let n = 0;
  const newEventId = () => `evt-enf-new-${++n}`;
  const finding = (c, rule_id = "RULE_X", severity = "HIGH") => ({
    schema_version: 1, event_id: `f-${c.tool_call_id}-${rule_id}`, session_id: c.session_id, occurred_at: c.occurred_at,
    recorded_at: c.recorded_at, interceptor: "analyzer", event_type: "risk.detected", severity, category: "x",
    description: "something", related_event_id: c.tool_call_id, rule_id,
  });
  const loaded = (extra) => ({ mode: "guardrails", on_error: "allow", ...extra });
  // The module's decision is opaque here: these tests check what the public
  // side does with it.
  const module = {
    GUARDRAILS_INTERFACE: 1,
    decide: ({ host, verdicts, failure, onError }) => {
      if (failure) return onError === "block" ? { action: "deny", held: [], output: { stop: host } } : { action: "alert_only", held: [], output: null };
      const held = verdicts.filter((v) => v.action !== "alert_only").map((v) => v.rule_id);
      return held.length ? { action: "deny", held, output: { stop: host, held } } : { action: "alert_only", held: [], output: null };
    },
  };

  it("guardrails: hands the resolved verdicts to the module and stamps what it held", async () => {
    const c = bash("echo hi");
    const seen = [];
    const spy = { ...module, decide: (input) => { seen.push(input); return module.decide(input); } };
    const r = await enforceCaptured([finding(c, "RULE_A"), finding(c, "RULE_B")], [c], {
      host: "claude-code", newEventId, module: spy,
      loaded: loaded({ user: { rules: { RULE_A: "confirm" } } }),
    });
    assert.deepEqual(seen[0].verdicts.map((v) => [v.rule_id, v.action]), [["RULE_A", "confirm"], ["RULE_B", "alert_only"]]);
    assert.equal(seen[0].host, "claude-code");
    assert.deepEqual(r.output, { stop: "claude-code", held: ["RULE_A"] });
    assert.equal(r.findings[0].enforcement.held, true);
    assert.equal(r.findings[0].enforcement.mode, "guardrails");
    assert.equal(r.findings[1].enforcement, undefined);
  });

  it("guardrails without a module: recorded as shadow, nothing decided", async () => {
    const c = bash("echo hi");
    const r = await enforceCaptured([finding(c)], [c], { host: "claude-code", newEventId, module: null, loaded: loaded({ user: { rules: { RULE_X: "deny" } } }) });
    assert.equal(r.output, null);
    assert.equal(r.mode, "shadow");
    assert.deepEqual(r.findings[0].enforcement, { mode: "shadow", candidate: "alert_only", action: "deny", held: false, source: "user-rule" });
  });

  it("monitor and shadow never ask the module", async () => {
    const c = bash("echo hi");
    for (const mode of ["monitor", "shadow"]) {
      let asked = false;
      const r = await enforceCaptured([finding(c)], [c], {
        host: "claude-code", newEventId, module: { ...module, decide: () => { asked = true; return module.decide({ verdicts: [] }); } },
        loaded: loaded({ mode, user: { rules: { RULE_X: "deny" } } }),
      });
      assert.equal(r.output, null);
      assert.equal(asked, false);
    }
  });

  it("a failure records an enforcement error with the module's outcome", async () => {
    const c = bash("echo hi");
    const open = await enforceCaptured([], [c], { host: "codex", newEventId, failure: "timeout", module, loaded: loaded() });
    assert.equal(open.output, null);
    assert.equal(open.extra[0].event_type, "risk.enforcement_error");
    assert.equal(open.extra[0].outcome, "allowed");
    const closed = await enforceCaptured([], [c], { host: "antigravity", newEventId, failure: "error", module, loaded: loaded({ on_error: "block" }) });
    assert.deepEqual(closed.output, { stop: "antigravity" });
    assert.equal(closed.extra[0].outcome, "blocked");
  });

  it("a module that throws lets the call run", async () => {
    const c = bash("echo hi");
    const errors = [];
    const r = await enforceCaptured([finding(c)], [c], {
      host: "claude-code", newEventId, module: { ...module, decide: () => { throw new Error("boom"); } },
      loaded: loaded({ user: { rules: { RULE_X: "deny" } } }), onError: (e) => errors.push(e),
    });
    assert.equal(r.output, null);
    assert.equal(errors.length, 1);
  });

  it("without a tool call there is nothing to decide", async () => {
    const r = await enforceCaptured([], [], { host: "claude-code", newEventId, module, loaded: loaded() });
    assert.equal(r.output, null);
  });
});

describe("loadGuardrailsModule", () => {
  const home = () => fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-guardrails-"));

  it("opens a module signed by a trusted key with the right content key", async () => {
    const h = home();
    const { env } = installModule(h);
    const load = await loadGuardrailsModule(h, { env });
    assert.equal(load.skipped, undefined);
    assert.equal(typeof load.module.decide, "function");
    assert.match(describeGuardrails(load), /guardrails module 1\.0\.0/);
  });

  it("refuses what it cannot trust or open, without throwing", async () => {
    const cases = [
      [{}, (env) => ({ ...env, OMNODEX_GUARDRAILS_PUBLIC_KEY: undefined }), "untrusted_signature"],
      [{ tamper: true }, (env) => env, "payload_mismatch"],
      [{ notAfter: new Date(Date.now() - 1000).toISOString() }, (env) => env, "expired"],
      [{}, (env) => ({ ...env, OMNODEX_GUARDRAILS_KEY: undefined }), "no_key"],
      [{ interface: 2 }, (env) => env, "interface_mismatch"],
      [{ source: "export const nothing = 1;" }, (env) => env, "malformed_module"],
    ];
    for (const [overrides, envOf, reason] of cases) {
      const h = home();
      const { env } = installModule(h, overrides);
      const load = await loadGuardrailsModule(h, { env: envOf(env) });
      assert.equal(load.skipped, reason, JSON.stringify(overrides));
      assert.ok(describeGuardrails(load).length > 0);
    }
    assert.equal((await loadGuardrailsModule(home(), { env: {} })).skipped, "none_cached");
  });

  it("takes the key the license check gave for exactly this version", async () => {
    const h = home();
    const { env, contentKey } = installModule(h, { version: "2.1.0" });
    const pubOnly = { OMNODEX_GUARDRAILS_PUBLIC_KEY: env.OMNODEX_GUARDRAILS_PUBLIC_KEY };
    const grant = (module_version) => fs.writeFileSync(path.join(h, "license-cache.json"), JSON.stringify({
      response: { guardrails_module: { module_version, content_key: contentKey.toString("base64") } },
    }));
    grant("2.0.0");
    assert.equal((await loadGuardrailsModule(h, { env: pubOnly })).skipped, "no_key");
    grant("2.1.0");
    assert.equal((await loadGuardrailsModule(h, { env: pubOnly })).skipped, undefined);
  });

  it("a module's signature does not pass as another artifact's", async () => {
    const h = home();
    const { sealed, env } = installModule(h);
    const relabeled = { ...sealed, manifest: { ...sealed.manifest, module_version: "9.9.9" } };
    fs.writeFileSync(path.join(h, "guardrails", "current.module.json"), JSON.stringify(relabeled));
    assert.equal((await loadGuardrailsModule(h, { env })).skipped, "untrusted_signature");
  });
});
