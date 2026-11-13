/**
 * Session start check of the project's .claude/settings.local.json: finds a
 * credential saved by "Yes, and don't ask again", says whether the
 * repository's own ignore rules cover it and whether git tracks it, and
 * never puts the value in the finding.
 */

import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectSettingsLocal, settingsSecretFinding, SETTINGS_SECRET_RULE_ID } from "../dist/settings-secret-check.js";

// A made-up token in the GitHub personal access token format.
const SECRET = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";
const approved = (command) => JSON.stringify({ permissions: { allow: [`Bash(${command})`] } }, null, 2);

let root;
let home;
beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "omnodex-settings-"));
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-home-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

const git = (args) => execFileSync("git", args, { cwd: root, stdio: "pipe" });
async function project({ settings = approved(`curl -H "Authorization: token ${SECRET}" https://api.github.com/user`), gitignore, repo = true, exclude } = {}) {
  if (repo) git(["init", "-q"]);
  await mkdir(path.join(root, ".claude"), { recursive: true });
  if (settings !== null) await writeFile(path.join(root, ".claude", "settings.local.json"), settings);
  if (gitignore !== undefined) await writeFile(path.join(root, ".gitignore"), gitignore);
  if (exclude !== undefined) await writeFile(path.join(root, ".git", "info", "exclude"), exclude);
}
let n = 0;
const finding = () => settingsSecretFinding({ project: root, sessionId: "s1", relatedEventId: "e1", home, newEventId: () => `evt-${++n}` });

describe("settings.local.json check: what is reported", () => {
  test("a credential in an unignored file in a repo is MEDIUM and names the type, not the value", async () => {
    await project();
    const f = await finding();
    assert.equal(f.event_type, "risk.detected");
    assert.equal(f.rule_id, SETTINGS_SECRET_RULE_ID);
    assert.equal(f.rule_tier, "community");
    assert.equal(f.severity, "MEDIUM");
    assert.match(f.description, /github-pat/);
    assert.match(f.description, /does not cover it/);
    assert.ok(!JSON.stringify(f).includes(SECRET), "the value must not be in the event");
    assert.ok(!JSON.stringify(f).includes(SECRET.slice(4, 20)), "no fragment of the value either");
  });

  test("a bearer token inside escaped JSON quotes is found", async () => {
    await project({ settings: approved(`curl -H \\"Authorization: Bearer ${"aB3dE5fG7hJ9kL1mN3pQ5rS7"}\\" https://x.test`) });
    const f = await finding();
    assert.ok(f, "expected a finding");
    assert.match(f.description, /bearer/);
  });

  test("covered by the repository's .gitignore is LOW", async () => {
    await project({ gitignore: ".claude/settings.local.json\n" });
    const f = await finding();
    assert.equal(f.severity, "LOW");
    assert.match(f.description, /covers it/);
  });

  test("tracked by git is HIGH, even when an ignore rule exists", async () => {
    await project({ gitignore: ".claude/settings.local.json\n" });
    git(["add", "-f", ".claude/settings.local.json"]);
    const f = await finding();
    assert.equal(f.severity, "HIGH");
    assert.match(f.description, /already tracks/);
  });

  test("outside a git repository is LOW", async () => {
    await project({ repo: false });
    const f = await finding();
    assert.equal(f.severity, "LOW");
    assert.match(f.description, /not in a git repository/);
  });
});

describe("settings.local.json check: MUST_NOT_FIRE", () => {
  test("no file", async () => {
    await project({ settings: null });
    assert.equal(await finding(), null);
  });

  test("a file with no credential", async () => {
    await project({ settings: approved("npm test") });
    assert.equal(await finding(), null);
  });

  test("a placeholder is not a credential", async () => {
    await project({ settings: approved('curl -H "Authorization: token ${GITHUB_TOKEN}" https://api.github.com') });
    assert.equal(await finding(), null);
  });

  test("an unreadable (not JSON) file with no credential", async () => {
    await project({ settings: "not json at all" });
    assert.equal(await finding(), null);
  });
});

describe("settings.local.json check: repository ignore rules", () => {
  const covered = [
    [".claude/settings.local.json", "full path"],
    ["/.claude/settings.local.json", "anchored full path"],
    [".claude/", "the folder"],
    [".claude", "the folder name"],
    ["/.claude", "anchored folder"],
    [".claude/*", "everything in the folder"],
    ["settings.local.json", "bare file name"],
    ["*.local.json", "glob on the name"],
    [".claude/*.local.json", "glob in the folder"],
    ["**/settings.local.json", "any depth"],
    ["**/.claude/settings.local.*", "any depth, extension glob"],
    ["# comment\n\n.claude/settings.local.json   \n", "comments, blanks and trailing space"],
  ];
  for (const [rule, name] of covered) {
    test(`covered: ${name}`, async () => {
      await project({ gitignore: rule + "\n" });
      assert.equal((await inspectSettingsLocal(root)).ignored, true, rule);
    });
  }

  const notCovered = [
    [".claude/settings.json", "only the shared settings file"],
    ["settings.local.yaml", "a different extension"],
    ["/settings.local.json", "anchored at the root, where the file is not"],
    [".claude/settings.local.json\n!.claude/settings.local.json", "re-included by a later rule"],
    ["docs/", "an unrelated folder"],
    ["node_modules\ndist", "other entries"],
  ];
  for (const [rule, name] of notCovered) {
    test(`not covered: ${name}`, async () => {
      await project({ gitignore: rule + "\n" });
      assert.equal((await inspectSettingsLocal(root)).ignored, false, rule);
    });
  }

  test("no .gitignore at all", async () => {
    await project();
    assert.equal((await inspectSettingsLocal(root)).ignored, false);
  });

  test(".git/info/exclude counts", async () => {
    await project({ exclude: ".claude/settings.local.json\n" });
    assert.equal((await inspectSettingsLocal(root)).ignored, true);
  });

  test("a .gitignore above the project folder applies to a rule that matches at any depth", async () => {
    git(["init", "-q"]);
    await writeFile(path.join(root, ".gitignore"), ".claude/\n");
    const sub = path.join(root, "packages", "app");
    await mkdir(path.join(sub, ".claude"), { recursive: true });
    await writeFile(path.join(sub, ".claude", "settings.local.json"), approved(`echo ${SECRET}`));
    assert.equal((await inspectSettingsLocal(sub)).ignored, true);
  });

  test("a path rule in the root .gitignore is anchored to the root, not the project folder", async () => {
    git(["init", "-q"]);
    await writeFile(path.join(root, ".gitignore"), ".claude/settings.local.json\n");
    const sub = path.join(root, "packages", "app");
    await mkdir(path.join(sub, ".claude"), { recursive: true });
    await writeFile(path.join(sub, ".claude", "settings.local.json"), approved(`echo ${SECRET}`));
    assert.equal((await inspectSettingsLocal(sub)).ignored, false);
  });

  test("a .gitignore in the project folder can re-include", async () => {
    git(["init", "-q"]);
    await writeFile(path.join(root, ".gitignore"), "settings.local.json\n");
    const sub = path.join(root, "app");
    await mkdir(path.join(sub, ".claude"), { recursive: true });
    await writeFile(path.join(sub, ".gitignore"), "!settings.local.json\n");
    await writeFile(path.join(sub, ".claude", "settings.local.json"), approved(`echo ${SECRET}`));
    assert.equal((await inspectSettingsLocal(sub)).ignored, false);
  });
});

describe("settings.local.json check: reported once per change", () => {
  test("the same state is not reported again", async () => {
    await project();
    assert.ok(await finding());
    assert.equal(await finding(), null);
  });

  test("a change in ignore state is reported again", async () => {
    await project();
    assert.equal((await finding()).severity, "MEDIUM");
    await writeFile(path.join(root, ".gitignore"), ".claude/settings.local.json\n");
    assert.equal((await finding()).severity, "LOW");
  });

  test("a new credential type is reported again", async () => {
    await project();
    await finding();
    await writeFile(
      path.join(root, ".claude", "settings.local.json"),
      approved(`curl -H "Authorization: token ${SECRET}" -u AKIAQ7XK2M9PZ4TW6B3N:x https://x.test`),
    );
    const f = await finding();
    assert.ok(f);
    assert.match(f.description, /aws-key/);
  });

  test("cleaning the file clears the state, so a later leak is reported", async () => {
    await project();
    await finding();
    await writeFile(path.join(root, ".claude", "settings.local.json"), approved("npm test"));
    assert.equal(await finding(), null);
    await writeFile(path.join(root, ".claude", "settings.local.json"), approved(`echo ${SECRET}`));
    assert.ok(await finding());
  });

  test("a failing scan or git lookup means no finding, not an error", async () => {
    await project();
    const f = await settingsSecretFinding({
      project: root, sessionId: "s", relatedEventId: "e", home, newEventId: () => "x",
      options: { scan: () => { throw new Error("boom"); } },
    });
    assert.equal(f, null);
  });
});

describe("settings.local.json check: through the hook shim", () => {
  const SHIM = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "bin", "claude-hook-shim.js");
  const run = (payload, env) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM], {
      env: { ...process.env, OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0", ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
  const log = async (sessionId) =>
    (await readFile(path.join(home, "event-log", "sessions", `${sessionId}.jsonl`), "utf8"))
      .split("\n").filter(Boolean).map((l) => JSON.parse(l));

  test("SessionStart writes the finding next to session.started, without the value", async () => {
    await project();
    const res = await run({ session_id: "shim-1", cwd: root, hook_event_name: "SessionStart", user: "case" }, { OMNODEX_HOME: home });
    assert.equal(res.code, 0, res.stderr);
    const events = await log("shim-1");
    const found = events.filter((e) => e.rule_id === SETTINGS_SECRET_RULE_ID);
    assert.equal(found.length, 1);
    assert.equal(found[0].severity, "MEDIUM");
    assert.ok(events.some((e) => e.event_type === "session.started"));
    assert.ok(!JSON.stringify(events).includes(SECRET));
    // A second session in the same project does not repeat it.
    await run({ session_id: "shim-2", cwd: root, hook_event_name: "SessionStart", user: "case" }, { OMNODEX_HOME: home });
    assert.ok(!(await log("shim-2")).some((e) => e.rule_id === SETTINGS_SECRET_RULE_ID));
  });

  test("a clean project writes no finding", async () => {
    await project({ settings: approved("npm test") });
    await run({ session_id: "shim-3", cwd: root, hook_event_name: "SessionStart", user: "case" }, { OMNODEX_HOME: home });
    assert.ok(!(await log("shim-3")).some((e) => e.rule_id === SETTINGS_SECRET_RULE_ID));
  });
});
