/**
 * RULE_THREAT_DESTRUCTIVE_COMMAND: commands that delete live data stores
 * (container volumes, databases, Redis), and that guardrails mode can hold
 * them.
 */

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_THREAT_DESTRUCTIVE_COMMAND } from "../../dist/rules/index.js";
import { resolveVerdict, enforceCaptured } from "../../dist/enforcement/index.js";

let n = 0;
function bash(command) {
  n++;
  return {
    schema_version: 1,
    event_id: `evt-ds-${n}`,
    session_id: "sess-ds",
    occurred_at: "2026-11-13T00:00:00.000Z",
    recorded_at: "2026-11-13T00:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-ds-${n}`,
    tool_name: "Bash",
    mcp_server: "builtin",
    parameters: { command },
  };
}
const engine = new RuleEngine([RULE_THREAT_DESTRUCTIVE_COMMAND]);
const run = (command) => engine.evaluate(bash(command));

const MUST_FIRE = [
  ["docker volume rm", "docker volume rm pgdata", "container-volume-delete"],
  ["docker volume rm many", "docker volume rm $(docker volume ls -q)", "container-volume-delete"],
  ["docker volume remove", "docker volume remove a b c", "container-volume-delete"],
  ["docker volume prune", "docker volume prune -f", "container-volume-delete"],
  ["docker with a global flag", "docker --context prod volume prune --force", "container-volume-delete"],
  ["docker volume prune after another command", "cd app && docker volume prune -f", "container-volume-delete"],
  ["inside bash -c", "bash -c 'docker volume prune -f'", "container-volume-delete"],
  ["inside ssh", "ssh dev 'docker volume rm data'", "container-volume-delete"],
  ["sudo podman volume rm", "sudo podman volume rm db", "container-volume-delete"],
  ["podman volume prune", "podman volume prune", "container-volume-delete"],
  ["docker system prune with volumes", "docker system prune -af --volumes", "container-system-prune-volumes"],
  ["podman system prune with volumes", "podman system prune --volumes", "container-system-prune-volumes"],
  ["compose down -v", "docker compose down -v", "compose-down-volumes"],
  ["compose down --volumes", "docker compose -f dev.yml down --volumes --remove-orphans", "compose-down-volumes"],
  ["compose down with a flag cluster", "docker-compose down --rmi local -v", "compose-down-volumes"],
  ["podman compose down -v", "podman-compose down -v", "compose-down-volumes"],
  ["dropdb", "dropdb -U postgres app_dev", "database-drop"],
  ["dropdb with sudo -u", "sudo -u postgres dropdb app", "database-drop"],
  ["mysqladmin drop", "mysqladmin -uroot drop shop", "database-drop"],
  ["psql -c DROP DATABASE", `psql -U postgres -c "DROP DATABASE app_dev"`, "database-drop"],
  ["psql drop database lowercase", `psql -c "drop database if exists app"`, "database-drop"],
  ["psql DROP SCHEMA CASCADE", `psql $DATABASE_URL -c 'DROP SCHEMA public CASCADE'`, "database-drop"],
  ["mysql -e DROP DATABASE", `mysql -uroot -e "DROP DATABASE shop"`, "database-drop"],
  ["sqlite3 with DROP SCHEMA", `sqlite3 dev.db "DROP SCHEMA x"`, "database-drop"],
  ["statement piped into psql", `echo "DROP DATABASE app;" | psql`, "database-drop"],
  ["heredoc into psql", "psql app <<'SQL'\nSELECT 1;\nDROP DATABASE app;\nSQL", "database-drop"],
  ["mongo dropDatabase", `mongosh --eval "db.dropDatabase()"`, "database-drop"],
  ["redis-cli FLUSHALL", "redis-cli FLUSHALL", "redis-flush"],
  ["redis-cli flushall with host and async", "redis-cli -h cache.local flushall async", "redis-flush"],
  ["redis-cli FLUSHDB", "redis-cli -n 2 FLUSHDB", "redis-flush"],
  ["FLUSHALL piped to redis-cli", "echo FLUSHALL | redis-cli", "redis-flush"],
  ["valkey-cli FLUSHALL", "valkey-cli FLUSHALL", "redis-flush"],
];

const MUST_NOT_FIRE = [
  ["docker volume ls", "docker volume ls"],
  ["docker volume inspect", "docker volume inspect pgdata"],
  ["docker volume create", "docker volume create pgdata"],
  ["docker system prune without volumes", "docker system prune -af"],
  ["docker container prune", "docker container prune -f"],
  ["docker image prune", "docker image prune -a"],
  ["compose down", "docker compose down"],
  ["compose down --remove-orphans", "docker compose down --remove-orphans"],
  ["compose up -v is a different flag", "docker compose up -d -v"],
  ["compose logs", "docker compose logs -f"],
  ["psql select", `psql -c "SELECT * FROM users"`],
  ["psql DROP TABLE", `psql -c "DROP TABLE tmp_report"`],
  ["psql list databases", "psql -l"],
  ["createdb", "createdb app_dev"],
  ["DROP DATABASE in a sql file, no client", "cat migrations/0001.sql"],
  ["redis-cli get", "redis-cli GET session:1"],
  ["redis-cli keys", "redis-cli KEYS 'user:*'"],
  ["git commit mentioning docker volume prune", `git commit -m "docs: explain docker volume prune"`],
  ["gh pr body mentioning compose down -v", `gh pr create --title "x" --body "Avoid docker compose down -v in CI"`],
  ["echo of a dropdb command", `echo "run dropdb app to reset"`],
  ["git commit with FLUSHALL in message", `git commit -m "document redis-cli FLUSHALL risk"`],
  ["docker run", "docker run --rm -v data:/data alpine ls /data"],
  ["rm of a build dir", "rm -rf node_modules dist"],
];

describe("data store destruction: MUST_FIRE", () => {
  for (const [name, command, type] of MUST_FIRE) {
    test(name, () => {
      const findings = run(command);
      assert.equal(findings.length, 1, `no finding for: ${command}`);
      assert.equal(findings[0].severity, "HIGH");
      assert.ok(findings[0].description.includes(type), `expected ${type} in: ${findings[0].description}`);
    });
  }
});

describe("data store destruction: MUST_NOT_FIRE", () => {
  for (const [name, command] of MUST_NOT_FIRE) {
    test(name, () => {
      assert.deepEqual(run(command), [], `unexpected finding for: ${command}`);
    });
  }
});

describe("data store destruction: guardrails mode", () => {
  const finding = (c) => run(c.parameters.command).map((f) => ({ ...f, related_event_id: c.tool_call_id }));

  test("the rule's candidate verdict is deny", () => {
    assert.equal(resolveVerdict({ rule: RULE_THREAT_DESTRUCTIVE_COMMAND }).candidate, "deny");
  });

  test("a policy entry that denies the rule holds a docker volume prune", () => {
    const v = resolveVerdict({
      rule: RULE_THREAT_DESTRUCTIVE_COMMAND,
      config: { user: { rules: { RULE_THREAT_DESTRUCTIVE_COMMAND: "deny" } } },
    });
    assert.equal(v.action, "deny");
  });

  test("guardrails holds the call through the module", async () => {
    const c = bash("docker volume prune -f");
    const module = {
      GUARDRAILS_INTERFACE: 1,
      decide: ({ host, verdicts }) => {
        const held = verdicts.filter((v) => v.action !== "alert_only").map((v) => v.rule_id);
        return held.length ? { action: "deny", held, output: { stop: host, held } } : { action: "alert_only", held: [], output: null };
      },
    };
    let k = 0;
    const result = await enforceCaptured(finding(c), [c], {
      host: "claude-code",
      newEventId: () => `evt-ds-new-${++k}`,
      module,
      loaded: { mode: "guardrails", on_error: "allow", user: { rules: { RULE_THREAT_DESTRUCTIVE_COMMAND: "deny" } } },
    });
    assert.deepEqual(result.output, { stop: "claude-code", held: ["RULE_THREAT_DESTRUCTIVE_COMMAND"] });
    assert.equal(result.findings[0].enforcement.held, true);
  });
});
