/**
 * Input validation attack detection rule unit tests.
 *
 * Covers:
 *   RULE_INPUT_VALIDATION_SQL_INJECTION -- SQL injection in MCP tool parameters (HIGH)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_INPUT_VALIDATION_SQL_INJECTION } from "../../dist/rules/index.js";

function makeDbEvent(toolName, mcpServer, parameters, sessionId = "sess-sql-test") {
  return {
    schema_version: 1,
    event_id: `evt-${Math.random().toString(36).slice(2)}`,
    session_id: sessionId,
    occurred_at: "2026-05-15T00:00:00.000Z",
    recorded_at: "2026-05-15T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: `tc-${Math.random().toString(36).slice(2)}`,
    tool_name: toolName,
    mcp_server: mcpServer,
    parameters,
  };
}

const sqlEngine = new RuleEngine([RULE_INPUT_VALIDATION_SQL_INJECTION]);

// ---------------------------------------------------------------------------
// MUST FIRE -- SQL injection patterns in DB server tool calls
// ---------------------------------------------------------------------------

test("SQL_INJECTION: fires for UNION SELECT in postgres MCP server query", () => {
  const event = makeDbEvent("mcp__postgres__query", "postgres", {
    query: "SELECT name FROM users WHERE id = '1' UNION SELECT password FROM admin--",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "input_validation");
  assert.ok(findings[0].description.includes("sql-union-inject"), findings[0].description);
});

test("SQL_INJECTION: fires for UNION ALL SELECT variant", () => {
  const event = makeDbEvent("mcp__mysql__execute", "mysql", {
    sql: "' UNION ALL SELECT table_name FROM information_schema.tables--",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-union-inject"), findings[0].description);
});

test("SQL_INJECTION: fires for comment-based injection pattern", () => {
  const event = makeDbEvent("mcp__db__run_query", "db", {
    query: "SELECT * FROM users WHERE username = 'admin';-- and password = ''",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-comment-inject"), findings[0].description);
});

test("SQL_INJECTION: fires for boolean tautology OR 1=1", () => {
  const event = makeDbEvent("mcp__sqlite__query", "sqlite", {
    statement: "SELECT * FROM secrets WHERE category = 'api' OR 1=1",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-boolean-inject"), findings[0].description);
});

test("SQL_INJECTION: fires for stacked query with DROP TABLE", () => {
  const event = makeDbEvent("mcp__rds__execute", "rds", {
    query: "UPDATE users SET name='x'; DROP TABLE audit_log--",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-stacked-query"), findings[0].description);
});

test("SQL_INJECTION: fires for SLEEP() time-based blind injection", () => {
  const event = makeDbEvent("mcp__doris__query", "doris", {
    sql: "SELECT * FROM products WHERE id = 1 AND SLEEP(5)--",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-time-based-inject"), findings[0].description);
});

test("SQL_INJECTION: fires for PG_SLEEP() in postgres-named server", () => {
  const event = makeDbEvent("mcp__pg__query", "pg", {
    query: "SELECT 1 FROM users WHERE id=1 AND PG_SLEEP(10)--",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-time-based-inject"), findings[0].description);
});

test("SQL_INJECTION: fires for LOAD_FILE out-of-band exfil pattern", () => {
  const event = makeDbEvent("mcp__mysql__execute", "mysql", {
    sql: "SELECT LOAD_FILE('/etc/passwd')",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-oob-exfil"), findings[0].description);
});

test("SQL_INJECTION: fires for server names with 'sql' substring", () => {
  const event = makeDbEvent("mcp__mssql__run", "mssql", {
    query: "SELECT * FROM users UNION SELECT password, null FROM admin--",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
});

test("SQL_INJECTION: fires for bigquery server with stacked query", () => {
  const event = makeDbEvent("mcp__bigquery__query", "bigquery", {
    sql: "SELECT id; DELETE FROM users WHERE 1=1",
  });
  const findings = sqlEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("sql-stacked-query"), findings[0].description);
});

// ---------------------------------------------------------------------------
// MUST NOT FIRE -- legitimate queries or wrong server type
// ---------------------------------------------------------------------------

test("SQL_INJECTION: does NOT fire for legitimate SELECT on a DB server", () => {
  const event = makeDbEvent("mcp__postgres__query", "postgres", {
    query: "SELECT id, name, email FROM users WHERE status = 'active' ORDER BY created_at DESC LIMIT 10",
  });
  assert.equal(sqlEngine.evaluate(event).length, 0);
});

test("SQL_INJECTION: does NOT fire for SQL injection pattern on a non-DB MCP server", () => {
  // filesystem MCP server doesn't match the DB server pattern
  const event = makeDbEvent("mcp__filesystem__read", "filesystem", {
    query: "SELECT * FROM users UNION SELECT password FROM admin",
  });
  assert.equal(sqlEngine.evaluate(event).length, 0);
});

test("SQL_INJECTION: does NOT fire for SQL patterns on builtin tools", () => {
  const event = makeDbEvent("bash", "builtin", {
    command: "echo 'UNION SELECT' > /tmp/test.sql",
  });
  assert.equal(sqlEngine.evaluate(event).length, 0);
});

test("SQL_INJECTION: does NOT fire for legitimate parametrized-style query on DB server", () => {
  const event = makeDbEvent("mcp__mysql__query", "mysql", {
    query: "SELECT * FROM orders WHERE user_id = $1 AND status = $2",
    params: ["user-123", "pending"],
  });
  assert.equal(sqlEngine.evaluate(event).length, 0);
});

test("SQL_INJECTION: does NOT fire for OR in a legitimate context without tautology", () => {
  const event = makeDbEvent("mcp__postgres__query", "postgres", {
    query: "SELECT * FROM logs WHERE level = 'error' OR level = 'warn'",
  });
  assert.equal(sqlEngine.evaluate(event).length, 0);
});

// Each named signature, case folding, spacing and comment terminator variant.
const signatures = [
  ["sql-union-inject", "UNION SELECT secret FROM users"],
  ["sql-union-inject", "uNiOn   aLl   sElEcT secret FROM users"],
  ...["--", "#", "/* comment */"].map(comment => ["sql-comment-inject", `';   ${comment}`]),
  ["sql-boolean-inject", "oR   1 = 1 -- comment"],
  ...["DROP", "DELETE", "INSERT", "UPDATE", "CREATE", "ALTER", "TRUNCATE"]
    .map(verb => ["sql-stacked-query", `;   ${verb.toLowerCase()} table_name`]),
  ...["SLEEP", "BENCHMARK", "PG_SLEEP", "WAITFOR DELAY"]
    .map(fn => ["sql-time-based-inject", `${fn.toLowerCase()} (5)`]),
  ...["LOAD_FILE", "UTL_HTTP", "UTL_INADDR", "UTL_FILE"]
    .map(fn => ["sql-oob-exfil", `${fn.toLowerCase()} ('case')`]),
];
for (const [signature, query] of signatures) {
  test(`SQL_INJECTION MUST_FIRE: ${signature}: ${query}`, () => {
    const findings = sqlEngine.evaluate(makeDbEvent("query", "postgres-case", { query }));
    assert.equal(findings.length, 1);
    assert.match(findings[0].description, new RegExp(signature));
  });
}

for (const server of ["filesystem", "github", "browser", "builtin"]) {
  test(`SQL_INJECTION MUST_NOT_FIRE: injection documentation on ${server}`, () => {
    assert.equal(sqlEngine.evaluate(makeDbEvent("write_documentation", server, {
      content: "SQL examples: UNION SELECT, OR 1=1, ';--, ; DROP TABLE, SLEEP(5), LOAD_FILE('case')",
    })).length, 0);
  });
}
for (const query of [
  "SELECT * FROM users WHERE id = ?", "INSERT INTO users(name) VALUES ('case')",
  "UPDATE users SET name = 'case' WHERE id = 1", "DELETE FROM users WHERE id = 1",
  "SELECT union_selector, sleep_count FROM metrics WHERE error = 1 OR warning = 1",
  "SELECT * FROM users /* ordinary comment */ WHERE id = 1",
]) {
  test(`SQL_INJECTION MUST_NOT_FIRE: ordinary query ${query}`, () => {
    assert.equal(sqlEngine.evaluate(makeDbEvent("query", "postgres", { query })).length, 0);
  });
}

// Keep bypass cases executable without changing the rule in this test-only task.
// TODO assertions describe desired behavior; the separate detection fix owns them.
for (const query of [
  "UNION\tSELECT secret FROM users", "UNION\nSELECT secret FROM users",
  "UNION/**/SELECT secret FROM users", "OR/**/1=1",
  "UNION%20SELECT%20secret%20FROM%20users", "OR%201%3D1",
  "WAITFOR DELAY '00:00:05'", "UTL_HTTP.REQUEST('https://example.com')",
]) {
  test(`SQL_INJECTION MUST_FIRE known gap: ${JSON.stringify(query)}`, { todo: "normalization or signature coverage requires a separate rule change" }, () => {
    assert.equal(sqlEngine.evaluate(makeDbEvent("query", "postgres", { query })).length, 1);
  });
}
test("SQL_INJECTION MUST_NOT_FIRE known gap: documentation field on database server", { todo: "all-field scope also scans documentation text" }, () => {
  assert.equal(sqlEngine.evaluate(makeDbEvent("describe_schema", "postgres", {
    documentation: "Prevent SQL injection such as UNION SELECT and OR 1=1.",
  })).length, 0);
});
test("SQL_INJECTION MUST_FIRE known gap: uppercase database server", { todo: "server regex lacks case-insensitive matching" }, () => {
  assert.equal(sqlEngine.evaluate(makeDbEvent("query", "POSTGRES", { query: "UNION SELECT secret FROM users" })).length, 1);
});
