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
