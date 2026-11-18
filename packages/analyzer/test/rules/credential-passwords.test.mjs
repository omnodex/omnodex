/**
 * Passwords in connection strings and after password flags, for
 * RULE_CREDENTIAL_IN_PARAMS.
 *
 * Every form it reports has a MUST_FIRE case, and every stand-in or look-alike
 * that must stay quiet has a MUST_NOT_FIRE case. The values are made up.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CREDENTIAL_IN_PARAMS, CREDENTIAL_PATTERNS } from "../../dist/rules/index.js";
import { findCredentials } from "../../dist/conditions/credential-match.js";
import { maskSecretsInText } from "../../dist/mask-secrets.js";

const engine = new RuleEngine([RULE_CREDENTIAL_IN_PARAMS]);

function makeEvent(parameters = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-05-01T00:00:00.000Z",
    recorded_at: "2026-05-01T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: "Bash",
    mcp_server: "",
    parameters,
  };
}

const PW = "Rk7vQ2mXp9";

// [description, command, expected type label]
const MUST_FIRE = [
  // Connection strings.
  ["postgres URL", `psql postgres://app:${PW}@db.internal:5432/orders`, "connection-string"],
  ["postgresql URL", `DATABASE_URL=postgresql://app:${PW}@db.internal/orders`, "connection-string"],
  ["SQLAlchemy driver suffix", `engine = create_engine("postgresql+psycopg2://app:${PW}@db/orders")`, "connection-string"],
  ["mongodb URL", `mongosh mongodb://admin:${PW}@mongo1:27017/admin`, "connection-string"],
  ["mongodb+srv URL", `mongodb+srv://admin:${PW}@cluster0.example.net/test`, "connection-string"],
  ["mysql URL", `mysql://root:${PW}@127.0.0.1:3306/shop`, "connection-string"],
  ["mariadb URL", `mariadb://root:${PW}@127.0.0.1/shop`, "connection-string"],
  ["redis URL with a user", `redis://default:${PW}@cache:6379/0`, "connection-string"],
  ["redis URL with no user", `redis-cli -u redis://:${PW}@cache:6379`, "connection-string"],
  ["rediss URL", `rediss://default:${PW}@cache.example.net:6380`, "connection-string"],
  ["amqp URL", `amqp://guest:${PW}@rabbit:5672/vhost`, "connection-string"],
  ["amqps URL", `amqps://svc:${PW}@rabbit.example.net/`, "connection-string"],
  ["mssql URL", `mssql://sa:${PW}@sql01:1433/master`, "connection-string"],
  ["templated user, real password", `postgres://\${DB_USER}:${PW}@db/orders`, "connection-string"],
  ["URL-encoded password", `postgres://app:p%40ss${PW}@db/orders`, "connection-string"],
  ["JDBC-style prefix", `jdbc:mysql://app:${PW}@db:3306/shop`, "connection-string"],
  // Password flags.
  ["mysql -p attached", `mysql -u root -p${PW} shop`, "password"],
  ["mysql -p attached first", `mysql -p${PW} -h db shop`, "password"],
  ["mysqldump -p attached", `mysqldump -u root -p${PW} shop > shop.sql`, "password"],
  ["mysql -p single-quoted", `mysql -u root -p'${PW}' shop`, "password"],
  ["mysql -p double-quoted in JSON", `mysql -u root -p"${PW}" shop`, "password"],
  ["mysqladmin -p attached", `mysqladmin -uroot -p${PW} status`, "password"],
  ["mariadb-dump -p attached", `mariadb-dump -u root -p${PW} shop`, "password"],
  ["sshpass -p with a space", `sshpass -p ${PW} ssh deploy@host uptime`, "password"],
  ["sshpass -p attached", `sshpass -p${PW} ssh deploy@host`, "password"],
  ["sshpass -p quoted", `sshpass -p '${PW}' scp file deploy@host:/tmp`, "password"],
  ["sshpass with an option first", `sshpass -v -p ${PW} ssh deploy@host`, "password"],
  ["sshpass with a prompt option first", `sshpass -P assword -p ${PW} ssh deploy@host`, "password"],
  ["--password with a space", `docker login registry.example.net -u svc --password ${PW}`, "password"],
  ["--password=", `az login --service-principal --password=${PW}`, "password"],
  ["--passphrase with a space", `gpg --batch --passphrase ${PW} --decrypt file.gpg`, "password"],
  // Environment variables.
  ["PGPASSWORD prefix", `PGPASSWORD=${PW} psql -h db -U app orders`, "password"],
  ["MYSQL_PWD prefix", `MYSQL_PWD=${PW} mysqldump shop`, "password"],
  ["SSHPASS variable", `SSHPASS=${PW} sshpass -e ssh deploy@host`, "password"],
  ["REDISCLI_AUTH variable", `REDISCLI_AUTH=${PW} redis-cli ping`, "password"],
];

for (const [desc, command, expectedType] of MUST_FIRE) {
  test(`detects ${desc}`, () => {
    const findings = engine.evaluate(makeEvent({ command }));
    assert.equal(findings.length, 1, `expected 1 finding for ${desc}`);
    assert.equal(findings[0].severity, "MEDIUM");
    assert.ok(
      findings[0].description.includes(expectedType),
      `description "${findings[0].description}" should include "${expectedType}"`,
    );
  });
}

test("the reported value is the password alone", () => {
  const cases = [
    [`psql postgres://app:${PW}@db/orders`, PW],
    [`mysql -u root -p${PW} shop`, PW],
    [`sshpass -p ${PW} ssh host`, PW],
    [`mysql -u root -p'${PW}' shop`, PW],
  ];
  for (const [text, want] of cases) {
    const values = findCredentials(JSON.stringify({ command: text }), CREDENTIAL_PATTERNS).map((c) => c.value);
    assert.deepEqual(values, [want], text);
  }
});

test("the same password in a flag is reported once", () => {
  const cmd = `PGPASSWORD=${PW} psql postgres://app:${PW}@db/orders`;
  const found = findCredentials(JSON.stringify({ command: cmd }), CREDENTIAL_PATTERNS);
  assert.equal(found.length, 1);
});

test("a vendor token as the URL password keeps its vendor label", () => {
  const token = "ghp_" + "Zx9Lm2Qr7Tv4Wb8Nc1Hd5Kf3Jg6Ps0Ya2Ue4";
  const found = findCredentials(JSON.stringify({ command: `redis://default:${token}@cache:6379` }), CREDENTIAL_PATTERNS);
  assert.deepEqual(found.map((c) => c.type), ["github-pat"]);
});

test("masking at capture replaces the password in each form and leaves the rest", () => {
  const fp = () => "fp1";
  for (const text of [
    `psql postgres://app:${PW}@db:5432/orders`,
    `mysql -u root -p${PW} shop`,
    `sshpass -p ${PW} ssh deploy@host`,
    `docker login --password ${PW}`,
  ]) {
    const out = maskSecretsInText(text, fp);
    assert.ok(!out.includes(PW), `value still present: ${out}`);
    assert.ok(out.includes("[omnodex:secret:"), out);
  }
  assert.match(maskSecretsInText(`psql postgres://app:${PW}@db:5432/orders`, fp), /^psql postgres:\/\/app:\[omnodex:secret:connection-string:.*\]@db:5432\/orders$/);
});

const MUST_NOT_FIRE = [
  // Placeholders in a connection string.
  ["user:password@", "psql postgres://user:password@localhost/db"],
  ["USERNAME:PASSWORD@", "mongodb://USERNAME:PASSWORD@host:27017/db"],
  ["user:pass@", "redis://user:pass@localhost:6379"],
  ["user:pwd@", "mysql://user:pwd@localhost/db"],
  ["variable reference", "postgres://app:${DB_PASS}@db/orders"],
  ["shell variable", "postgres://app:$DB_PASS@db/orders"],
  ["shell variable in quotes", 'postgres://app:"$DB_PASS"@db/orders'],
  ["windows variable", "postgres://app:%DB_PASS%@db/orders"],
  ["angle-bracket template", "postgres://<user>:<password>@db/orders"],
  ["bracket template", "mongodb://[user]:[password]@db/orders"],
  ["brace template", "mongodb://{user}:{password}@db/orders"],
  ["masked with stars", "postgres://app:*****@db/orders"],
  ["redacted", "postgres://app:redacted@db/orders"],
  ["your password", "postgres://app:your-password-here@db/orders"],
  ["changeme", "mysql://root:changeme@db/orders"],
  ["underscore identifier", "postgres://app:db_password@db/orders"],
  ["Python format field", "postgres://app:%(password)s@db/orders"],
  ["JS template", "`postgres://app:${process.env.DB_PASSWORD}@db/orders`"],
  // Connection strings that carry no password.
  ["no credentials", "psql postgres://db.internal:5432/orders"],
  ["user only", "psql postgres://app@db.internal:5432/orders"],
  ["host and port", "redis://cache:6379/0"],
  ["port list", "mongodb://h1:27017,h2:27017,h3:27017/db?replicaSet=rs0"],
  ["email after a URL", "redis://cache:6379 notify ops@example.org"],
  ["password-free redis URL", "redis-cli -u redis://cache.example.net:6379"],
  // A scheme that is not a data store is outside this pattern.
  ["https URL", "curl https://user:hunter2abc@example.org/"],
  // Password flags with no value, or one that is not a password.
  ["mysql -p then a database name", "mysql -u root -p shop"],
  ["mysql -p at the end", "mysql -u root -p"],
  ["mysql port flag", "mysql -h db -P3306 -u root shop"],
  ["mysql port flag lowercase", "mysql -h db -p3306 shop"],
  ["mysql -p with a variable", 'mysql -u root -p"$DB_PASS" shop'],
  ["mysql -p unquoted variable", "mysql -u root -p$DB_PASS shop"],
  ["mysql -p with an identifier", "mysql -u root -pDB_PASSWORD shop"],
  ["mysql long port option", "mysql --port=3306 -u root shop"],
  ["mkdir -p", "mkdir -p src/lib/shared"],
  ["mkdir -p after a mysql command", "mysql -u root shop && mkdir -pvx build"],
  ["mkdir -p after a pipe", "mysqldump shop | gzip | tee -pbackup.sql.gz"],
  ["cp -p", "cp -p secrets.txt backup.txt"],
  ["ssh -p", "ssh -p 2222 deploy@host"],
  ["docker -p", "docker run -p 8080:80 nginx"],
  ["mysql -p in prose", "To use mysql, pass the password with -p and no space."],
  ["sshpass with a key file then ssh -p", "sshpass -f /root/pw.txt ssh -p 2222 deploy@host"],
  ["sshpass -p with a variable", 'sshpass -p "$SSH_PASS" ssh deploy@host'],
  ["sshpass -e", "sshpass -e ssh deploy@host"],
  ["sshpass -p placeholder", "sshpass -p password ssh deploy@host"],
  ["--password-stdin", "echo $TOKEN | docker login --password-stdin registry.example.net"],
  ["--password-file", "tool --password-file /run/secrets/db"],
  ["--password then another flag", "tool --password --user alice"],
  ["--password with a variable", 'docker login --password "$REGISTRY_PASS"'],
  ["--password with a template", "docker login --password <password>"],
  ["--password placeholder", "az login --password=password"],
  ["--passphrase with a variable", "gpg --batch --passphrase ${GPG_PASS} --decrypt f.gpg"],
  // Environment variables.
  ["PGPASSWORD variable", "PGPASSWORD=$DB_PASS psql -h db"],
  ["PGPASSWORD template", "PGPASSWORD=${DB_PASS} psql -h db"],
  ["MYSQL_PWD variable", "MYSQL_PWD=$DB_PASS mysqldump shop"],
  ["SSHPASS unset", "unset SSHPASS"],
  ["REDISCLI_AUTH variable", 'REDISCLI_AUTH="$REDIS_PASS" redis-cli ping'],
];

for (const [desc, command] of MUST_NOT_FIRE) {
  test(`does not fire: ${desc}`, () => {
    const findings = engine.evaluate(makeEvent({ command }));
    assert.equal(findings.length, 0, `unexpected finding for ${JSON.stringify(command)}: ${findings[0]?.description}`);
  });
}

test("existing password forms still fire and still skip placeholders", () => {
  assert.equal(engine.evaluate(makeEvent({ body: "password=hunter2abc" })).length, 1);
  assert.equal(engine.evaluate(makeEvent({ body: "password=${DB_PASSWORD}" })).length, 0);
  assert.equal(engine.evaluate(makeEvent({ body: "password=pass" })).length, 0);
});
