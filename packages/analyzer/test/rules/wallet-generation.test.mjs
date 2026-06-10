/**
 * Wallet generation rule unit tests.
 *
 * Covers three rules:
 *   RULE_WALLET_CLI_DETECTED  -- wallet CLI commands in tool parameters
 *   RULE_PRIVATE_KEY_MATERIAL -- labeled 64-char private key hex strings
 *   RULE_MNEMONIC_PHRASE      -- BIP-39 mnemonic seed phrases in labeled context
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_WALLET_CLI_DETECTED,
  RULE_PRIVATE_KEY_MATERIAL,
  RULE_MNEMONIC_PHRASE,
} from "../../dist/rules/index.js";

function makeEvent(toolName, mcpServer, parameters) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-05-01T00:00:00.000Z",
    recorded_at: "2026-05-01T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: toolName,
    mcp_server: mcpServer,
    parameters,
  };
}

function makeBash(command) {
  return makeEvent("bash", "builtin", { command });
}

// ---------------------------------------------------------------------------
// RULE_WALLET_CLI_DETECTED
// ---------------------------------------------------------------------------

const cliEngine = new RuleEngine([RULE_WALLET_CLI_DETECTED]);

const CLI_CASES = [
  ["solana-keygen",    makeBash("solana-keygen new --outfile ~/.config/solana/id.json")],
  ["ethkey",           makeBash("ethkey generate --json > key.json")],
  ["bitcoin-cli createwallet", makeBash("bitcoin-cli createwallet mywallet")],
  ["bitcoin-cli getnewaddress", makeBash("bitcoin-cli getnewaddress")],
  ["bitcoin-cli dumpprivkey",  makeBash("bitcoin-cli dumpprivkey 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf")],
  ["hdwallet-derive",  makeBash("hdwallet-derive --mnemonic-file seed.txt")],
  ["cast wallet",      makeBash("cast wallet new")],
  // generateWallet/eth_accounts appear as the RPC method parameter; credential_match
  // scans JSON.stringify(parameters), not the tool name.
  ["generateWallet API", makeEvent("mcp__web3__rpc", "web3", { method: "generateWallet", network: "ethereum" })],
  ["eth_accounts API",   makeEvent("mcp__web3__rpc", "web3", { method: "eth_accounts" })],
  ["eth_accounts API", makeEvent("mcp__web3__call", "web3", { method: "eth_accounts" })],
];

for (const [desc, event] of CLI_CASES) {
  test(`RULE_WALLET_CLI_DETECTED fires for ${desc}`, () => {
    const findings = cliEngine.evaluate(event);
    assert.equal(findings.length, 1, `expected 1 finding for ${desc}`);
    assert.equal(findings[0].severity, "HIGH");
    assert.equal(findings[0].category, "wallet_generation");
  });
}

test("RULE_WALLET_CLI_DETECTED does not fire for benign bash commands", () => {
  const safe = [
    makeBash("npm install"),
    makeBash("python3 analyze.py"),
    makeBash("git commit -m 'add feature'"),
    makeBash("ls -la ~/.config"),
  ];
  for (const event of safe) {
    assert.equal(cliEngine.evaluate(event).length, 0);
  }
});

// ---------------------------------------------------------------------------
// RULE_PRIVATE_KEY_MATERIAL
// ---------------------------------------------------------------------------

const pkEngine = new RuleEngine([RULE_PRIVATE_KEY_MATERIAL]);

// 64-char hex private key (valid 256-bit key).
const FAKE_PRIVKEY = "a" + "b".repeat(63);

test("RULE_PRIVATE_KEY_MATERIAL fires for private_key label with 64-char hex", () => {
  const event = makeEvent("Write", "builtin", {
    content: `private_key: "${FAKE_PRIVKEY}"`,
  });
  const findings = pkEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.ok(findings[0].description.includes("private-key-hex") || findings[0].description.includes("private_key"), findings[0].description);
});

test("RULE_PRIVATE_KEY_MATERIAL fires for privkey= assignment", () => {
  const event = makeEvent("bash", "builtin", {
    command: `ethkey sign privkey=${FAKE_PRIVKEY}`,
  });
  const findings = pkEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("RULE_PRIVATE_KEY_MATERIAL fires for 0x-prefixed eth private key", () => {
  const event = makeEvent("mcp__eth__sign", "eth", {
    key: "0x" + FAKE_PRIVKEY,
  });
  const findings = pkEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("RULE_PRIVATE_KEY_MATERIAL does not fire for unlabeled 64-char hex", () => {
  // A SHA-256 hash with no label should NOT trigger the private-key-hex pattern.
  const event = makeEvent("bash", "builtin", {
    command: `verify checksum ${"a".repeat(64)}`,
  });
  // The 0x-prefixed pattern requires 0x prefix, so only check private-key-hex pattern.
  // Without 0x prefix AND without a private_key label, should not fire.
  const findings = pkEngine.evaluate(event);
  // eth-private-key pattern requires 0x prefix -- should not match.
  // private-key-hex pattern requires a label -- should not match.
  assert.equal(findings.length, 0, "unlabeled hex should not trigger private key rule");
});

// ---------------------------------------------------------------------------
// RULE_MNEMONIC_PHRASE
// ---------------------------------------------------------------------------

const mnemonicEngine = new RuleEngine([RULE_MNEMONIC_PHRASE]);

// Valid 12-word BIP-39 mnemonic (from the BIP-39 wordlist test vectors).
const MNEMONIC_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("RULE_MNEMONIC_PHRASE fires for mnemonic label with 12 words", () => {
  const event = makeEvent("Write", "builtin", {
    content: `mnemonic: "${MNEMONIC_12}"`,
  });
  const findings = mnemonicEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "wallet_generation");
  assert.ok(findings[0].description.includes("bip39-mnemonic"), findings[0].description);
});

test("RULE_MNEMONIC_PHRASE fires for seed_phrase label", () => {
  const event = makeEvent("mcp__vault__store", "vault", {
    seed_phrase: MNEMONIC_12,
  });
  const findings = mnemonicEngine.evaluate(event);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("RULE_MNEMONIC_PHRASE fires for recovery_phrase label", () => {
  const event = makeEvent("bash", "builtin", {
    command: `wallet restore recovery_phrase="${MNEMONIC_12}"`,
  });
  const findings = mnemonicEngine.evaluate(event);
  assert.equal(findings.length, 1);
});

test("RULE_MNEMONIC_PHRASE does not fire for fewer than 12 words", () => {
  const event = makeEvent("Write", "builtin", {
    content: `mnemonic: "abandon abandon abandon abandon abandon"`,
  });
  assert.equal(mnemonicEngine.evaluate(event).length, 0);
});

test("RULE_MNEMONIC_PHRASE does not fire for unlabeled word sequences", () => {
  const event = makeEvent("bash", "builtin", {
    command: "echo hello world foo bar baz one two three four five six seven",
  });
  assert.equal(mnemonicEngine.evaluate(event).length, 0);
});
