// Validation: machine identity computation
//
// Tests the computeMachineId and readMachineLabel functions for the
// Level 2 multi-machine sync feature. Machine ID is a stable SHA-256
// prefix of the hostname; label is read from config.json.
//
// Run: node --test packages/sync-encryptor/test/machine-id.test.mjs

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import { promises as fs } from "node:fs";

import { computeMachineId, readMachineLabel } from "../dist/machine-id.js";

describe("computeMachineId", () => {
  it("returns a 16-character hex string", () => {
    const id = computeMachineId();
    assert.match(id, /^[0-9a-f]{16}$/);
  });

  it("is deterministic (same host produces same ID)", () => {
    const a = computeMachineId();
    const b = computeMachineId();
    assert.equal(a, b);
  });

  it("matches SHA-256 prefix of os.hostname()", () => {
    const expected = createHash("sha256")
      .update(os.hostname())
      .digest("hex")
      .slice(0, 16);
    assert.equal(computeMachineId(), expected);
  });
});

describe("readMachineLabel", () => {
  let tmpDir;

  afterEach(async () => {
    if (tmpDir) {
      await fs.rm(tmpDir, { recursive: true, force: true });
      tmpDir = undefined;
    }
  });

  it("returns undefined when config.json does not exist", async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-test-"));
    const label = await readMachineLabel(tmpDir);
    assert.equal(label, undefined);
  });

  it("returns undefined when config.json has no machine.label", async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-test-"));
    await fs.writeFile(path.join(tmpDir, "config.json"), JSON.stringify({ other: "value" }));
    const label = await readMachineLabel(tmpDir);
    assert.equal(label, undefined);
  });

  it("reads machine.label from config.json", async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-test-"));
    await fs.writeFile(
      path.join(tmpDir, "config.json"),
      JSON.stringify({ machine: { label: "Case's Workstation" } }),
    );
    const label = await readMachineLabel(tmpDir);
    assert.equal(label, "Case's Workstation");
  });

  it("returns undefined for malformed JSON", async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-test-"));
    await fs.writeFile(path.join(tmpDir, "config.json"), "not json at all");
    const label = await readMachineLabel(tmpDir);
    assert.equal(label, undefined);
  });
});
