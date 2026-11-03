// Validation: machine identity
//
// The machine ID is random, generated once per OMNODEX_HOME and stored in
// machine-id.json; a home that synced under the old hostname-derived ID
// keeps it as `previous` until the service has remapped it. The label is
// read from config.json.
//
// Run: node --test packages/sync-encryptor/test/machine-id.test.mjs

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import { promises as fs, readFileSync } from "node:fs";

import {
  acknowledgeMachineIdRemap,
  computeMachineId,
  legacyMachineId,
  pendingMachineIdRemap,
  readMachineLabel,
  remapMachineId,
} from "../dist/machine-id.js";

const homes = [];
async function home() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-machine-id-"));
  homes.push(dir);
  return dir;
}
afterEach(async () => {
  while (homes.length) await fs.rm(homes.pop(), { recursive: true, force: true });
});

describe("computeMachineId", () => {
  it("is 16 random hex characters, stored once and stable after", async () => {
    const h = await home();
    const id = computeMachineId(h);
    assert.match(id, /^[0-9a-f]{16}$/);
    assert.equal(computeMachineId(h), id);
    assert.equal(JSON.parse(readFileSync(path.join(h, "machine-id.json"), "utf8")).id, id);
  });

  it("is not derived from the hostname, and differs per home", async () => {
    const a = computeMachineId(await home());
    const b = computeMachineId(await home());
    assert.notEqual(a, b);
    assert.notEqual(a, legacyMachineId());
  });

  it("replaces a malformed file", async () => {
    const h = await home();
    await fs.writeFile(path.join(h, "machine-id.json"), "{\"id\":\"not-hex\"}");
    assert.match(computeMachineId(h), /^[0-9a-f]{16}$/);
  });
});

describe("legacyMachineId", () => {
  it("is the SHA-256 prefix of os.hostname() older clients sent", () => {
    assert.equal(legacyMachineId(), createHash("sha256").update(os.hostname()).digest("hex").slice(0, 16));
  });
});

describe("machine ID remap", () => {
  it("has nothing to remap on a home that never synced", async () => {
    const h = await home();
    computeMachineId(h);
    assert.equal(pendingMachineIdRemap(h), undefined);
    assert.equal(await remapMachineId({ home: h, apiUrl: "https://api.example.test", apiToken: "t", fetchFn: () => assert.fail("no request") }), "none");
  });

  it("asks once to move the hostname-derived ID's data on a home that synced", async () => {
    const h = await home();
    await fs.writeFile(path.join(h, "sync-salt.bin"), Buffer.alloc(16));
    const id = computeMachineId(h);
    assert.equal(pendingMachineIdRemap(h), legacyMachineId());

    const sent = [];
    const fetchFn = async (url, init) => {
      sent.push({ url: String(url), body: JSON.parse(init.body), auth: init.headers.Authorization });
      return new Response("{}", { status: 200 });
    };
    assert.equal(await remapMachineId({ home: h, apiUrl: "https://api.example.test/", apiToken: "t", fetchFn }), "remapped");
    assert.deepEqual(sent, [{ url: "https://api.example.test/api/v1/sync/machine-remap", body: { from: legacyMachineId(), to: id }, auth: "Bearer t" }]);
    assert.equal(pendingMachineIdRemap(h), undefined);
    assert.equal(computeMachineId(h), id);
    assert.equal(await remapMachineId({ home: h, apiUrl: "https://api.example.test", apiToken: "t", fetchFn }), "none");
  });

  it("keeps the remap pending when the request fails", async () => {
    const h = await home();
    await fs.writeFile(path.join(h, "sync-salt.bin"), Buffer.alloc(16));
    computeMachineId(h);
    const fail = async () => new Response("", { status: 404 });
    assert.equal(await remapMachineId({ home: h, apiUrl: "https://api.example.test", apiToken: "t", fetchFn: fail }), "skipped");
    const down = async () => { throw new Error("offline"); };
    assert.equal(await remapMachineId({ home: h, apiUrl: "https://api.example.test", apiToken: "t", fetchFn: down }), "skipped");
    assert.equal(pendingMachineIdRemap(h), legacyMachineId());
    acknowledgeMachineIdRemap(h);
    assert.equal(pendingMachineIdRemap(h), undefined);
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
