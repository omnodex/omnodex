// Builds a signed, sealed guardrails module for tests, the way the
// publisher does: seal the source under a fresh content key, hash the sealed
// payload, sign the manifest. The module inside is a stand-in that only
// echoes what it was asked; the real decision code is not in this repository.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { canonicalModuleManifest } from "../../dist/enforcement/module.js";

/**
 * Stops or holds a call at the strictest verdict, and answers with a marker
 * the tests can recognize: { test_decision, host, rules }, or { reason } for
 * the MCP proxy.
 */
export const FAKE_MODULE_SOURCE = `
export const GUARDRAILS_INTERFACE = 1;
const rank = { alert_only: 0, confirm: 1, deny: 2 };
export function decide({ host, verdicts, failure, onError }) {
  if (failure) {
    if (onError !== "block") return { action: "alert_only", held: [], output: null };
    return { action: "deny", held: [], output: host === "mcp-proxy" ? { reason: "test: could not check" } : { test_decision: "deny", host, rules: [], could_not_check: true } };
  }
  let action = "alert_only";
  for (const v of verdicts) if (rank[v.action] > rank[action]) action = v.action;
  if (action === "alert_only") return { action, held: [], output: null };
  const rules = verdicts.filter((v) => v.action === action).map((v) => v.rule_id);
  return { action, held: rules, output: host === "mcp-proxy" ? { reason: "test: " + action + " " + rules.join(",") } : { test_decision: action, host, rules } };
}
`;

/**
 * A sealed module plus the keys to check and open it.
 * Overrides: source, version, interface, notAfter, tamper.
 */
export function makeModule(overrides = {}) {
  const contentKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", contentKey, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(overrides.source ?? FAKE_MODULE_SOURCE, "utf8")), cipher.final()]);
  let payload = Buffer.concat([iv, body, cipher.getAuthTag()]);
  const manifest = {
    kind: "guardrails-module",
    module_version: overrides.version ?? "1.0.0",
    interface: overrides.interface ?? 1,
    channel: "pro",
    created_at: new Date().toISOString(),
    not_after: overrides.notAfter ?? new Date(Date.now() + 30 * 86_400_000).toISOString(),
    payload_sha256: crypto.createHash("sha256").update(payload).digest("hex"),
  };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const signature = crypto.sign(null, canonicalModuleManifest(manifest), privateKey).toString("base64");
  if (overrides.tamper) {
    payload = Buffer.from(payload);
    payload[payload.length - 20] ^= 0xff;
  }
  return {
    sealed: { manifest, signature, payload: payload.toString("base64") },
    contentKey,
    publicKeyB64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

/**
 * Install a fake module into an Omnodex home, and return the environment a
 * process needs to open it (the development key variables).
 */
export function installModule(home, overrides = {}) {
  const m = makeModule(overrides);
  const file = path.join(home, "guardrails", "current.module.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(m.sealed));
  return {
    ...m,
    env: { OMNODEX_GUARDRAILS_PUBLIC_KEY: m.publicKeyB64, OMNODEX_GUARDRAILS_KEY: m.contentKey.toString("base64") },
  };
}
