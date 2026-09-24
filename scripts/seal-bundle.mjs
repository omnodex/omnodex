#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Seal a rule pack into a bundle, the way the distributor will.
 *
 * Advanced rules are not in this repository: it is public, and they are the
 * paid asset. This script takes a pack of RuleDefinitions from wherever it
 * lives, seals it under a fresh content key, signs the manifest, and writes
 * a bundle the analyzer can open. That is how advanced rules are written and
 * dogfooded before the cloud side exists (ENG-342 does the same thing in a
 * Worker, with a signing key held as a secret).
 *
 * Usage:
 *   node scripts/seal-bundle.mjs <pack.json> [options]
 *
 *     --out <file>       bundle to write (default: <pack>.bundle.json)
 *     --channel <name>   pro (default) or enterprise
 *     --version <semver> bundle version (default: 0.0.0-dev)
 *     --days <n>         validity in days (default: 30)
 *     --signing-key <f>  PEM private key to sign with; generated if omitted
 *     --install <home>   also install into <home>/rules/current.bundle.json
 *
 * It prints the two environment variables a client needs to open the result.
 * Both are development conveniences: in production the public key is
 * compiled in and the content key arrives wrapped from the licence server.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import { canonicalManifest, bundlePath } from "../packages/analyzer/dist/bundle.js";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

const packFile = process.argv[2];
if (!packFile || packFile.startsWith("--")) {
  console.error("usage: node scripts/seal-bundle.mjs <pack.json> [--out f] [--channel pro] [--version x.y.z] [--days 30] [--signing-key f] [--install home]");
  process.exit(2);
}

const rules = JSON.parse(fs.readFileSync(packFile, "utf8"));
if (!Array.isArray(rules) || rules.length === 0) {
  console.error(`${packFile}: expected a non-empty array of rules`);
  process.exit(2);
}
for (const rule of rules) {
  if (rule.tier !== "advanced") {
    console.error(`${rule.rule_id ?? "(unnamed rule)"}: tier must be "advanced" in a bundle`);
    process.exit(2);
  }
}

const channel = arg("channel", "pro");
const version = arg("version", "0.0.0-dev");
const days = Number(arg("days", "30"));

const contentKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", contentKey, iv);
const payload = Buffer.concat([
  iv,
  cipher.update(Buffer.from(JSON.stringify(rules), "utf8")),
  cipher.final(),
  cipher.getAuthTag(),
]);

const manifest = {
  bundle_version: version,
  channel,
  created_at: new Date().toISOString(),
  not_after: new Date(Date.now() + days * 86_400_000).toISOString(),
  rules: rules.map((r) => ({ rule_id: r.rule_id, version: r.version ?? "1.0.0" })),
  payload_sha256: crypto.createHash("sha256").update(payload).digest("hex"),
};

const signingKeyFile = arg("signing-key");
const privateKey = signingKeyFile
  ? crypto.createPrivateKey(fs.readFileSync(signingKeyFile, "utf8"))
  : crypto.generateKeyPairSync("ed25519").privateKey;
const publicKey = crypto.createPublicKey(privateKey);

const bundle = {
  manifest,
  signature: crypto.sign(null, canonicalManifest(manifest), privateKey).toString("base64"),
  payload: payload.toString("base64"),
};

const out = arg("out", `${packFile.replace(/\.json$/, "")}.bundle.json`);
fs.writeFileSync(out, JSON.stringify(bundle), "utf8");

const home = arg("install");
if (home) {
  const installed = bundlePath(home);
  fs.mkdirSync(path.dirname(installed), { recursive: true });
  fs.copyFileSync(out, installed);
}

console.log(`sealed ${rules.length} rule(s) into ${out}`);
console.log(`  channel ${channel}, version ${version}, valid until ${manifest.not_after}`);
if (home) console.log(`  installed into ${bundlePath(home)}`);
if (!signingKeyFile) {
  console.log("  signed with a throwaway key: pass --signing-key to keep one across bundles");
}
console.log("");
console.log(`export OMNODEX_RULES_PUBLIC_KEY=${publicKey.export({ type: "spki", format: "der" }).toString("base64")}`);
console.log(`export OMNODEX_RULES_KEY=${contentKey.toString("base64")}`);
