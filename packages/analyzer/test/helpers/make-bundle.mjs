// Builds a signed, sealed advanced rule bundle for tests, the way the
// publisher will (PAID_RULE_DELIVERY.md section 4): seal the rules under a
// fresh content key, hash the sealed payload, sign the manifest.

import * as crypto from "node:crypto";
import { canonicalManifest } from "../../dist/bundle.js";

export const ADVANCED_RULE = {
  rule_id: "RULE_ADVANCED_SSH_THEN_OUTBOUND",
  name: "Credential read followed by an outbound call",
  description: "A session read an SSH key and then called out",
  severity: "HIGH",
  category: "exfiltration",
  tier: "advanced",
  conditions: [{ type: "path_match", patterns: ["**/.ssh/**"] }],
};

/**
 * A sealed bundle plus the keys to check and open it.
 *
 * Overrides: rules, channel, version, notAfter (Date or ISO string), and
 * `tamper`, which flips a byte of the sealed payload after the manifest is
 * signed.
 */
export function makeBundle(overrides = {}) {
  const rules = overrides.rules ?? [ADVANCED_RULE];
  const contentKey = overrides.contentKey ?? crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", contentKey, iv);
  const body = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(rules), "utf8")),
    cipher.final(),
  ]);
  let payload = Buffer.concat([iv, body, cipher.getAuthTag()]);

  const notAfter =
    overrides.notAfter instanceof Date
      ? overrides.notAfter.toISOString()
      : (overrides.notAfter ?? new Date(Date.now() + 30 * 86_400_000).toISOString());

  const manifest = {
    bundle_version: overrides.version ?? "1.0.0",
    channel: overrides.channel ?? "pro",
    created_at: new Date().toISOString(),
    not_after: notAfter,
    rules: rules.map((r) => ({ rule_id: r.rule_id, version: "1.0.0" })),
    payload_sha256: crypto.createHash("sha256").update(payload).digest("hex"),
  };

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const signature = crypto.sign(null, canonicalManifest(manifest), privateKey);

  if (overrides.tamper) {
    const flipped = Buffer.from(payload);
    flipped[flipped.length - 20] ^= 0xff;
    payload = flipped;
  }

  return {
    bundle: { manifest, signature: signature.toString("base64"), payload: payload.toString("base64") },
    keyBase64: contentKey.toString("base64"),
    publicKeyBase64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    contentKey,
  };
}

/** Another keypair's signature over the same manifest: a bundle we did not sign. */
export function signedByStranger(overrides = {}) {
  const made = makeBundle(overrides);
  const stranger = crypto.generateKeyPairSync("ed25519");
  made.bundle.signature = crypto
    .sign(null, canonicalManifest(made.bundle.manifest), stranger.privateKey)
    .toString("base64");
  return made;
}
