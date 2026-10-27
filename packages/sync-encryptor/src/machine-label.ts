// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- encrypted labels
 *
 * Names the hosted dashboard shows but the service has no use for, such as
 * the machine label, leave the machine only encrypted:
 *
 *   key  = HKDF-SHA256(Argon2id(secret, fixed salt), SHA-256(scope), info)
 *   wire = "v1." + base64url(iv) + "." + base64url(AES-256-GCM ciphertext)
 *
 * The same Argon2id master as the streaming key, with its own info label,
 * so the keys are independent. The scope is fixed rather than the customer
 * ID because a device code request names the machine before any stream
 * exists. The field name is bound as associated data, so one sealed value
 * cannot be passed off as another field. The dashboard and the connect and
 * device pages hold the stream secret and derive the same key.
 */

import { webcrypto } from "node:crypto";
import { deriveStreamSubkeyBytes } from "./crypto.js";
import { readMachineLabel } from "./machine-id.js";

const subtle = webcrypto.subtle;

/** Stands in for the customer ID: labels are sealed before a stream exists. */
const LABEL_SCOPE = "omnodex-sealed-label";
/** HKDF `info` for the label key. Changing it orphans every stored label. */
const LABEL_INFO = new TextEncoder().encode("omnodex-sealed-label-v1");
const LABEL_AAD_PREFIX = "omnodex-sealed-label-aad-v1";

/** A sealed label as it travels and is stored: "v1.<iv>.<ciphertext>". */
export const SEALED_LABEL_RE = /^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/;

/** Fields a sealed label may stand for. */
export type LabelField = "machine_label";

export type LabelKey = webcrypto.CryptoKey;

const keys = new Map<string, Promise<LabelKey>>();

/** The label key for a stream secret. Runs Argon2id once per secret per process. */
export function deriveLabelKey(passphrase: string): Promise<LabelKey> {
  let key = keys.get(passphrase);
  if (!key) {
    key = deriveStreamSubkeyBytes(passphrase, LABEL_SCOPE, LABEL_INFO).then((bytes) =>
      subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    );
    key.catch(() => keys.delete(passphrase));
    keys.set(passphrase, key);
  }
  return key;
}

const aad = (field: LabelField) => new TextEncoder().encode(`${LABEL_AAD_PREFIX}\0${field}`);
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** Seal `text` for `field`. A fresh nonce each time, so equal labels do not match. */
export async function sealLabel(
  key: LabelKey,
  field: LabelField,
  text: string,
  iv: Uint8Array = webcrypto.getRandomValues(new Uint8Array(12)),
): Promise<string> {
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(field) }, key, new TextEncoder().encode(text));
  return `v1.${b64url(iv)}.${b64url(new Uint8Array(ct))}`;
}

/** Open a sealed label; undefined if it is malformed or was sealed under another key or field. */
export async function openLabel(key: LabelKey, field: LabelField, sealed: string): Promise<string | undefined> {
  if (!SEALED_LABEL_RE.test(sealed)) return undefined;
  const [, iv, ct] = sealed.split(".");
  try {
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: Buffer.from(iv!, "base64url"), additionalData: aad(field) },
      key,
      Buffer.from(ct!, "base64url"),
    );
    return new TextDecoder().decode(pt);
  } catch {
    return undefined;
  }
}

/**
 * The machine label to send: `label` if given, else the one in config.json,
 * sealed under the stream secret. Undefined when there is no label.
 */
export async function sealedMachineLabel(
  passphrase: string,
  omnodexHome?: string,
  label?: string,
): Promise<string | undefined> {
  const text = label?.trim() || (await readMachineLabel(omnodexHome));
  if (!text) return undefined;
  return sealLabel(await deriveLabelKey(passphrase), "machine_label", text);
}
