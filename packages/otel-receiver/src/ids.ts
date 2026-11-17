// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Deterministic event ids. Span delivery is at least once, so a span that
 * arrives twice must produce the same event ids both times and let the read
 * model absorb the copy. A name-based UUID (version 5) of the span's identity
 * does that without keeping any state.
 */

import { createHash } from "node:crypto";

/** Namespace for ids minted from spans. Fixed forever: changing it changes every id. */
const NAMESPACE = "9b0f2c64-5e1a-5a3d-8c47-2f6d1e7b0a93";

function uuidBytes(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ""), "hex");
}

/** RFC 4122 version 5 UUID of `name` within the receiver's namespace. */
export function eventIdFor(name: string): string {
  const hash = createHash("sha1").update(uuidBytes(NAMESPACE)).update(name, "utf8").digest();
  hash[6] = (hash[6]! & 0x0f) | 0x50;
  hash[8] = (hash[8]! & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
