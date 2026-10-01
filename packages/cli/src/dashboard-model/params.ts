// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * Tool parameters as the detail panel shows them. Parameters are stored as
 * a JSON string; long or multi-line string values (a file being written, a
 * script, a patch) read as text blocks rather than one escaped line.
 */

export type ParamNode =
  | { kind: "text"; value: string }
  | { kind: "scalar"; value: string }
  | { kind: "object"; entries: Array<{ key: string; value: ParamNode }> }
  | { kind: "array"; items: ParamNode[] };

/** Strings longer than this, or with a line break, show as a text block. */
const BLOCK_LENGTH = 100;

export function toParamNode(value: unknown): ParamNode {
  if (typeof value === "string") {
    return value.includes("\n") || value.length > BLOCK_LENGTH
      ? { kind: "text", value }
      : { kind: "scalar", value: JSON.stringify(value) };
  }
  if (Array.isArray(value)) return { kind: "array", items: value.map(toParamNode) };
  if (value !== null && typeof value === "object") {
    return { kind: "object", entries: Object.entries(value as Record<string, unknown>).map(([key, v]) => ({ key, value: toParamNode(v) })) };
  }
  return { kind: "scalar", value: JSON.stringify(value) ?? String(value) };
}

/** The stored parameters as a tree, or the raw text when they are not JSON. */
export function parseParameters(json: string | null | undefined): ParamNode {
  if (!json) return { kind: "object", entries: [] };
  try {
    return toParamNode(JSON.parse(json));
  } catch {
    return { kind: "text", value: json };
  }
}
