// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The span shape the mapper reads, and a reader for OTLP/JSON trace exports.
 *
 * The mapper never sees OTLP's wire details. Whatever decodes a request
 * (this reader for JSON, a protobuf decoder for the binary form) produces
 * `OtelSpan`s with flat attributes, resource attributes merged in, ids as
 * lowercase hex and times as nanosecond strings.
 */

/** A decoded attribute value: OTLP's AnyValue as plain JavaScript. */
export type AttrValue = string | number | boolean | null | AttrValue[] | { [key: string]: AttrValue };

export interface OtelSpan {
  /** Lowercase hex, 32 characters. */
  traceId: string;
  /** Lowercase hex, 16 characters. */
  spanId: string;
  parentSpanId?: string;
  name: string;
  /** Unix time in nanoseconds, as a decimal string (64-bit values do not fit a JS number). */
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  /** Span attributes over resource attributes: the span's value wins on a clash. */
  attributes: Record<string, AttrValue>;
  /** The resource's attributes alone, for `service.name` and the like. */
  resource: Record<string, AttrValue>;
  status?: { code: "unset" | "ok" | "error"; message?: string };
}

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** One OTLP/JSON AnyValue as a plain value. Unknown shapes become null. */
export function anyValueToJs(v: unknown): AttrValue {
  if (!isObject(v)) return null;
  if (typeof v.stringValue === "string") return v.stringValue;
  if (v.boolValue !== undefined) return v.boolValue === true;
  if (v.intValue !== undefined) {
    // OTLP/JSON carries 64-bit integers as strings.
    const n = Number(v.intValue);
    return Number.isSafeInteger(n) ? n : String(v.intValue);
  }
  if (typeof v.doubleValue === "number") return v.doubleValue;
  if (typeof v.bytesValue === "string") return v.bytesValue;
  if (isObject(v.arrayValue)) {
    const values = v.arrayValue.values;
    return Array.isArray(values) ? values.map(anyValueToJs) : [];
  }
  if (isObject(v.kvlistValue)) {
    return keyValuesToRecord(v.kvlistValue.values);
  }
  return null;
}

/** An OTLP KeyValue list as a record. Later duplicates of a key win. */
export function keyValuesToRecord(list: unknown): Record<string, AttrValue> {
  const out: Record<string, AttrValue> = {};
  if (!Array.isArray(list)) return out;
  for (const kv of list) {
    if (isObject(kv) && typeof kv.key === "string") out[kv.key] = anyValueToJs(kv.value);
  }
  return out;
}

function nanoString(v: unknown): string {
  if (typeof v === "string" && /^\d+$/.test(v)) return v;
  if (typeof v === "number" && Number.isFinite(v) && v >= 0) return BigInt(Math.trunc(v)).toString();
  return "0";
}

function statusOf(v: unknown): OtelSpan["status"] {
  if (!isObject(v)) return undefined;
  const raw = v.code;
  let code: "unset" | "ok" | "error" = "unset";
  if (raw === 1 || raw === "STATUS_CODE_OK") code = "ok";
  else if (raw === 2 || raw === "STATUS_CODE_ERROR") code = "error";
  const message = typeof v.message === "string" && v.message ? v.message : undefined;
  return message ? { code, message } : { code };
}

/**
 * Spans from an OTLP/JSON `ExportTraceServiceRequest`. Reads what it can and
 * skips what it cannot: a malformed span never fails its siblings.
 */
export function spansFromOtlpJson(body: unknown): OtelSpan[] {
  const spans: OtelSpan[] = [];
  if (!isObject(body) || !Array.isArray(body.resourceSpans)) return spans;
  for (const rs of body.resourceSpans) {
    if (!isObject(rs)) continue;
    const resource = isObject(rs.resource) ? keyValuesToRecord(rs.resource.attributes) : {};
    const scopes = Array.isArray(rs.scopeSpans) ? rs.scopeSpans : [];
    for (const scope of scopes) {
      if (!isObject(scope) || !Array.isArray(scope.spans)) continue;
      for (const s of scope.spans) {
        if (!isObject(s) || typeof s.traceId !== "string" || typeof s.spanId !== "string") continue;
        const span: OtelSpan = {
          traceId: s.traceId.toLowerCase(),
          spanId: s.spanId.toLowerCase(),
          name: typeof s.name === "string" ? s.name : "",
          startTimeUnixNano: nanoString(s.startTimeUnixNano),
          endTimeUnixNano: nanoString(s.endTimeUnixNano),
          attributes: { ...resource, ...keyValuesToRecord(s.attributes) },
          resource,
        };
        if (typeof s.parentSpanId === "string" && s.parentSpanId) span.parentSpanId = s.parentSpanId.toLowerCase();
        const status = statusOf(s.status);
        if (status) span.status = status;
        spans.push(span);
      }
    }
  }
  return spans;
}
