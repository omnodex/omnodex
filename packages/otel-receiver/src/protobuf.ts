// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * A reader for the OTLP trace export request in protobuf form.
 *
 * The Claude API Console sends nothing else, and a generated decoder would
 * add a dependency to the public CLI for about eight message types. This
 * reads only the fields the mapper uses and skips the rest. Field numbers
 * are from `opentelemetry/proto/trace/v1/trace.proto`, `common/v1/common.proto`
 * and `collector/trace/v1/trace_service.proto`; golden tests pin them against
 * payloads written by an independent protobuf encoder.
 *
 * It never trusts a length: every read is bounds-checked, nesting is capped,
 * and a malformed body throws `ProtobufError` for the server to answer 400.
 */

import type { AttrValue, OtelSpan } from "./otlp.js";

export class ProtobufError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtobufError";
  }
}

const MAX_DEPTH = 32;

const VARINT = 0;
const FIXED64 = 1;
const LEN = 2;
const FIXED32 = 5;

class Reader {
  pos = 0;
  constructor(
    readonly buf: Uint8Array,
    readonly end: number = buf.length,
  ) {}

  get done(): boolean {
    return this.pos >= this.end;
  }

  /** A varint of up to 64 bits, as a bigint. */
  varint(): bigint {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < 10; i++) {
      if (this.pos >= this.end) throw new ProtobufError("truncated varint");
      const byte = this.buf[this.pos++]!;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7n;
    }
    throw new ProtobufError("varint longer than 10 bytes");
  }

  /** A varint that must fit a safe integer: field keys and lengths. */
  smallVarint(): number {
    const v = this.varint();
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ProtobufError("length out of range");
    return Number(v);
  }

  fixed64(): bigint {
    if (this.pos + 8 > this.end) throw new ProtobufError("truncated fixed64");
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(this.buf[this.pos + i]!);
    this.pos += 8;
    return v;
  }

  double(): number {
    if (this.pos + 8 > this.end) throw new ProtobufError("truncated double");
    const view = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 8);
    this.pos += 8;
    return view.getFloat64(0, true);
  }

  /** The bytes of a length-delimited field, as a sub-reader. */
  sub(): Reader {
    const len = this.smallVarint();
    if (len > this.end - this.pos) throw new ProtobufError("length-delimited field runs past the message");
    const r = new Reader(this.buf, this.pos + len);
    r.pos = this.pos;
    this.pos += len;
    return r;
  }

  bytes(): Uint8Array {
    const r = this.sub();
    return this.buf.subarray(r.pos, r.end);
  }

  string(): string {
    return Buffer.from(this.bytes()).toString("utf8");
  }

  skip(wire: number): void {
    switch (wire) {
      case VARINT:
        this.varint();
        return;
      case FIXED64:
        if (this.pos + 8 > this.end) throw new ProtobufError("truncated fixed64");
        this.pos += 8;
        return;
      case LEN:
        this.sub();
        return;
      case FIXED32:
        if (this.pos + 4 > this.end) throw new ProtobufError("truncated fixed32");
        this.pos += 4;
        return;
      default:
        throw new ProtobufError(`unsupported wire type ${wire}`);
    }
  }

  /** The next field's number and wire type, or null at the end. */
  field(): { no: number; wire: number } | null {
    if (this.done) return null;
    const key = this.smallVarint();
    const no = Math.floor(key / 8);
    if (no === 0) throw new ProtobufError("field number 0");
    return { no, wire: key % 8 };
  }
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function toSigned64(v: bigint): bigint {
  return BigInt.asIntN(64, v);
}

function anyValue(r: Reader, depth: number): AttrValue {
  if (depth > MAX_DEPTH) throw new ProtobufError("attribute value nested too deeply");
  let out: AttrValue = null;
  for (let f = r.field(); f; f = r.field()) {
    switch (f.no) {
      case 1:
        if (f.wire !== LEN) throw new ProtobufError("bad string_value wire type");
        out = r.string();
        break;
      case 2:
        if (f.wire !== VARINT) throw new ProtobufError("bad bool_value wire type");
        out = r.varint() !== 0n;
        break;
      case 3: {
        if (f.wire !== VARINT) throw new ProtobufError("bad int_value wire type");
        const n = toSigned64(r.varint());
        out = n >= BigInt(Number.MIN_SAFE_INTEGER) && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString();
        break;
      }
      case 4:
        if (f.wire !== FIXED64) throw new ProtobufError("bad double_value wire type");
        out = r.double();
        break;
      case 5: {
        if (f.wire !== LEN) throw new ProtobufError("bad array_value wire type");
        const values: AttrValue[] = [];
        const arr = r.sub();
        for (let g = arr.field(); g; g = arr.field()) {
          if (g.no === 1 && g.wire === LEN) values.push(anyValue(arr.sub(), depth + 1));
          else arr.skip(g.wire);
        }
        out = values;
        break;
      }
      case 6: {
        if (f.wire !== LEN) throw new ProtobufError("bad kvlist_value wire type");
        const record: Record<string, AttrValue> = {};
        const list = r.sub();
        for (let g = list.field(); g; g = list.field()) {
          if (g.no === 1 && g.wire === LEN) {
            const [k, v] = keyValue(list.sub(), depth + 1);
            if (k !== undefined) record[k] = v;
          } else list.skip(g.wire);
        }
        out = record;
        break;
      }
      case 7:
        if (f.wire !== LEN) throw new ProtobufError("bad bytes_value wire type");
        out = Buffer.from(r.bytes()).toString("base64");
        break;
      default:
        r.skip(f.wire);
    }
  }
  return out;
}

function keyValue(r: Reader, depth: number): [string | undefined, AttrValue] {
  let key: string | undefined;
  let value: AttrValue = null;
  for (let f = r.field(); f; f = r.field()) {
    if (f.no === 1 && f.wire === LEN) key = r.string();
    else if (f.no === 2 && f.wire === LEN) value = anyValue(r.sub(), depth + 1);
    else r.skip(f.wire);
  }
  return [key, value];
}

function attributesInto(target: Record<string, AttrValue>, r: Reader): void {
  const [k, v] = keyValue(r, 0);
  if (k !== undefined) target[k] = v;
}

function status(r: Reader): OtelSpan["status"] {
  let code: "unset" | "ok" | "error" = "unset";
  let message: string | undefined;
  for (let f = r.field(); f; f = r.field()) {
    if (f.no === 2 && f.wire === LEN) message = r.string() || undefined;
    else if (f.no === 3 && f.wire === VARINT) {
      const c = r.varint();
      code = c === 1n ? "ok" : c === 2n ? "error" : "unset";
    } else r.skip(f.wire);
  }
  return message ? { code, message } : { code };
}

function span(r: Reader, resource: Record<string, AttrValue>): OtelSpan {
  const own: Record<string, AttrValue> = {};
  const s: OtelSpan = {
    traceId: "",
    spanId: "",
    name: "",
    startTimeUnixNano: "0",
    endTimeUnixNano: "0",
    attributes: {},
    resource,
  };
  for (let f = r.field(); f; f = r.field()) {
    if (f.no === 1 && f.wire === LEN) s.traceId = hex(r.bytes());
    else if (f.no === 2 && f.wire === LEN) s.spanId = hex(r.bytes());
    else if (f.no === 4 && f.wire === LEN) {
      const parent = hex(r.bytes());
      if (parent) s.parentSpanId = parent;
    } else if (f.no === 5 && f.wire === LEN) s.name = r.string();
    else if (f.no === 7 && f.wire === FIXED64) s.startTimeUnixNano = r.fixed64().toString();
    else if (f.no === 8 && f.wire === FIXED64) s.endTimeUnixNano = r.fixed64().toString();
    else if (f.no === 9 && f.wire === LEN) attributesInto(own, r.sub());
    else if (f.no === 15 && f.wire === LEN) s.status = status(r.sub());
    else r.skip(f.wire);
  }
  s.attributes = { ...resource, ...own };
  return s;
}

/**
 * The spans in a protobuf `ExportTraceServiceRequest`. Spans without a trace
 * and span id are dropped; a malformed message throws `ProtobufError`.
 */
export function spansFromOtlpProtobuf(body: Uint8Array): OtelSpan[] {
  const spans: OtelSpan[] = [];
  const top = new Reader(body);
  for (let f = top.field(); f; f = top.field()) {
    if (f.no !== 1 || f.wire !== LEN) {
      top.skip(f.wire);
      continue;
    }
    // ResourceSpans: resource (1), scope_spans (2).
    const rs = top.sub();
    const resource: Record<string, AttrValue> = {};
    const scopeReaders: Reader[] = [];
    for (let g = rs.field(); g; g = rs.field()) {
      if (g.no === 1 && g.wire === LEN) {
        const res = rs.sub();
        for (let h = res.field(); h; h = res.field()) {
          if (h.no === 1 && h.wire === LEN) attributesInto(resource, res.sub());
          else res.skip(h.wire);
        }
      } else if (g.no === 2 && g.wire === LEN) scopeReaders.push(rs.sub());
      else rs.skip(g.wire);
    }
    for (const scope of scopeReaders) {
      for (let g = scope.field(); g; g = scope.field()) {
        if (g.no === 2 && g.wire === LEN) {
          const s = span(scope.sub(), resource);
          if (s.traceId && s.spanId) spans.push(s);
        } else scope.skip(g.wire);
      }
    }
  }
  return spans;
}
