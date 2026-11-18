import { test } from "node:test";
import assert from "node:assert/strict";
import { ProtobufError, spansFromOtlpProtobuf } from "../dist/index.js";
import { GOLDEN_TRACE_HEX } from "./golden.mjs";

const golden = () => Buffer.from(GOLDEN_TRACE_HEX, "hex");

test("a payload from an independent encoder decodes to the spans it carried", () => {
  const spans = spansFromOtlpProtobuf(golden());
  assert.deepEqual(spans.map((s) => s.name), ["anthropic.tool_use bash", "no status", "second scope", "other resource"]);

  const s = spans[0];
  assert.equal(s.traceId, "5b8efff798038103d269b633813fc60c");
  assert.equal(s.spanId, "eee19b7ec3c1b174");
  assert.equal(s.parentSpanId, "0102030405060708");
  // Fixed 64-bit times survive in full, including the largest value.
  assert.equal(s.startTimeUnixNano, "1794582000000000001");
  assert.equal(s.endTimeUnixNano, "18446744073709551615");
  assert.deepEqual(s.status, { code: "error", message: "boom" });
  assert.deepEqual(s.resource, { "service.name": "claude-platform", "anthropic.organization.id": "org_1" });

  const a = s.attributes;
  assert.equal(a["service.name"], "claude-platform", "resource attributes are merged in");
  assert.equal(a["gen_ai.operation.name"], "execute_tool");
  // The JSON text is carried as is, escape sequence and all: parsing it is the mapper's job.
  assert.equal(a["gen_ai.tool.call.arguments"], '{"command":"echo \\u00e9"}');
  assert.equal(a.flag, true);
  assert.equal(a.small, 42);
  assert.equal(a.negative, -7);
  assert.equal(a.huge, "9223372036854775807", "integers past 2^53 stay exact as strings");
  assert.equal(a.ratio, 1.5);
  assert.deepEqual(a.list, ["a", 2]);
  assert.deepEqual(a.map, { k: "v", nested: [false] });
  assert.equal(a.blob, Buffer.from([1, 2, 3, 250]).toString("base64"));
  assert.equal(a.emoji, "snow ☃ 😀");
});

test("spans in later scopes and resources keep their own resource attributes", () => {
  const spans = spansFromOtlpProtobuf(golden());
  assert.equal(spans[1].parentSpanId, undefined);
  assert.equal(spans[1].status, undefined);
  assert.equal(spans[2].traceId, "aa".repeat(16));
  assert.deepEqual(spans[2].status, { code: "ok" });
  assert.equal(spans[2].resource["service.name"], "claude-platform");
  assert.equal(spans[3].resource["service.name"], "other");
  assert.equal(spans[3].attributes["service.name"], "span wins", "a span's own attribute beats its resource's");
});

test("unknown fields, dropped counts and events are skipped without harm", () => {
  // The golden span carries dropped_attributes_count, an event and a schema url.
  assert.equal(spansFromOtlpProtobuf(golden()).length, 4);
});

test("an empty body has no spans", () => {
  assert.deepEqual(spansFromOtlpProtobuf(new Uint8Array()), []);
});

test("every truncation of a valid payload either decodes or throws ProtobufError, never anything else", () => {
  const whole = golden();
  let thrown = 0;
  for (let n = 0; n < whole.length; n++) {
    try {
      spansFromOtlpProtobuf(whole.subarray(0, n));
    } catch (err) {
      assert.ok(err instanceof ProtobufError, `cut at ${n}: ${err}`);
      thrown++;
    }
  }
  assert.ok(thrown > 100, "most cuts land inside a field and are rejected");
});

test("random garbage never crashes the reader", () => {
  let seed = 1234567;
  const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  for (let i = 0; i < 500; i++) {
    const buf = Buffer.alloc(1 + (next() % 200));
    for (let j = 0; j < buf.length; j++) buf[j] = next() & 0xff;
    try {
      spansFromOtlpProtobuf(buf);
    } catch (err) {
      assert.ok(err instanceof ProtobufError, String(err));
    }
  }
});

test("a length that runs past the message is refused", () => {
  // Field 1 (resource_spans), length 100, but only three bytes follow.
  assert.throws(() => spansFromOtlpProtobuf(Buffer.from([0x0a, 100, 1, 2, 3])), ProtobufError);
});

test("deeply nested attribute values are refused rather than recursed into", () => {
  // AnyValue { array_value { values: [ AnyValue { array_value ... } ] } }, 60 deep.
  let inner = Buffer.from([0x0a, 0]); // string_value ""
  for (let i = 0; i < 60; i++) {
    const array = Buffer.concat([Buffer.from([0x0a, inner.length]), inner]); // ArrayValue.values
    inner = Buffer.concat([Buffer.from([0x2a, array.length]), array]); // AnyValue.array_value
  }
  const kv = Buffer.concat([Buffer.from([0x0a, 1, 0x6b, 0x12, inner.length]), inner]); // key "k", value
  const span = Buffer.concat([
    Buffer.from([0x0a, 16]), Buffer.alloc(16, 1), Buffer.from([0x12, 8]), Buffer.alloc(8, 2),
    Buffer.from([0x4a, kv.length]), kv,
  ]);
  const scope = Buffer.concat([Buffer.from([0x12, span.length]), span]);
  const rs = Buffer.concat([Buffer.from([0x12, scope.length]), scope]);
  const req = Buffer.concat([Buffer.from([0x0a, rs.length]), rs]);
  assert.throws(() => spansFromOtlpProtobuf(req), /nested too deeply|ProtobufError/);
});

test("spans missing a trace or span id are dropped", () => {
  // One span with only a name (field 5).
  const span = Buffer.concat([Buffer.from([0x2a, 1, 0x78])]);
  const scope = Buffer.concat([Buffer.from([0x12, span.length]), span]);
  const rs = Buffer.concat([Buffer.from([0x12, scope.length]), scope]);
  const req = Buffer.concat([Buffer.from([0x0a, rs.length]), rs]);
  assert.deepEqual(spansFromOtlpProtobuf(req), []);
});
