import { test } from "node:test";
import assert from "node:assert/strict";
import { anyValueToJs, createOtelMapper, spansFromOtlpJson } from "../dist/index.js";
import { byType } from "./fixtures.mjs";
import { InMemoryReadModelStore, Projector } from "@omnodex/projection";

// An ExportTraceServiceRequest in OTLP/JSON, as the protobuf JSON mapping
// writes it: hex ids, nanosecond times and 64-bit integers as strings.
const START = "1794582000000000000"; // 2026-11-13T15:00:00Z
const END = "1794582000250000000";

function request() {
  return {
    resourceSpans: [
      {
        resource: {
          attributes: [
            { key: "service.name", value: { stringValue: "claude-platform" } },
            { key: "anthropic.organization.id", value: { stringValue: "org_1" } },
          ],
        },
        scopeSpans: [
          {
            scope: { name: "anthropic" },
            spans: [
              {
                traceId: "5B8EFFF798038103D269B633813FC60C",
                spanId: "EEE19B7EC3C1B174",
                name: "anthropic.tool_use bash",
                kind: 1,
                startTimeUnixNano: START,
                endTimeUnixNano: END,
                attributes: [
                  { key: "anthropic.session.id", value: { stringValue: "sesn_1" } },
                  { key: "gen_ai.operation.name", value: { stringValue: "execute_tool" } },
                  { key: "gen_ai.tool.name", value: { stringValue: "bash" } },
                  { key: "gen_ai.tool.call.id", value: { stringValue: "toolu_1" } },
                  { key: "gen_ai.tool.call.arguments", value: { stringValue: '{"command":"id"}' } },
                  { key: "anthropic.content.size", value: { intValue: "42" } },
                  { key: "anthropic.content.truncated", value: { boolValue: false } },
                ],
                status: { code: 1 },
              },
              { traceId: "bad" },
              "not a span",
            ],
          },
        ],
      },
    ],
  };
}

test("OTLP/JSON spans decode with resource attributes merged under the span's own", () => {
  const spans = spansFromOtlpJson(request());
  assert.equal(spans.length, 1, "malformed siblings are skipped, not fatal");
  const s = spans[0];
  assert.equal(s.traceId, "5b8efff798038103d269b633813fc60c");
  assert.equal(s.spanId, "eee19b7ec3c1b174");
  assert.equal(s.startTimeUnixNano, START);
  assert.equal(s.attributes["anthropic.organization.id"], "org_1");
  assert.equal(s.attributes["anthropic.content.size"], 42);
  assert.equal(s.attributes["anthropic.content.truncated"], false);
  assert.equal(s.resource["service.name"], "claude-platform");
  assert.equal(s.attributes["gen_ai.tool.name"], "bash");
  assert.deepEqual(s.status, { code: "ok" });
});

test("status codes read as numbers or as enum names", () => {
  const body = request();
  const span = body.resourceSpans[0].scopeSpans[0].spans[0];
  span.status = { code: "STATUS_CODE_ERROR", message: "boom" };
  assert.deepEqual(spansFromOtlpJson(body)[0].status, { code: "error", message: "boom" });
  span.status = { code: 2 };
  assert.deepEqual(spansFromOtlpJson(body)[0].status, { code: "error" });
  delete span.status;
  assert.equal(spansFromOtlpJson(body)[0].status, undefined);
});

test("garbage bodies yield no spans", () => {
  for (const body of [null, undefined, 3, "x", [], {}, { resourceSpans: "x" }, { resourceSpans: [null, { scopeSpans: 3 }] }]) {
    assert.deepEqual(spansFromOtlpJson(body), []);
  }
});

test("AnyValue covers arrays, key-value lists, doubles and unsafe integers", () => {
  assert.deepEqual(anyValueToJs({ arrayValue: { values: [{ stringValue: "a" }, { intValue: "2" }] } }), ["a", 2]);
  assert.deepEqual(anyValueToJs({ kvlistValue: { values: [{ key: "k", value: { doubleValue: 1.5 } }] } }), { k: 1.5 });
  assert.equal(anyValueToJs({ intValue: "9223372036854775807" }), "9223372036854775807");
  assert.equal(anyValueToJs({}), null);
  assert.equal(anyValueToJs(undefined), null);
});

test("an OTLP/JSON request maps end to end into the read model, and redelivery changes nothing", async () => {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const mapper = createOtelMapper({ clock: () => Date.parse("2026-11-13T15:01:00Z") });

  const first = mapper.mapSpans(spansFromOtlpJson(request())).events;
  for (const e of first) await projector.apply(e);
  // Anthropic delivers at least once: the same request again, to a receiver
  // that restarted and forgot the session.
  const again = createOtelMapper({ clock: () => Date.parse("2026-11-13T15:02:00Z") }).mapSpans(spansFromOtlpJson(request())).events;
  for (const e of again) await projector.apply(e);

  assert.deepEqual(first.map((e) => e.event_id), again.map((e) => e.event_id));
  const sessions = await store.listSessions();
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].session_id, "ma:sesn_1");
  assert.equal(sessions[0].platform, "managed-agents");
  assert.equal(sessions[0].interceptor, "otel-receiver");
  assert.equal(sessions[0].tool_call_count, 1);
  const calls = await store.listToolCalls("ma:sesn_1");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].tool_call_id, "toolu_1");
  assert.equal(calls[0].status, "success");
  assert.equal(calls[0].duration_ms, 250);
  assert.equal(JSON.parse(calls[0].parameters_json).command, "id");
  assert.equal(byType(first, "session.started")[0].origin.org_id, "org_1");
});
