// Span builders for the mapper tests. Attribute names follow the Claude API
// span reference and the OpenTelemetry GenAI conventions as of the pinned
// reference commit; a probe against the real services may refine them.

export const T0 = Date.parse("2026-11-13T15:00:00.000Z");

const hex = (n, len) => n.toString(16).padStart(len, "0");

/** Nanosecond string for `ms` after T0. */
export function at(ms) {
  return String(BigInt(T0 + ms) * 1_000_000n);
}

let counter = 0;
export function resetIds() {
  counter = 0;
}

/** An OtelSpan with ids filled in. Attributes are a plain object. */
export function span({ name, trace = 1, id, parent, start = 0, end = 10, attributes = {}, status, resource = {} }) {
  counter += 1;
  return {
    traceId: hex(trace, 32),
    spanId: hex(id ?? counter, 16),
    ...(parent ? { parentSpanId: hex(parent, 16) } : {}),
    name,
    startTimeUnixNano: at(start),
    endTimeUnixNano: at(end),
    attributes: { ...resource, ...attributes },
    resource,
    ...(status ? { status } : {}),
  };
}

export const SESSION = "sesn_01abc";

/** Attributes every Claude API span carries. */
export function platformAttrs(extra = {}) {
  return {
    "anthropic.organization.id": "org_1",
    "anthropic.workspace.id": "wrkspc_1",
    "anthropic.session.id": SESSION,
    "gen_ai.conversation.id": "thread_main",
    ...extra,
  };
}

export function toolSpan({ tool = "bash", args, result, spanName, extra = {}, ...rest }) {
  return span({
    name: spanName ?? `anthropic.tool_use ${tool}`,
    attributes: platformAttrs({
      "gen_ai.operation.name": "execute_tool",
      "gen_ai.tool.name": tool,
      "gen_ai.tool.call.id": `toolu_${tool}`,
      ...(args !== undefined ? { "gen_ai.tool.call.arguments": typeof args === "string" ? args : JSON.stringify(args) } : {}),
      ...(result !== undefined ? { "anthropic.tool_result.content": typeof result === "string" ? result : JSON.stringify(result) } : {}),
      ...extra,
    }),
    ...rest,
  });
}

export function turnSpan({ input, output, model = "claude-fable-5-2", thread = "thread_main", extra = {}, ...rest }) {
  return span({
    name: "anthropic.session.turn",
    attributes: platformAttrs({
      "gen_ai.operation.name": "invoke_agent",
      "gen_ai.conversation.id": thread,
      "gen_ai.agent.id": "agent_1",
      "gen_ai.agent.name": "Deploy bot",
      "gen_ai.request.model": model,
      ...(input !== undefined ? { "gen_ai.input.messages": JSON.stringify(input) } : {}),
      ...(output !== undefined ? { "gen_ai.output.messages": JSON.stringify(output) } : {}),
      ...extra,
    }),
    ...rest,
  });
}

export const userMessage = (text) => [{ role: "user", parts: [{ type: "text", content: text }] }];
export const toolCallMessage = (id, name, args) => [
  { role: "assistant", parts: [{ type: "tool_call", id, name, arguments: args }], finish_reason: "tool_calls" },
];

export function byType(events, type) {
  return events.filter((e) => e.event_type === type);
}
