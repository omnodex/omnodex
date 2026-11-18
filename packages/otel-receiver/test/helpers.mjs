import { promises as fs } from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "@omnodex/event-log";
import { createLocalSink, Spool, startReceiver } from "../dist/index.js";
import { T0 } from "./fixtures.mjs";

// node:test runs t.after hooks in the order they were registered, not last in
// first out. Anything that writes into a scratch home registers its closer here
// so the home is removed only after the receiver and its sink have closed.
const closers = new WeakMap();
export function closeBeforeRemoval(t, close) {
  closers.get(t)?.push(close);
}

/** A scratch home. Also points HOME and the Omnodex variables at it, so nothing here can touch the real one. */
export async function scratchHome(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-otel-case-"));
  const home = path.join(root, ".omnodex");
  await fs.mkdir(home, { recursive: true });
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, OMNODEX_HOME: process.env.OMNODEX_HOME, OMNODEX_SINGLE_ROOT: process.env.OMNODEX_SINGLE_ROOT };
  Object.assign(process.env, { HOME: root, USERPROFILE: root, OMNODEX_HOME: home, OMNODEX_SINGLE_ROOT: "1" });
  const mine = [];
  closers.set(t, mine);
  t.after(async () => {
    for (const close of mine.reverse()) await close();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return home;
}

/** A started receiver on an ephemeral loopback port, writing to a scratch home. */
export async function startLocal(t, options = {}) {
  const home = options.home ?? (await scratchHome(t));
  const sink = options.sink ?? (await createLocalSink({ home }));
  const spool = new Spool(path.join(home, "otel-spool"));
  const receiver = await startReceiver({ host: "127.0.0.1", port: 0, spool, sink, sweepMs: 20, ...options, home: undefined });
  let closed = false;
  const close = async () => {
    if (!closed) {
      closed = true;
      await receiver.close();
    }
  };
  closeBeforeRemoval(t, close);
  t.after(close);
  return { home, receiver, spool, close, url: `http://127.0.0.1:${receiver.port}` };
}

export function request(url, { method = "POST", path: p = "/v1/traces", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, method, path: p, headers, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export const JSON_HEADERS = { "content-type": "application/json" };
export const PB_HEADERS = { "content-type": "application/x-protobuf" };

/** An OTLP/JSON export request for some OtelSpans from fixtures.mjs. */
export function jsonExport(spans) {
  const kv = (key, v) => ({
    key,
    value: typeof v === "boolean" ? { boolValue: v } : typeof v === "number" ? { intValue: String(v) } : { stringValue: String(v) },
  });
  return JSON.stringify({
    resourceSpans: [{
      resource: { attributes: [] },
      scopeSpans: [{
        spans: spans.map((s) => ({
          traceId: s.traceId, spanId: s.spanId, name: s.name,
          startTimeUnixNano: s.startTimeUnixNano, endTimeUnixNano: s.endTimeUnixNano,
          attributes: Object.entries(s.attributes).map(([k, v]) => kv(k, v)),
          ...(s.status ? { status: { code: s.status.code === "error" ? 2 : 1 } } : {}),
        })),
      }],
    }],
  });
}

// -- a minimal protobuf writer, for tests only ---------------------------------

const varint = (n) => {
  let v = BigInt(n);
  const out = [];
  while (v > 0x7fn) {
    out.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  out.push(Number(v));
  return Buffer.from(out);
};
const len = (no, buf) => Buffer.concat([varint(no * 8 + 2), varint(buf.length), buf]);
const str = (no, s) => len(no, Buffer.from(s, "utf8"));
const fixed64 = (no, n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return Buffer.concat([varint(no * 8 + 1), b]);
};
const attr = (k, v) => len(9, Buffer.concat([str(1, k), len(2, str(1, String(v)))]));

/** An OTLP protobuf export request for OtelSpans with string-valued attributes. */
export function protobufExport(spans) {
  const encoded = spans.map((s) =>
    Buffer.concat([
      len(1, Buffer.from(s.traceId, "hex")), len(2, Buffer.from(s.spanId, "hex")), str(5, s.name),
      fixed64(7, s.startTimeUnixNano), fixed64(8, s.endTimeUnixNano),
      ...Object.entries(s.attributes).map(([k, v]) => attr(k, v)),
    ]),
  );
  const scope = Buffer.concat(encoded.map((e) => len(2, e)));
  return len(1, len(2, scope));
}

export async function readAllEvents(home) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  const out = [];
  for (const id of await log.listSessions()) out.push(...(await log.readSession(id)));
  await log.close();
  return out;
}

export { T0 };
