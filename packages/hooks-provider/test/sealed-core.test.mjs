// Tests for the generic parts of the sealed capture core: optional ingest
// token, platform label control and pluggable payload adapters.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  ingestDir,
  handleHookPayload,
  makeCurlPoster,
  parseIngestConfig,
  postWithFetch,
  prepareEvent,
} from "../dist/container-hook.js";
import { bytesToBase64, generateStreamKeyPair, openEvent } from "../../sync-encryptor/dist/hpke-event.js";

async function rawConfig(extra = {}) {
  const pair = await generateStreamKeyPair();
  const raw = {
    version: 1,
    source_id: "src_0123456789ab",
    public_key: bytesToBase64(pair.publicKey),
    key_id: pair.keyId,
    ...extra,
  };
  return { pair, raw };
}

const home = () => fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-sealed-core-"));
const EVENT = {
  schema_version: 1,
  event_id: "e1",
  event_type: "tool.invoked",
  session_id: "s1",
  occurred_at: "2026-11-13T12:00:00.000Z",
  recorded_at: "2026-11-13T12:00:00.000Z",
  interceptor: "copilot-hook",
  platform: "copilot",
  tool_name: "bash",
  parameters: { command: "ls" },
};

test("a missing token is refused unless the caller allows it", async () => {
  const { raw } = await rawConfig();
  assert.equal(await parseIngestConfig(raw), null);
  const cfg = await parseIngestConfig(raw, { tokenOptional: true });
  assert.ok(cfg);
  assert.equal(cfg.ingestToken, undefined);
});

test("a malformed token is refused even when a token is optional", async () => {
  const { raw } = await rawConfig({ ingest_token: "nope" });
  assert.equal(await parseIngestConfig(raw, { tokenOptional: true }), null);
});

test("a token that is present is kept when optional tokens are allowed", async () => {
  const { raw } = await rawConfig({ ingest_token: "oxi_" + "C".repeat(43) });
  const cfg = await parseIngestConfig(raw, { tokenOptional: true });
  assert.equal(cfg.ingestToken, "oxi_" + "C".repeat(43));
});

test("prepareEvent keeps the mapper's platform when asked to, and defaults to cowork", () => {
  assert.equal(prepareEvent(EVENT, false).platform, "cowork");
  assert.equal(prepareEvent(EVENT, false, null).platform, "copilot");
  assert.equal(prepareEvent(EVENT, false, "cursor").platform, "cursor");
});

test("a custom adapter's events are sealed, spooled and sent without a token", async () => {
  const { pair, raw } = await rawConfig();
  const config = await parseIngestConfig(raw, { tokenOptional: true });
  const h = home();
  const calls = [];
  const post = async (url, token, body) => {
    calls.push({ url, token, body: JSON.parse(body) });
    return { status: 202 };
  };
  await handleHookPayload({ hook_event_name: "x" }, config, {
    home: h,
    post,
    platform: null,
    adapter: async () => ({ events: [EVENT], flush: true }),
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].token, undefined);
  assert.equal(calls[0].body.events.length, 1);
  const opened = await openEvent({ keyId: pair.keyId, privateKey: pair.privateKey }, calls[0].body.events[0]);
  assert.equal(JSON.parse(new TextDecoder().decode(opened)).platform, "copilot");
});

test("an adapter that declines a payload leaves no spool", async () => {
  const { raw } = await rawConfig();
  const config = await parseIngestConfig(raw, { tokenOptional: true });
  const h = home();
  const out = await handleHookPayload({}, config, { home: h, post: async () => ({ status: 202 }), adapter: async () => null });
  assert.equal(out, null);
  assert.equal(fs.existsSync(ingestDir(h)), false);
});

test("fetch and curl posters send no Authorization header without a token", async () => {
  const http = await import("node:http");
  const seen = [];
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push(req.headers.authorization);
      res.writeHead(202).end("{}");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/x`;
  try {
    assert.deepEqual(await postWithFetch(url, undefined, "{}"), { status: 202 });
    assert.deepEqual(await makeCurlPoster(home())(url, undefined, "{}"), { status: 202 });
    assert.deepEqual(await postWithFetch(url, "t", "{}"), { status: 202 });
  } finally {
    server.close();
  }
  assert.deepEqual(seen, [undefined, undefined, "Bearer t"]);
});
