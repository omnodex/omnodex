/**
 * The local dashboard's feedback link: an email to the support address with
 * the CLI version and platform in the subject, and the server's /api/info
 * that supplies the version. No network call from the page itself.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { FEEDBACK_EMAIL, feedbackMailto } from "../dist/dashboard-model/feedback.js";
import { InMemoryReadModelStore } from "../../projection/dist/index.js";
import { DashboardServer } from "../dist/dashboard-server.js";

test("feedback goes to the support address", () => {
  assert.equal(FEEDBACK_EMAIL, "support@omnodex.com");
});

test("the subject carries the version and platform", () => {
  const url = new URL(feedbackMailto("0.7.1", "Linux"));
  assert.equal(url.protocol, "mailto:");
  assert.equal(url.pathname, "support@omnodex.com");
  assert.equal(url.searchParams.get("subject"), "Omnodex local dashboard feedback, v0.7.1, Linux");
  assert.match(url.searchParams.get("body") ?? "", /What happened/);
});

test("the subject leaves out what is unknown", () => {
  const url = new URL(feedbackMailto(null, ""));
  assert.equal(url.searchParams.get("subject"), "Omnodex local dashboard feedback");
  assert.equal(new URL(feedbackMailto("v0.8.0", null)).searchParams.get("subject"), "Omnodex local dashboard feedback, v0.8.0");
  assert.equal(new URL(feedbackMailto("0.0.0", "Windows")).searchParams.get("subject"), "Omnodex local dashboard feedback, source build, Windows");
});

test("/api/info reports the CLI version", async (t) => {
  const assetsDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-dash-info-"));
  await fs.writeFile(path.join(assetsDir, "dashboard.html"), "<!doctype html><title>t</title>");
  const server = new DashboardServer({ store: new InMemoryReadModelStore(), port: 0, assetsDir, version: "0.7.1" });
  t.after(async () => {
    server.close();
    await fs.rm(assetsDir, { recursive: true, force: true });
  });
  await server.ready;
  const body = await new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port: server.port, path: "/api/info", headers: { host: `localhost:${server.port}` } }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
  assert.deepEqual(JSON.parse(body), { version: "0.7.1" });
});
