/**
 * Tests for the local dashboard server's exposure.
 *
 * The dashboard serves everything an agent did: tool parameters, file paths,
 * findings. These tests confirm only the local browser can read it:
 *   1. The server listens on loopback, not on every interface.
 *   2. No response carries a CORS allowance, so another page cannot read it.
 *   3. A request addressed to a non-loopback host name (DNS rebinding) or
 *      sent from another origin is refused, SSE stream included.
 *   4. The page and API still answer on localhost, 127.0.0.1 and [::1].
 */

import { test, before, after } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as http from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore } from "../../projection/dist/index.js";
import {
  DashboardServer,
  isLoopbackHost,
  isLoopbackOrigin,
} from "../dist/dashboard-server.js";

let assetsDir;
let server;
let port;

before(async () => {
  assetsDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-dash-"));
  await fs.writeFile(path.join(assetsDir, "dashboard.html"), "<!doctype html><title>t</title>");
  server = new DashboardServer({ store: new InMemoryReadModelStore(), port: 0, assetsDir });
  await server.ready;
  port = server.port;
});

after(async () => {
  server.close();
  await fs.rm(assetsDir, { recursive: true, force: true });
});

/** GET a path from 127.0.0.1 with the given headers; resolves status, headers, body. */
function get(pathname, headers = {}, address = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: address, port, path: pathname, method: "GET", headers: { host: `localhost:${port}`, ...headers } },
      (res) => {
        // SSE never ends on its own; the status and headers are all we need.
        if (res.headers["content-type"] === "text/event-stream") {
          resolve({ status: res.statusCode, headers: res.headers, body: "" });
          req.destroy();
          return;
        }
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function hasIpv6Loopback() {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.listen(0, "::1", () => probe.close(() => resolve(true)));
  });
}

// ---------------------------------------------------------------------------
// Host and Origin checks
// ---------------------------------------------------------------------------

test("isLoopbackHost accepts loopback names on the server's port only", () => {
  assert.ok(isLoopbackHost("localhost:7890", 7890));
  assert.ok(isLoopbackHost("LOCALHOST:7890", 7890));
  assert.ok(isLoopbackHost("127.0.0.1:7890", 7890));
  assert.ok(isLoopbackHost("[::1]:7890", 7890));

  assert.ok(!isLoopbackHost("localhost:7891", 7890));
  assert.ok(!isLoopbackHost("localhost", 7890));
  assert.ok(!isLoopbackHost("evil.example:7890", 7890));
  assert.ok(!isLoopbackHost("localhost.evil.example:7890", 7890));
  assert.ok(!isLoopbackHost("192.168.1.20:7890", 7890));
  assert.ok(!isLoopbackHost("0.0.0.0:7890", 7890));
  assert.ok(!isLoopbackHost("[::]:7890", 7890));
  assert.ok(!isLoopbackHost("", 7890));
  assert.ok(!isLoopbackHost(undefined, 7890));
});

test("isLoopbackOrigin allows a missing origin and this server's own origin", () => {
  assert.ok(isLoopbackOrigin(undefined, 7890));
  assert.ok(isLoopbackOrigin("http://localhost:7890", 7890));
  assert.ok(isLoopbackOrigin("http://127.0.0.1:7890", 7890));
  assert.ok(isLoopbackOrigin("http://[::1]:7890", 7890));

  assert.ok(!isLoopbackOrigin("https://evil.example", 7890));
  assert.ok(!isLoopbackOrigin("http://localhost:3000", 7890));
  assert.ok(!isLoopbackOrigin("null", 7890));
  assert.ok(!isLoopbackOrigin("file://", 7890));
});

// ---------------------------------------------------------------------------
// Live server
// ---------------------------------------------------------------------------

test("page and API answer on localhost with no CORS allowance", async () => {
  const page = await get("/");
  assert.equal(page.status, 200);
  assert.match(page.body, /<title>t<\/title>/);

  const api = await get("/api/sessions");
  assert.equal(api.status, 200);
  assert.deepEqual(JSON.parse(api.body), []);
  assert.equal(api.headers["access-control-allow-origin"], undefined);
});

test("same-origin requests from the dashboard page are allowed", async () => {
  const res = await get("/api/sessions", { origin: `http://localhost:${port}` });
  assert.equal(res.status, 200);
});

test("requests addressed to 127.0.0.1 and [::1] host names are allowed", async () => {
  assert.equal((await get("/api/sessions", { host: `127.0.0.1:${port}` })).status, 200);
  assert.equal((await get("/api/sessions", { host: `[::1]:${port}` })).status, 200);
});

test("a non-loopback Host header is refused (DNS rebinding)", async () => {
  const res = await get("/api/sessions", { host: `evil.example:${port}` });
  assert.equal(res.status, 403);
  assert.equal((await get("/", { host: `evil.example:${port}` })).status, 403);
});

test("a cross-origin request is refused, for the API and the SSE stream", async () => {
  const api = await get("/api/sessions", { origin: "https://evil.example" });
  assert.equal(api.status, 403);

  const sse = await get("/api/events", { origin: "https://evil.example" });
  assert.equal(sse.status, 403);

  const ownSse = await get("/api/events", { origin: `http://localhost:${port}` });
  assert.equal(ownSse.status, 200);
  assert.equal(ownSse.headers["access-control-allow-origin"], undefined);
});

test("a CORS preflight gets no allowance", async () => {
  const res = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/api/sessions",
        method: "OPTIONS",
        headers: { host: `localhost:${port}`, origin: "https://evil.example", "access-control-request-method": "GET" },
      },
      (r) => {
        r.resume();
        r.on("end", () => resolve(r));
      },
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.headers["access-control-allow-origin"], undefined);
});

test("the server is reachable over IPv6 loopback when the host has it", async (t) => {
  if (!(await hasIpv6Loopback())) {
    t.skip("no IPv6 loopback on this host");
    return;
  }
  const res = await get("/api/sessions", { host: `[::1]:${port}` }, "::1");
  assert.equal(res.status, 200);
});

test("the server does not listen on non-loopback interfaces", async (t) => {
  const external = Object.values(os.networkInterfaces())
    .flat()
    .find((i) => i && i.family === "IPv4" && !i.internal);
  if (!external) {
    t.skip("no non-loopback IPv4 interface on this host");
    return;
  }
  await assert.rejects(
    () => get("/api/sessions", { host: `${external.address}:${port}` }, external.address),
    (err) => err.code === "ECONNREFUSED" || err.code === "EHOSTUNREACH" || err.code === "ETIMEDOUT",
  );
});

test("ready rejects when the port is already taken", async () => {
  const blocker = net.createServer();
  await new Promise((resolve) => blocker.listen(0, "127.0.0.1", resolve));
  const taken = blocker.address().port;
  const clash = new DashboardServer({ store: new InMemoryReadModelStore(), port: taken, assetsDir });
  try {
    await assert.rejects(clash.ready, (err) => err.code === "EADDRINUSE");
  } finally {
    clash.close();
    await new Promise((resolve) => blocker.close(resolve));
  }
});
