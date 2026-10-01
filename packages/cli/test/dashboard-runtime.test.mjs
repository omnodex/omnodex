/**
 * Tests for running the local dashboard on every platform.
 *
 * These tests confirm:
 *   1. The page is found from a source checkout and from the npm bundle
 *      layout, including under a path with a space, using the platform's
 *      own path conventions (no hand-built Windows or POSIX paths).
 *   2. A source checkout serves the page build-dashboard.mjs wrote to
 *      dist/dashboard.html byte for byte, and a missing page gets a page
 *      that says how to build it rather than an error.
 *   3. Shutdown closes every resource, in order, and a failing step does
 *      not stop the rest.
 *   4. Closing the server drops open SSE and keep-alive connections instead
 *      of waiting for them.
 *   5. The real `omnodex dashboard` command serves the page and the API,
 *      and on POSIX exits cleanly on SIGINT (Windows cannot deliver a
 *      catchable signal to a child process; item 3 covers its shutdown).
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs, readFileSync } from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { InMemoryReadModelStore } from "../../projection/dist/index.js";
import { waitFor } from "../../../scripts/test-wait.mjs";
import {
  DashboardServer,
  resolveDashboardAssetsDir,
  shutdownDashboard,
} from "../dist/dashboard-server.js";

const PKG_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLI = path.join(PKG_DIR, "dist", "index.js");
const BUILT_HTML = path.join(PKG_DIR, "dist", "dashboard.html");

async function tempDir(prefix) {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

function get(port, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: pathname, headers: { host: `localhost:${port}` } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Asset resolution
// ---------------------------------------------------------------------------

test("a source checkout serves the built page from dist/, even under a path with a space", async () => {
  const root = await tempDir("omnodex dash ");
  try {
    const pkg = path.join(root, "packages", "cli");
    await fs.mkdir(path.join(pkg, "dist"), { recursive: true });
    await fs.mkdir(path.join(pkg, "bundle"), { recursive: true });
    await fs.writeFile(path.join(pkg, "package.json"), JSON.stringify({ name: "@omnodex/cli" }));
    await fs.writeFile(path.join(pkg, "dist", "dashboard.html"), "current");
    await fs.writeFile(path.join(pkg, "bundle", "dashboard.html"), "stale");

    const moduleUrl = pathToFileURL(path.join(pkg, "dist", "index.js")).href;
    assert.match(moduleUrl, /%20/, "the module URL percent-encodes the space");
    const dir = resolveDashboardAssetsDir(moduleUrl);
    assert.equal(dir, path.join(pkg, "dist"));
    assert.equal(readFileSync(path.join(dir, "dashboard.html"), "utf8"), "current");
    // The bundle, run from a source checkout, serves the current build too.
    const fromBundle = resolveDashboardAssetsDir(pathToFileURL(path.join(pkg, "bundle", "omnodex-bundle.cjs")).href);
    assert.equal(readFileSync(path.join(fromBundle, "dashboard.html"), "utf8"), "current");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a checkout whose page was never built serves instructions instead of an error", async () => {
  const root = await tempDir("omnodex unbuilt ");
  const server = new DashboardServer({ store: new InMemoryReadModelStore(), port: 0, assetsDir: root });
  try {
    await server.ready;
    const page = await get(server.port, "/");
    assert.equal(page.status, 200);
    assert.match(page.body.toString("utf8"), /npm run build/);
  } finally {
    await server.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("the npm bundle serves the page shipped next to the module", async () => {
  const root = await tempDir("omnodex bundle ");
  try {
    const pkg = path.join(root, "node_modules", "omnodex");
    await fs.mkdir(pkg, { recursive: true });
    await fs.writeFile(path.join(pkg, "package.json"), JSON.stringify({ name: "omnodex" }));
    await fs.writeFile(path.join(pkg, "dashboard.html"), "bundled");

    const dir = resolveDashboardAssetsDir(pathToFileURL(path.join(pkg, "omnodex-bundle.cjs")).href);
    assert.equal(dir, pkg);
    assert.equal(readFileSync(path.join(dir, "dashboard.html"), "utf8"), "bundled");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("this checkout serves the built dist/dashboard.html byte for byte", async () => {
  const assetsDir = resolveDashboardAssetsDir(pathToFileURL(CLI).href);
  const server = new DashboardServer({ store: new InMemoryReadModelStore(), port: 0, assetsDir });
  try {
    await server.ready;
    const page = await get(server.port, "/");
    assert.equal(page.status, 200);
    assert.ok(page.body.equals(readFileSync(BUILT_HTML)), "served page differs from dist/dashboard.html");
  } finally {
    await server.close();
  }
});

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

test("shutdownDashboard closes writers, then the server, then logs and store", async () => {
  const order = [];
  const closer = (name) => ({ close: async () => void order.push(name) });
  await shutdownDashboard({
    stopStreaming: async () => void order.push("streaming"),
    transport: { stop: async () => void order.push("transport") },
    server: closer("server"),
    logs: [{ log: closer("log-a") }, { log: closer("log-b") }],
    store: closer("store"),
  });
  assert.deepEqual(order, ["streaming", "transport", "server", "log-a", "log-b", "store"]);
});

test("a failing shutdown step does not leave later resources open", async () => {
  const closed = [];
  const originalError = console.error;
  console.error = () => {};
  try {
    await shutdownDashboard({
      stopStreaming: async () => {
        throw new Error("boom");
      },
      transport: null,
      server: { close: async () => void closed.push("server") },
      logs: [{ log: { close: async () => { throw new Error("log"); } } }],
      store: { close: async () => void closed.push("store") },
    });
  } finally {
    console.error = originalError;
  }
  assert.deepEqual(closed, ["server", "store"]);
});

test("closing the server drops an open SSE stream instead of waiting for it", async () => {
  const assetsDir = await tempDir("omnodex-dash-");
  const server = new DashboardServer({ store: new InMemoryReadModelStore(), port: 0, assetsDir });
  try {
    await server.ready;
    let streamConnected = false;
    const streamClosed = new Promise((resolve, reject) => {
      const req = http.get(
        { host: "127.0.0.1", port: server.port, path: "/api/events", headers: { host: `localhost:${server.port}` } },
        (res) => {
          streamConnected = true;
          res.on("data", () => {});
          res.on("close", resolve);
        },
      );
      req.on("error", resolve);
      setTimeout(() => reject(new Error("SSE stream still open")), 5_000).unref();
    });
    // Let the stream connect before closing.
    await waitFor(() => streamConnected, 5000, "SSE connection");
    const started = Date.now();
    await server.close();
    await streamClosed;
    assert.ok(Date.now() - started < 2_000, "close waited on the open stream");
  } finally {
    await fs.rm(assetsDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// The real command
// ---------------------------------------------------------------------------

test("omnodex dashboard serves the page and API, and exits cleanly on SIGINT", async (t) => {
  const scratch = await tempDir("omnodex dashboard cli ");
  const env = {
    ...process.env,
    HOME: scratch,
    USERPROFILE: scratch,
    OMNODEX_HOME: path.join(scratch, ".omnodex"),
    OMNODEX_NO_UPDATE_CHECK: "1",
    OMNODEX_API_TOKEN: "",
  };
  const child = spawn(process.execPath, [CLI, "dashboard", "0", "--no-detect"], { env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (c) => (output += c));
  child.stderr.on("data", (c) => (output += c));
  const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));

  try {
    const port = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`dashboard did not start:\n${output}`)), 30_000);
      const check = () => {
        const match = /open http:\/\/localhost:(\d+)/.exec(output);
        if (match) {
          clearTimeout(timer);
          resolve(Number(match[1]));
        }
      };
      child.stdout.on("data", check);
      child.on("exit", () => reject(new Error(`dashboard exited early:\n${output}`)));
    });

    const page = await get(port, "/");
    assert.equal(page.status, 200);
    assert.ok(page.body.equals(readFileSync(BUILT_HTML)), "served page differs from dist/dashboard.html");
    assert.equal((await get(port, "/api/sessions")).status, 200);

    if (process.platform === "win32") {
      t.diagnostic("Windows cannot send a catchable SIGINT to a child; shutdown is covered by the unit tests above");
      child.kill();
      await exited;
      return;
    }

    child.kill("SIGINT");
    const result = await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(() => resolve({ timeout: true }), 15_000)),
    ]);
    assert.notEqual(result.timeout, true, `dashboard did not exit after SIGINT:\n${output}`);
    assert.equal(result.code, 0, `exit code ${result.code}, signal ${result.signal}:\n${output}`);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
      await exited;
    }
    await fs.rm(scratch, { recursive: true, force: true });
  }
});
