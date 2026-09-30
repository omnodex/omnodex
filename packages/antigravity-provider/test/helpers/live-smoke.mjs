// Manual authenticated CLI smoke: node packages/antigravity-provider/test/helpers/live-smoke.mjs
// Uses a scratch project and Omnodex home; no hosted credentials or global edits.
import { mkdtemp, mkdir, writeFile, readdir, readFile, rm, cp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { AntigravityInterceptor } from "../../dist/antigravity-interceptor.js";

const project = await mkdtemp(join(tmpdir(), "omnodex-agy-live-"));
const home = join(project, "omnodex-home");
const proxy = fileURLToPath(new URL("../../../../mcp-proxy/dist/bin/omnodex-mcp-proxy.js", import.meta.url));
const shim = fileURLToPath(new URL("../../dist/bin/antigravity-hook-shim.js", import.meta.url));
try {
  await mkdir(home);
  const wrapper = join(project, "capture-hook.mjs");
  await writeFile(wrapper, `import { readFileSync, appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const raw = readFileSync(0, 'utf8');
appendFileSync(${JSON.stringify(join(home, "hook-inputs.jsonl"))}, JSON.stringify({ event: process.argv[2], payload: JSON.parse(raw) }) + '\\n');
const result = spawnSync(process.execPath, [${JSON.stringify(shim)}, process.argv[2]], { input: raw, encoding: 'utf8', env: process.env });
process.stdout.write(result.stdout ?? '');
process.stderr.write(result.stderr ?? '');
process.exit(result.status ?? 1);
`);
  await writeFile(join(project, "example.txt"), "case-live-capture\n");
  await writeFile(join(home, "omnodex-proxy.json"), JSON.stringify({ version: 1, upstream_servers: [], proxy_bin: proxy }));
  await new AntigravityInterceptor({ projectPath: project, shimPath: wrapper, omnodexHome: home, nodePath: process.execPath }).install();
  const pluginArg = process.argv.indexOf("--plugin");
  if (pluginArg !== -1) {
    const plugin = join(project, ".agents", "plugins", "omnodex-antigravity");
    await cp(process.argv[pluginArg + 1], plugin, { recursive: true });
    const configured = spawnSync(process.execPath, [join(plugin, "bin", "configure.js")], { encoding: "utf8" });
    if (configured.status !== 0) throw new Error(configured.stderr);
  } else await writeFile(join(project, ".agents", "mcp_config.json"), JSON.stringify({ mcpServers: {
    "omnodex-live-test": { command: process.execPath, args: [proxy, "--config", join(home, "omnodex-proxy.json"), "--platform", "antigravity"], env: { OMNODEX_HOME: home } },
  } }));
  const child = spawn("agy", ["--print", "Use view_file to read example.txt in this project, then reply with its contents. Do not edit files, run commands, or use MCP servers.", "--print-timeout", "45s", "--output-format", "json"], {
    cwd: project, env: { ...process.env, OMNODEX_HOME: home, OMNODEX_PROXY_BIN: "", OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0" }, stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "", stderr = "";
  child.stdout.on("data", d => { stdout += d; });
  child.stderr.on("data", d => { stderr += d; });
  const code = await new Promise((resolve, reject) => { child.on("close", resolve); child.on("error", reject); });
  console.log(JSON.stringify({ code, stdout, stderr }));
  const events = [];
  for (const name of await readdir(join(home, "event-log", "sessions")).catch(() => [])) {
    if (name.endsWith(".jsonl")) events.push(...(await readFile(join(home, "event-log", "sessions", name), "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse));
  }
  console.log(JSON.stringify({ events: events.map(e => ({ type: e.event_type, interceptor: e.interceptor, session: e.session_id, tool: e.tool_name, status: e.status })) }));
  const inputs = (await readFile(join(home, "hook-inputs.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
  console.log(JSON.stringify({ inputs: inputs.map(({ event, payload }) => ({ event, fields: Object.keys(payload), fullyIdle: payload.fullyIdle, executionNum: payload.executionNum, invocationNum: payload.invocationNum, initialNumSteps: payload.initialNumSteps })) }));
  if (code !== 0 || !events.some(e => e.interceptor === "antigravity-hook" && e.event_type === "tool.invoked")
    || !events.some(e => e.interceptor === "mcp-proxy" && e.event_type === "session.started")) process.exitCode = 1;
} finally {
  await rm(project, { recursive: true, force: true });
}
