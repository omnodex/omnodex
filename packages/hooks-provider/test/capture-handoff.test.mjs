import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const shim = fileURLToPath(new URL("../dist/bin/claude-hook-shim.js", import.meta.url));
const payload = (id) => ({ session_id: "case-burst", cwd: "/home/case/repo", hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: id, tool_input: { command: "omnodex uninstall --confirm" } });
async function waitFor(check) {
  const end = Date.now() + 30000;
  while (Date.now() < end) { if (await check()) return; await new Promise(r => setTimeout(r, 40)); }
  throw new Error("capture did not settle");
}
async function rig(t) {
  const home = await mkdtemp(join(tmpdir(), "omnodex-handoff-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  const env = { ...process.env, HOME:home, USERPROFILE:home, OMNODEX_HOME:home, OMNODEX_SINGLE_ROOT:"1", OMNODEX_AUTO_SYNC:"0", OMNODEX_AUTO_DETECT:"0" };
  const events = async () => (await readFile(join(home,"event-log/sessions/case-burst.jsonl"),"utf8").catch(()=>"" )).split("\n").filter(Boolean).flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
  const receipts = async () => readdir(join(home,"hook-spool")).catch(()=>[]);
  const run = (raw, extra = {}) => new Promise((resolveRun,reject) => {
    const child = spawn(process.execPath,[shim,"--background"],{env:{...env,...extra},stdio:["pipe","pipe","pipe"]});
    let stdout="",stderr="";
    child.stdout.on("data",d=>stdout+=d); child.stderr.on("data",d=>stderr+=d);
    child.on("error",reject); child.on("close",code=>resolveRun({code,stdout,stderr}));
    child.stdin.end(raw);
  });
  return {home,env,events,receipts,run};
}

test("monitor receipt exits before worker imports finish; detached worker then captures and judges", async t => {
  const r = await rig(t);
  const gate = join(r.home,"release"), ready=join(r.home,"worker-ready");
  const preload=join(r.home,"hold-worker.mjs");
  await writeFile(preload, `import fs from 'node:fs';
if (process.argv.includes('--capture-worker')) {
 fs.writeFileSync(${JSON.stringify(ready)},'ready');
 while(!fs.existsSync(${JSON.stringify(gate)})) await new Promise(r=>setTimeout(r,20));
}`);
  t.after(()=>writeFile(gate,"release").catch(()=>{}));
  const result = await r.run(JSON.stringify(payload("case-first")), {NODE_OPTIONS:`--import=${pathToFileURL(preload).href}`});
  assert.equal(result.code,0,result.stderr); assert.equal(result.stdout,"");
  await waitFor(async()=>!!(await readFile(ready).catch(()=>null)));
  assert.equal((await r.receipts()).length,1,"receipt exists while worker is held");
  assert.deepEqual(await r.events(),[],"foreground did not wait for mapping or analysis");
  await writeFile(gate,"release");
  await waitFor(async()=> (await r.events()).some(e=>e.rule_id==="RULE_SELF_PROTECTION_BASH") && (await r.receipts()).length===0);
});

test("a rapid concurrent burst retains every invocation and finding after all receipt processes exit", async t => {
  const r=await rig(t), ids=Array.from({length:8},(_,i)=>`case-${i}`);
  const results=await Promise.all(ids.map(id=>r.run(JSON.stringify(payload(id)))));
  for(const result of results) { assert.equal(result.code,0,result.stderr); assert.equal(result.stdout,""); }
  await waitFor(async()=> (await r.events()).filter(e=>e.rule_id==="RULE_SELF_PROTECTION_BASH").length===ids.length && (await r.receipts()).length===0);
  const events=await r.events();
  assert.deepEqual(events.filter(e=>e.event_type==="tool.invoked").map(e=>e.tool_call_id).sort(),ids.sort());
});

test("malformed receipt input stays silent and does not create a pending payload", async t => {
  const r=await rig(t), result=await r.run("not JSON");
  assert.equal(result.code,0); assert.equal(result.stdout,""); assert.deepEqual(await r.receipts(),[]);
});

test("a recording pause keeps raw payloads out of the spool as well as the event log", async t => {
  const r=await rig(t);
  await writeFile(join(r.home,"pause-state.json"),JSON.stringify({record:{pause_id:"case-pause",paused_at:new Date().toISOString(),until:null,by:"cli"}}));
  const result=await r.run(JSON.stringify(payload("case-paused")));
  assert.equal(result.code,0,result.stderr); assert.equal(result.stdout,"");
  assert.deepEqual(await r.receipts(),[]); assert.deepEqual(await r.events(),[]);
});
