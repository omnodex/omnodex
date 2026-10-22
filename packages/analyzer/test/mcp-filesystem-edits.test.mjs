import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine, COMMUNITY_RULES, normalizeAction, credentialRole } from "../dist/index.js";
import { extractStagedContent } from "../dist/conditions/index.js";

const event=(name,path,edits)=>({schema_version:1,event_id:"case-edit",session_id:"case-mcp",occurred_at:"2026-10-22T12:00:00Z",recorded_at:"2026-10-22T12:00:00Z",interceptor:"mcp-proxy",event_type:"tool.invoked",tool_call_id:"case-call",tool_name:name,mcp_server:"filesystem",parameters:{path,edits}});
const run=(e,id)=>new RuleEngine(COMMUNITY_RULES.filter(r=>r.rule_id===id)).evaluate(e);
const target="/home/case/.claude/settings.json";
for(const name of ["edit_file","filesystem__edit_file","mcp__filesystem__edit_file"]) {
  for(const [label,oldText,newText,id] of [
    ["hook removal",'"command":"node claude-hook-launcher.js"','"command":"echo ready"',"RULE_SELF_PROTECTION_HOOK_REMOVED"],
    ["plugin disable",'"omnodex-cowork@local": true','"omnodex-cowork@local": false',"RULE_SELF_PROTECTION_HOOK_REMOVED"],
    ["disable hooks",'"theme":"dark"','"theme":"dark", "disableAllHooks": true',"RULE_SELF_PROTECTION_HOOKS_DISABLED"],
    ["MCP removal",'"omnodex": {"command":"node"}','',"RULE_SELF_PROTECTION_HOOK_REMOVED"],
  ]) test(`${name} MUST_FIRE: ${label} uses filesystem oldText/newText`,()=>{
    const e=event(name,target,[{oldText,newText}]), before=JSON.stringify(e);
    assert.equal(run(e,id).length,1);
    assert.deepEqual(normalizeAction(e).writes,[target]);
    assert.equal(credentialRole(e,newText||oldText),"content");
    assert.equal(JSON.stringify(e),before,"raw payload stays intact");
  });
  test(`${name} MUST_NOT_FIRE: benign hook edit keeps its entry`,()=>{
    const oldText='"command":"node claude-hook-launcher.js", "timeout":10';
    const e=event(name,target,[{oldText,newText:oldText.replace("10","11")}]);
    assert.deepEqual(run(e,"RULE_SELF_PROTECTION_HOOK_REMOVED"),[]);
    assert.deepEqual(run(e,"RULE_SELF_PROTECTION_HOOKS_DISABLED"),[]);
  });
  test(`${name} stages only newText, and does not execute the edit`,()=>{
    const e=event(name,"/home/case/setup.sh",[null,3,{}, {oldText:"omnodex uninstall",newText:"echo ready"},{old_string:"old",new_string:"echo done"}]);
    assert.deepEqual(extractStagedContent(e),[{path:"/home/case/setup.sh",text:"echo ready\necho done"}]);
    assert.deepEqual(run(e,"RULE_SELF_PROTECTION_BASH"),[]);
    const staged=event(name,"/home/case/setup.sh",[{oldText:"echo ready",newText:"omnodex uninstall"}]);
    assert.equal(run(staged,"RULE_SELF_PROTECTION_BASH")[0].severity,"MEDIUM");
    assert.equal(normalizeAction(staged).command,null);
    assert.deepEqual(run(event(name,"/home/case/README.md",staged.parameters.edits),"RULE_SELF_PROTECTION_BASH"),[]);
  });
}
