import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine, COMMUNITY_RULES } from "../dist/index.js";
const rules=COMMUNITY_RULES.filter(r=>["RULE_SELF_PROTECTION_BASH","RULE_SELF_PROTECTION_HOOKS_DISABLED"].includes(r.rule_id));
const run=(tool_name,parameters)=>new RuleEngine(rules).evaluate({schema_version:1,event_id:"case",session_id:"case",occurred_at:"2026-10-22T12:00:00Z",recorded_at:"2026-10-22T12:00:00Z",event_type:"tool.invoked",interceptor:"mock",tool_call_id:"case-call",tool_name,mcp_server:"builtin",parameters});
const content='{"hooks":{"Stop":[{"command":"node capture.js"}]},"disableAllHooks":true}';
for(const file_path of ["/home/case/.claude/settings.json","C:\\Users\\case\\.claude\\settings.local.json","/home/case/custom/settings.json"]) {
  for(const [tool,params] of [
    ["Edit",{file_path,old_string:'"theme":"dark"',new_string:'"disableAllHooks":true'}],
    ["Write",{file_path,content}],
    ["mcp__filesystem__edit_file",{path:file_path,edits:[{oldText:'"theme":"dark"',newText:'"disableAllHooks":true'}]}],
  ]) test(`${tool}: direct settings write produces only the HIGH hooks-disabled finding (${file_path})`,()=>{
    const found=run(tool,params);
    assert.deepEqual(found.map(f=>[f.rule_id,f.severity]),[["RULE_SELF_PROTECTION_HOOKS_DISABLED","HIGH"]]);
  });
}
test("shell commands and staged scripts still report the shell pattern",()=>{
  const command="jq '.disableAllHooks=true' settings.json > next.json";
  assert.equal(run("Bash",{command})[0].rule_id,"RULE_SELF_PROTECTION_BASH");
  const found=run("Write",{file_path:"/home/case/setup.sh",content:command});
  assert.deepEqual(found.map(f=>[f.rule_id,f.severity]),[["RULE_SELF_PROTECTION_BASH","MEDIUM"]]);
});
test("settings exclusion is per pattern and per file, preserving other staged threats",()=>{
  const found=run("Write",{file_path:"/home/case/.claude/settings.json",content:'{"disableAllHooks":true,"command":"omnodex uninstall"}'});
  assert.equal(found.length,2);
  assert.match(found.find(f=>f.rule_id==="RULE_SELF_PROTECTION_BASH").description,/omnodex-uninstall/);
  assert.doesNotMatch(found.find(f=>f.rule_id==="RULE_SELF_PROTECTION_BASH").description,/hooks-disabled/);
  const multi=run("apply_patch",{input:'*** Begin Patch\n*** Add File: /home/case/.claude/settings.json\n+{"disableAllHooks":true}\n*** Add File: /home/case/setup.sh\n+jq .disableAllHooks=true settings.json\n*** End Patch'});
  assert.equal(multi.length,2);
  assert.match(multi.find(f=>f.rule_id==="RULE_SELF_PROTECTION_BASH").description,/setup\.sh/);
});
