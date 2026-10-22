import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RuleEngine, COMMUNITY_RULES, normalizeAction } from '../dist/index.js';
import { extractStagedContent, evaluatePathMatch } from '../dist/conditions/index.js';

const event = (tool_name, parameters) => ({ schema_version: 1, event_id: 'evt-file', session_id: 'sess-file', occurred_at: '2026-10-21T12:00:00.000Z', recorded_at: '2026-10-21T12:00:00.000Z', interceptor: 'mock', event_type: 'tool.invoked', tool_call_id: 'tc-file', tool_name, mcp_server: 'builtin', parameters });
const run = (e, id) => new RuleEngine(COMMUNITY_RULES.filter(r => r.rule_id === id)).evaluate(e);
const hook = '"command": "node antigravity-hook-launcher.js"';
const config = '/home/case/.codex/config.toml';
const sandbox = 'sandbox_mode = "danger-full-access"';

for (const prefix of ['', 'mcp__filesystem__']) {
  test(`${prefix}CLI file fields retain targets and only stage replacement text`, () => {
    const e = event(prefix + 'edit_file', { Path: '/tmp/deploy.sh', Target: 'omnodex uninstall', Replacement: 'echo ready' });
    const original = JSON.stringify(e);
    const a = normalizeAction(e);
    assert.deepEqual(a.paths, ['/tmp/deploy.sh']);
    assert.deepEqual(a.writes, a.paths);
    assert.equal(a.command, null);
    assert.deepEqual(extractStagedContent(e), [{ path: '/tmp/deploy.sh', text: 'echo ready' }]);
    assert.deepEqual(run(e, 'RULE_SELF_PROTECTION_BASH'), []);
    assert.equal(JSON.stringify(e), original);
    const read = normalizeAction(event(prefix + 'read_file', { Path: '/tmp/deploy.sh' }));
    assert.deepEqual(read.paths, ['/tmp/deploy.sh']);
    assert.deepEqual(read.writes, []);
  });

  test(`${prefix}captured CLI edit/write schemas fire the four missed findings`, () => {
    for (const [tool, params, id] of [
      ['edit_file', { Path: '/tmp/hooks.json', Target: `{${hook}}`, Replacement: '{}' }, 'RULE_SELF_PROTECTION_HOOK_REMOVED'],
      ['write_file', { Path: '/tmp/hooks.json', Content: `{"enabled":false,${hook}}`, Overwrite: true }, 'RULE_SELF_PROTECTION_HOOKS_DISABLED'],
      ['edit_file', { Path: '/tmp/mcp_config.json', Target: '"omnodex": {"command":"node"}', Replacement: '' }, 'RULE_SELF_PROTECTION_HOOK_REMOVED'],
      ['write_file', { Path: '/home/case/.gemini/config/settings.json', Content: '{"sandbox_mode":"none"}', Overwrite: true }, 'RULE_SANDBOX_DISABLE_SETTINGS_WRITE'],
    ]) assert.equal(run(event(prefix + tool, params), id).length, 1, id);
    const benign = event(prefix + 'edit_file', { Path: '/tmp/hooks.json', Target: `{"timeout":10,${hook}}`, Replacement: `{"timeout":11,${hook}}` });
    assert.deepEqual(run(benign, 'RULE_SELF_PROTECTION_HOOK_REMOVED'), []);
    assert.deepEqual(run(benign, 'RULE_SELF_PROTECTION_HOOKS_DISABLED'), []);
    for (const name of [prefix + 'write_file', 'describe_change']) {
      const e = event(name, { Path: '/tmp/README.md', Content: 'omnodex uninstall', Target: hook, Replacement: '{}' });
      assert.deepEqual(run(e, 'RULE_SELF_PROTECTION_BASH'), []);
      assert.deepEqual(run(e, 'RULE_SELF_PROTECTION_HOOK_REMOVED'), []);
    }
  });

  test(`${prefix}patch paths include add/update/delete/move but never become reads or commands`, () => {
    const patch = '*** Begin Patch\n*** Add File: /tmp/new.txt\n+ready\n*** Update File: /tmp/old.txt\n*** Move to: /tmp/moved.txt\n-old\n+new\n*** Delete File: /tmp/gone.txt\n*** End Patch';
    const e = event(prefix + 'apply_patch', { command: patch });
    const a = normalizeAction(e);
    assert.deepEqual(a.paths, ['/tmp/new.txt', '/tmp/old.txt', '/tmp/moved.txt', '/tmp/gone.txt']);
    assert.deepEqual(a.writes, a.paths);
    assert.equal(a.command, null);
    assert.deepEqual(evaluatePathMatch({ access: 'read', patterns: [{ regex: '.*', label: 'any' }] }, e), []);
  });

  test(`${prefix}sandbox patch content is matched to its own resulting file`, () => {
    const id = 'RULE_SANDBOX_DISABLE_SETTINGS_WRITE';
    const patchEvent = body => event(prefix + 'apply_patch', { command: `*** Begin Patch\n${body}\n*** End Patch` });
    for (const body of [
      `*** Add File: ${config}\n+${sandbox}`,
      `*** Update File: ${config}\n-sandbox_mode = "workspace-write"\n+${sandbox}`,
      `*** Update File: /tmp/config.txt\n*** Move to: ${config}\n-old\n+${sandbox}`,
    ]) assert.equal(run(patchEvent(body), id).length, 1, body);
    for (const body of [
      `*** Add File: ${config}\n+sandbox_mode = "workspace-write"`,
      `*** Update File: ${config}\n-${sandbox}\n+sandbox_mode = "workspace-write"`,
      `*** Delete File: ${config}\n-${sandbox}`,
      `*** Add File: /tmp/README.md\n+${sandbox}`,
      `*** Add File: ${config}\n+theme = "dark"\n*** Add File: /tmp/README.md\n+${sandbox}`,
      `*** Update File: ${config}\n*** Move to: /tmp/README.md\n-old\n+${sandbox}`,
    ]) assert.deepEqual(run(patchEvent(body), id), [], body);
    const multi = run(patchEvent(`*** Add File: ${config}\n+${sandbox}\n*** Add File: /home/case/.claude/settings.json\n+{"sandbox":false}`), id);
    assert.equal(multi.length, 2);
    assert.ok(multi[0].description.includes(config));
    assert.ok(multi[1].description.includes('.claude/settings.json'));
    assert.deepEqual(run(event(prefix + 'read_file', { Path: config, Content: sandbox }), id), []);
    assert.deepEqual(run(event('describe_change', { Path: config, Content: sandbox }), id), []);
  });
}
