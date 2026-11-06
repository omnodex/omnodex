// Copilot, Cursor and OpenCode are known to capture, scope and the
// self-protection rules: their hook and plugin files are protected like the
// existing agents' files, and their events are evaluated as hook events.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RuleEngine, COMMUNITY_RULES, CAPTURE_HOSTS } from '../dist/index.js';
import { evaluatePathMatch } from '../dist/conditions/index.js';

const event = (tool_name, parameters) => ({ schema_version: 1, event_id: 'evt-p', session_id: 'sess-p', occurred_at: '2026-11-06T12:00:00.000Z', recorded_at: '2026-11-06T12:00:00.000Z', interceptor: 'mock', event_type: 'tool.invoked', tool_call_id: 'tc-p', tool_name, mcp_server: 'builtin', parameters });
const run = (e, id) => new RuleEngine(COMMUNITY_RULES.filter(r => r.rule_id === id)).evaluate(e);
const bash = (command) => event('Bash', { command });

test('capture evaluates the new interceptors as hooks', () => {
  for (const kind of ['copilot-hook', 'cursor-hook', 'opencode-plugin']) assert.equal(CAPTURE_HOSTS[kind], 'hook', kind);
  assert.equal(CAPTURE_HOSTS['mcp-proxy'], 'proxy');
});

test('shell commands that wipe the new platforms\' Omnodex files fire the self-protection rule', () => {
  for (const command of [
    'rm ~/.copilot/hooks/omnodex.json',
    'rm "$COPILOT_HOME/hooks/omnodex.json"',
    'rm .github/hooks/omnodex.json',
    'echo {} > ~/.cursor/hooks.json',
    'rm .cursor/hooks.json',
    'rm ~/.config/opencode/plugins/omnodex.js',
    'mv /tmp/x.js ~/.config/opencode/plugins/omnodex.js',
    'opencode mcp remove omnodex',
    'copilot plugin remove omnodex',
  ]) assert.equal(run(bash(command), 'RULE_SELF_PROTECTION_BASH').length, 1, command);
});

test('ordinary commands near those folders do not fire', () => {
  for (const command of [
    'ls ~/.copilot/hooks',
    'cat ~/.cursor/hooks.json',
    'rm .github/hooks/lint.json',
    'rm ~/.config/opencode/plugins/other.js',
    'opencode run "explain this repo"',
  ]) assert.deepEqual(run(bash(command), 'RULE_SELF_PROTECTION_BASH'), [], command);
});

test('removing the Omnodex entry from a new platform\'s hooks or plugin file is reported', () => {
  const removed = (file, target) => event('Edit', { file_path: file, old_string: target, new_string: '' });
  assert.equal(run(removed('/home/case/.copilot/hooks/omnodex.json', '"command": "node copilot-hook-launcher.js --user-scope"'), 'RULE_SELF_PROTECTION_HOOK_REMOVED').length, 1);
  assert.equal(run(removed('/home/case/.cursor/hooks.json', '"command": "node cursor-hook-launcher.js"'), 'RULE_SELF_PROTECTION_HOOK_REMOVED').length, 1);
  assert.equal(run(removed('/home/case/.config/opencode/plugins/omnodex.js', 'const PLUGIN = "omnodex-managed";'), 'RULE_SELF_PROTECTION_HOOK_REMOVED').length, 1);
  // An unrelated edit to the same file keeps the entry and is quiet.
  assert.deepEqual(run(event('Edit', { file_path: '/home/case/.cursor/hooks.json', old_string: '"timeout": 10, "command": "node cursor-hook-launcher.js"', new_string: '"timeout": 20, "command": "node cursor-hook-launcher.js"' }), 'RULE_SELF_PROTECTION_HOOK_REMOVED'), []);
});

test('rewriting a new platform\'s hooks file without the Omnodex entry is reported', () => {
  const write = (file, content) => event('Write', { file_path: file, content });
  for (const file of ['/home/case/.copilot/hooks/omnodex.json', '/home/case/repo/.github/hooks/omnodex.json', '/home/case/.cursor/hooks.json']) {
    assert.equal(run(write(file, '{"hooks":{"preToolUse":[]}}'), 'RULE_SELF_PROTECTION_HOOK_FILE_REWRITE').length, 1, file);
    assert.deepEqual(run(write(file, '{"hooks":{"preToolUse":[{"command":"node cursor-hook-launcher.js"}]}}'), 'RULE_SELF_PROTECTION_HOOK_FILE_REWRITE'), [], `${file} with the entry`);
  }
});

test('the rules that changed are versioned', () => {
  const version = (id) => COMMUNITY_RULES.find(r => r.rule_id === id).version;
  assert.equal(version('RULE_SELF_PROTECTION_BASH'), '1.4.0');
  assert.equal(version('RULE_SELF_PROTECTION_HOOK_REMOVED'), '1.1.0');
  assert.equal(version('RULE_SELF_PROTECTION_HOOK_FILE_REWRITE'), '1.1.0');
  assert.ok(typeof evaluatePathMatch === 'function');
});
