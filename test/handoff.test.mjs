// Offline tests for session handoff: fixture transcripts in the shapes Claude Code and Cursor
// actually write, no model calls. Run with: node --test test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tether-handoff-'));
// handoff.mjs reads its roots from HOME and TETHER_HOME at import, so point both at the sandbox first
process.env.HOME = tmp;
process.env.TETHER_HOME = path.join(tmp, '.tether');
const H = await import('../daemon/handoff.mjs');

const proj = path.join(tmp, 'proj');
fs.mkdirSync(proj);
execFileSync('git', ['init', '-q'], { cwd: proj });
execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'init'], { cwd: proj });
fs.writeFileSync(path.join(proj, 'calc.py'), 'def add(a, b):\n    return a + b\n');

const line = (o) => JSON.stringify(o);
const ts = (m) => `2026-09-30T10:${String(m).padStart(2, '0')}:00.000Z`;
const claudeDir = path.join(tmp, '.claude', 'projects', '-sandbox-proj');
fs.mkdirSync(claudeDir, { recursive: true });
const CLAUDE_SID = '11111111-2222-4333-8444-555555555555';
const claudeFile = path.join(claudeDir, `${CLAUDE_SID}.jsonl`);
fs.writeFileSync(claudeFile, [
  line({ type: 'user', cwd: proj, gitBranch: 'main', timestamp: ts(0), message: { role: 'user', content: 'Build calc.py: add now, multiply later.' } }),
  line({ type: 'assistant', timestamp: ts(1), message: { model: 'claude-opus-5-5', role: 'assistant', content: [
    { type: 'text', text: '## Plan\nI will write add first.' },
    { type: 'tool_use', id: 't1', name: 'Write', input: { file_path: path.join(proj, 'calc.py'), content: 'def add...' } },
    { type: 'tool_use', id: 't2', name: 'Bash', input: { command: 'python3 -c "import calc"' } },
    { type: 'tool_use', id: 't3', name: 'TodoWrite', input: { todos: [{ content: 'add()', status: 'completed' }, { content: 'multiply()', status: 'pending' }] } },
  ] } }),
  line({ type: 'user', timestamp: ts(2), message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't2', content: 'ok' }] } }),
  line({ type: 'user', isCompactSummary: true, timestamp: ts(3), message: { role: 'user', content: 'This session is being continued from a previous conversation.\nSummary: add() is done; multiply() is next.' } }),
  line({ type: 'user', timestamp: ts(4), message: { role: 'user', content: '<command-name>/model</command-name><command-args>opus</command-args>' } }),
  line({ type: 'user', timestamp: ts(5), message: { role: 'user', content: 'now multiply please <system-reminder>ignore me</system-reminder>' } }),
  line({ type: 'assistant', timestamp: ts(6), message: { model: '<synthetic>', role: 'assistant', content: [{ type: 'text', text: "You've hit your session limit · resets 1:10pm (Asia/Calcutta)" }] } }),
].join('\n') + '\n');

const cursorDir = path.join(tmp, '.cursor', 'projects', 'sandbox', 'agent-transcripts', 'c0ffee00-0000-4000-8000-000000000000');
fs.mkdirSync(cursorDir, { recursive: true });
const cursorFile = path.join(cursorDir, 'c0ffee00-0000-4000-8000-000000000000.jsonl');
fs.writeFileSync(cursorFile, [
  line({ role: 'user', message: { content: [{ type: 'text', text: '<user_query>\nfix the login bug\n</user_query>' }] } }),
  line({ role: 'assistant', message: { content: [
    { type: 'text', text: 'Looking at auth.ts.' },
    { type: 'tool_use', id: 'c1', name: 'StrReplace', input: { path: 'src/auth.ts', old_string: 'a', new_string: 'b' } },
    { type: 'tool_use', id: 'c2', name: 'ApplyPatch', input: '*** Begin Patch\n*** Update File: src/session.ts\n@@\n-x\n+y\n*** End Patch' },
    { type: 'tool_use', id: 'c3', name: 'Shell', input: { command: 'npm test' } },
  ] } }),
].join('\n') + '\n');

test('reads a Claude Code transcript: requests, tools, compaction summary, limit', () => {
  const tr = H.readTranscript(claudeFile);
  const asks = tr.messages.filter((m) => m.role === 'user').map((m) => m.text);
  assert.deepEqual(asks, ['Build calc.py: add now, multiply later.', '(ran /model opus)', 'now multiply please']);
  assert.match(tr.compactSummary, /multiply\(\) is next/);
  assert.equal(tr.limitHit?.text, "You've hit your session limit · resets 1:10pm (Asia/Calcutta)");
  assert.equal(tr.tools.find((t) => t.id === 't2').result, 'ok');
  assert.equal(tr.todos.length, 2);
});

test('a real model turn after the limit clears it', () => {
  const f = path.join(tmp, 'lifted.jsonl');
  fs.writeFileSync(f, fs.readFileSync(claudeFile, 'utf8')
    + line({ type: 'assistant', timestamp: ts(9), message: { model: 'claude-opus-5-5', role: 'assistant', content: [{ type: 'text', text: 'back' }] } }) + '\n');
  assert.equal(H.readTranscript(f).limitHit, null);
});

test('builds a handoff with every section a new agent needs', () => {
  const h = H.buildHandoff({ file: claudeFile, target: 'cursor', note: 'tests first' });
  const md = h.markdown;
  for (const s of ['## Read this first', '## Note from the person', '## Why this was handed off', '## Original request',
    "## Earlier context (Claude Code's own summary)", '## Everything the person asked (3)', '## Plan and to-dos (latest)',
    '## Files the agent changed (1)', '## Commands it ran', '## Repository state now', '## Where it stopped']) {
    assert.ok(md.includes(s), `missing section: ${s}`);
  }
  assert.ok(md.includes('`calc.py`'), 'changed file listed relative to the project');
  assert.ok(md.includes('?? calc.py'), 'uncommitted state included');
  assert.ok(!md.includes('ignore me'), 'system reminders stripped');
  assert.ok(!/^## Plan$/m.test(md), 'headings inside quoted chat are demoted');
  assert.equal(h.summary.agent, 'claude');
  assert.equal(h.summary.cwd, proj);
  assert.match(h.id, /^h-\d{8}-\d{6}-[0-9a-f]{4}$/);
});

test('reads Cursor transcripts, including raw ApplyPatch input', () => {
  const h = H.buildHandoff({ file: cursorFile, cwd: proj });
  assert.equal(h.summary.agent, 'cursor');
  assert.ok(h.markdown.includes('fix the login bug'));
  assert.ok(!h.markdown.includes('<user_query>'));
  assert.ok(h.markdown.includes('`src/auth.ts`') && h.markdown.includes('`src/session.ts`'));
  assert.ok(h.markdown.includes('`npm test`'));
});

test('writes into the project, git-ignored, and the prompt references it', () => {
  const h = H.buildHandoff({ file: claudeFile, target: 'claude' });
  const w = H.writeHandoff(h, proj);
  assert.ok(fs.existsSync(w.path) && fs.existsSync(w.transcriptPath));
  const status = execFileSync('git', ['status', '--porcelain'], { cwd: proj }).toString();
  assert.ok(!status.includes('.tether'), 'handoff files must not show up in git status');
  const prompt = H.handoffPrompt({ relPath: w.relPath, source: 'claude', note: 'hi' });
  assert.equal(prompt.match(H.HANDOFF_REF_RE)?.[1], h.id);
  assert.ok(!prompt.includes('\n'), 'one line, so it survives every CLI and tmux');
});

test('lineage links a handoff to the session it started', () => {
  H.recordHandoff({ id: 'h-20260930-100000-abcd', from: { sessionId: CLAUDE_SID, agent: 'claude' }, to: { agent: 'cursor' } });
  const rec = H.linkHandoff('h-20260930-100000-abcd', 'new-session');
  assert.equal(rec.from.sessionId, CLAUDE_SID);
  assert.equal(H.readLineage().at(-1).to.sessionId, 'new-session');
  assert.equal(H.linkHandoff('h-missing', 'x'), null);
});

test('lists and resolves sessions across agents', () => {
  const all = H.listSessions({ limit: 10 });
  assert.deepEqual(new Set(all.map((s) => s.agent)), new Set(['claude', 'cursor']));
  assert.equal(H.resolveSession('11111111').sessionId, CLAUDE_SID);
  assert.equal(H.resolveSession('latest', { cwd: proj }).sessionId, CLAUDE_SID);
  assert.throws(() => H.resolveSession('99999999'), /no session matches/);
});

test('the MCP server answers list_sessions and get_session_context over stdio', async () => {
  const p = spawn(process.execPath, [path.join(HERE, '..', 'daemon', 'context-mcp.mjs')], { env: process.env, stdio: ['pipe', 'pipe', 'inherit'] });
  let buf = ''; const waiting = new Map();
  p.stdout.on('data', (c) => { buf += c; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiting.get(m.id)?.(m); } });
  let n = 0;
  const rpc = (method, params) => new Promise((r) => { const id = ++n; waiting.set(id, r); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); });
  try {
    assert.equal((await rpc('initialize', {})).result.serverInfo.name, 'tether-sessions');
    assert.deepEqual((await rpc('tools/list', {})).result.tools.map((t) => t.name), ['list_sessions', 'get_session_context']);
    const ls = await rpc('tools/call', { name: 'list_sessions', arguments: {} });
    assert.ok(ls.result.content[0].text.includes(CLAUDE_SID));
    const ctx = await rpc('tools/call', { name: 'get_session_context', arguments: { session_id: 'c0ffee00' } });
    assert.ok(ctx.result.content[0].text.includes('fix the login bug'));
    assert.ok(ctx.result.content[0].text.includes(cursorFile), 'points at the original transcript when nothing is written');
    const bad = await rpc('tools/call', { name: 'get_session_context', arguments: { session_id: 'deadbeef' } });
    assert.equal(bad.result.isError, true);
  } finally { p.kill(); }
});
