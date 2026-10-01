// Session handoff: turn one agent's chat into a portable context file another agent can pick
// up from. Each tool keeps its sessions in its own private format (Claude Code and Cursor
// write JSONL, Codex SQLite, Devin lives in the cloud), and none of them can resume the
// others' — so instead of forging native session files we write down what a person taking
// over would need, in plain markdown every coding agent already knows how to read.
//
// Deliberately deterministic: no model is asked to summarize. The usual reason to hand off is
// that the source agent just hit its limit, so it cannot be the one writing the summary. What
// Claude Code already summarized itself (its compaction summary) is reused as-is.
//
// Dependency-free on purpose: context-mcp.mjs runs this from ~/.tether/bin, outside the package.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const HOME = os.homedir();
export const TETHER_DIR = process.env.TETHER_HOME || path.join(HOME, '.tether');
const LINEAGE_PATH = path.join(TETHER_DIR, 'handoffs.json');

export const AGENT_NAMES = {
  claude: 'Claude Code', cursor: 'Cursor', codex: 'Codex', gemini: 'Gemini CLI', opencode: 'OpenCode', aider: 'Aider',
};
// Agents a handoff can start. Each one takes an initial prompt both interactively and headless.
export const HANDOFF_TARGETS = ['claude', 'cursor', 'codex'];

// A handoff file is referenced by path in the first message of the session it starts; that
// reference is how the new session is linked back to the one it continues.
export const HANDOFF_DIR = path.join('.tether', 'handoff');
export const HANDOFF_REF_RE = /\.tether\/handoff\/(h-\d{8}-\d{6}-[0-9a-f]{4})\.md/;

// What Claude Code writes when a plan limit stops a turn (a synthetic assistant message), e.g.
// "You've hit your session limit · resets 1:10pm (Asia/Calcutta)". Checked against real transcripts.
export const LIMIT_RE = /you['’]ve hit your (?:\w+ )?limit|usage limit reached|out of extra usage/i;

const READ_CAP = 24 * 1024 * 1024; // bytes read from the end of a very long transcript
const HEAD_CAP = 512 * 1024;       // bytes always read from the start, for the original goal
const ANSI_RE = new RegExp('\\x1b\\[[0-9;?]*[A-Za-z]', 'g');

const clip = (s, n) => {
  s = String(s ?? '');
  return s.length > n ? `${s.slice(0, n)}\n… [${s.length - n} more characters]` : s;
};
const oneLine = (s, n = 160) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};
// Quoted chat text keeps its words but not its headings, so it cannot break this file's outline.
const demote = (s) => String(s ?? '').replace(/^#{1,6}[ \t]+(.+)$/gm, '**$1**');
// A fence that cannot be closed early by backticks inside the content.
const fence = (s, lang = '') => {
  const longest = Math.max(2, ...(String(s).match(/`+/g) ?? []).map((m) => m.length));
  const f = '`'.repeat(longest + 1);
  return `${f}${lang}\n${s}\n${f}`;
};

// ---------------------------------------------------------------- locating sessions

export const agentForPath = (file) => (String(file).includes(`${path.sep}.cursor${path.sep}`) ? 'cursor' : 'claude');

export function defaultRoots() {
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(path.join(TETHER_DIR, 'config.json'), 'utf8')); } catch {}
  const roots = (cfg.roots ?? [path.join(HOME, '.claude', 'projects')])
    .map((r) => (typeof r === 'string' ? { path: r, agent: 'claude' } : { path: r.path, agent: r.agent || 'claude' }));
  // Offer both tailable agents even when this machine was connected before one was installed.
  for (const [p, agent] of [[path.join(HOME, '.claude', 'projects'), 'claude'], [path.join(HOME, '.cursor', 'projects'), 'cursor']]) {
    if (!roots.some((r) => r.path === p) && fs.existsSync(p)) roots.push({ path: p, agent });
  }
  return roots.filter((r) => fs.existsSync(r.path));
}

// Cursor names project folders by the workspace path with '/' turned into '-'. Folder names can
// contain '-' themselves, so resolve greedily against the filesystem instead of splitting.
export function decodeProjectPath(enc) {
  const parts = String(enc).replace(/^-/, '').split('-');
  let cur = '', i = 0;
  while (i < parts.length) {
    let piece = parts[i], j = i, next = `${cur}/${piece}`;
    while (!fs.existsSync(next) && j + 1 < parts.length) { j++; piece += `-${parts[j]}`; next = `${cur}/${piece}`; }
    if (!fs.existsSync(next)) return null;
    cur = next; i = j + 1;
  }
  return cur || null;
}
export function cwdFromCursorPath(file) {
  const m = String(file).match(/\/\.cursor\/projects\/([^/]+)\//);
  return m ? decodeProjectPath(m[1]) : null;
}

function walkJsonl(root, out) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'subagents') stack.push(p); } // sub-agent chats are not sessions
      else if (e.name.endsWith('.jsonl')) out.push(p);
    }
  }
  return out;
}

// Read only the first few lines: enough for the working directory and an opening request.
function peek(file) {
  const out = { cwd: null, title: null, firstUser: null };
  let head = '';
  try {
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(64 * 1024);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    head = buf.subarray(0, n).toString('utf8');
  } catch { return out; }
  for (const line of head.split('\n').slice(0, 40)) {
    let o; try { o = JSON.parse(line); } catch { continue; }
    if (!out.cwd && o.cwd) out.cwd = o.cwd;
    if (!out.title && (o.type === 'ai-title' || o.type === 'custom-title' || o.type === 'summary')) out.title = o.aiTitle ?? o.customTitle ?? o.title ?? o.summary ?? null;
    if (!out.firstUser && (o.type ?? o.role) === 'user' && !o.isMeta && !o.isCompactSummary) {
      const t = cleanUserText(textOf(o.message?.content));
      if (t) out.firstUser = t;
    }
  }
  return out;
}

/**
 * Sessions on this machine, newest first.
 * @param {{cwd?: string, agent?: string, limit?: number, stateMeta?: object}} q
 */
export function listSessions({ cwd = null, agent = null, limit = 20, stateMeta = null } = {}) {
  const meta = stateMeta ?? readStateMeta();
  const files = [];
  for (const r of defaultRoots()) walkJsonl(r.path, files);
  const rows = [];
  for (const f of files) {
    let st; try { st = fs.statSync(f); } catch { continue; }
    rows.push({ file: f, mtime: st.mtimeMs, size: st.size });
  }
  rows.sort((a, b) => b.mtime - a.mtime);
  const out = [];
  for (const r of rows) {
    const sessionId = path.basename(r.file, '.jsonl');
    const a = agentForPath(r.file);
    if (agent && a !== agent) continue;
    const saved = meta[sessionId] ?? {};
    let sCwd = saved.projectCwd ?? saved.cwd ?? null, title = saved.title ?? null;
    if (!sCwd || !title) {
      const p = peek(r.file);
      sCwd = sCwd ?? p.cwd ?? (a === 'cursor' ? cwdFromCursorPath(r.file) : null);
      title = title ?? p.title ?? (p.firstUser ? oneLine(p.firstUser, 70) : null);
    }
    if (cwd && sCwd !== cwd) continue;
    out.push({ sessionId, agent: a, title, cwd: sCwd, file: r.file, updatedAt: r.mtime, sizeKb: Math.round(r.size / 1024) });
    if (out.length >= limit) break;
  }
  return out;
}

function readStateMeta() {
  try { return JSON.parse(fs.readFileSync(path.join(TETHER_DIR, 'state.json'), 'utf8')).meta ?? {}; } catch { return {}; }
}

/** A full session id, a unique prefix of one, or 'latest' (optionally within a folder). */
export function resolveSession(ref, { cwd = null } = {}) {
  if (!ref || ref === 'latest') {
    const [s] = listSessions({ cwd, limit: 1 });
    if (!s) throw new Error(cwd ? `no sessions found for ${cwd}` : 'no sessions found on this machine');
    return s;
  }
  const want = String(ref).trim();
  if (!/^[A-Za-z0-9-]{4,}$/.test(want)) throw new Error(`not a session id: ${want}`);
  const hits = listSessions({ limit: 100000 }).filter((s) => s.sessionId === want || s.sessionId.startsWith(want));
  const exact = hits.find((s) => s.sessionId === want);
  if (exact) return exact;
  if (!hits.length) throw new Error(`no session matches "${want}"`);
  if (hits.length > 1) throw new Error(`"${want}" matches ${hits.length} sessions — use more characters`);
  return hits[0];
}

// ---------------------------------------------------------------- reading a transcript

function textOf(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((b) => (typeof b === 'string' ? b : b?.type === 'text' ? (b.text ?? '') : '')).join('\n');
  return '';
}

// What people typed, without the scaffolding agents wrap around it.
function cleanUserText(t) {
  t = String(t ?? '');
  if (/^\s*<local-command-(caveat|stdout|stderr)>/.test(t)) return '';
  const cmd = t.match(/<command-name>([^<]*)<\/command-name>/);
  if (cmd) {
    const args = (t.match(/<command-args>([^<]*)<\/command-args>/) ?? [])[1] ?? '';
    return `(ran ${cmd[1].trim()}${args.trim() ? ` ${args.trim()}` : ''})`;
  }
  return t
    .replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '')
    .replace(/<timestamp>[\s\S]*?<\/timestamp>/g, '')
    .replace(/<\/?user_query>/g, '')
    .replace(ANSI_RE, '')
    .trim();
}

// Paths a tool call wrote to. Covers Claude Code (Edit/Write/MultiEdit/NotebookEdit),
// Cursor (StrReplace/Write/Delete/EditNotebook/ApplyPatch) and Codex-style apply_patch.
function editedPaths(name, input) {
  if (typeof input === 'string' || (input && typeof input === 'object' && '0' in input && !('path' in input))) {
    // A raw patch, sometimes stored as a character-indexed object.
    const patch = typeof input === 'string' ? input : Object.keys(input).sort((a, b) => a - b).map((k) => input[k]).join('');
    return [...patch.matchAll(/^\*\*\* (?:Update|Add|Delete) File: (.+)$/gm)].map((m) => m[1].trim());
  }
  if (!input || typeof input !== 'object') return [];
  if (!/edit|write|replace|patch|delete|notebook|create/i.test(name)) return [];
  if (/todo|plan/i.test(name)) return [];
  const p = input.file_path ?? input.notebook_path ?? input.path ?? input.target_file ?? null;
  if (typeof p === 'string') return [p];
  if (typeof input.patch === 'string' || typeof input.input === 'string') return editedPaths(name, input.patch ?? input.input);
  return [];
}
const isShell = (name) => /^(bash|shell|run_terminal_cmd|shell_command|exec_command|local_shell)$/i.test(name);
const shellCmd = (input) => {
  const c = input?.command ?? input?.cmd ?? null;
  return Array.isArray(c) ? c.join(' ') : c;
};

/**
 * Parse a Claude Code or Cursor transcript into what a handoff needs.
 * Reads the whole file up to READ_CAP (from the end), plus its head for the original goal.
 */
export function readTranscript(file) {
  const st = fs.statSync(file);
  let text, skipped = 0;
  if (st.size <= READ_CAP + HEAD_CAP) {
    text = fs.readFileSync(file, 'utf8');
  } else {
    const fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(HEAD_CAP);
    fs.readSync(fd, head, 0, HEAD_CAP, 0);
    const tail = Buffer.alloc(READ_CAP);
    fs.readSync(fd, tail, 0, READ_CAP, st.size - READ_CAP);
    fs.closeSync(fd);
    const h = head.toString('utf8'), t = tail.toString('utf8');
    skipped = st.size - READ_CAP - HEAD_CAP;
    // whole lines only on both sides of the gap
    text = `${h.slice(0, h.lastIndexOf('\n') + 1)}${t.slice(t.indexOf('\n') + 1)}`;
  }

  const r = {
    messages: [],      // {role:'user'|'assistant', text, ts}
    tools: [],         // {id, name, input, ts, result?, isError?}
    compactSummary: null, compactAt: null,
    limitHit: null,    // {text, ts} — the latest plan-limit message, if the session ended on one
    meta: { cwd: null, gitBranch: null, model: null },
    title: null, skippedBytes: skipped, sizeKb: Math.round(st.size / 1024),
    todos: null, plan: null,
  };
  const byId = new Map();
  for (const raw of text.split('\n')) {
    if (!raw.trim()) continue;
    let o; try { o = JSON.parse(raw); } catch { continue; }
    if (o.cwd) r.meta.cwd = o.cwd;
    if (o.gitBranch) r.meta.gitBranch = o.gitBranch;
    const kind = o.type ?? o.role ?? null;
    if (kind === 'ai-title' || kind === 'custom-title' || kind === 'summary') { r.title = o.aiTitle ?? o.customTitle ?? o.title ?? o.summary ?? r.title; continue; }
    if (o.isSidechain) continue;
    const ts = o.timestamp ?? null;
    const c = o.message?.content;
    if (kind === 'user') {
      if (o.isCompactSummary) { r.compactSummary = textOf(c); r.compactAt = ts; continue; }
      if (o.isMeta) continue;
      if (typeof c === 'string') { const t = cleanUserText(c); if (t) r.messages.push({ role: 'user', text: t, ts }); continue; }
      if (!Array.isArray(c)) continue;
      for (const b of c) {
        if (b?.type === 'text') { const t = cleanUserText(b.text); if (t) r.messages.push({ role: 'user', text: t, ts }); }
        else if (b?.type === 'tool_result') {
          const tool = byId.get(b.tool_use_id);
          if (tool) { tool.result = textOf(b.content).replace(ANSI_RE, ''); tool.isError = !!b.is_error; }
        }
      }
    } else if (kind === 'assistant') {
      const model = o.message?.model ?? null;
      const blocks = Array.isArray(c) ? c : typeof c === 'string' ? [{ type: 'text', text: c }] : [];
      if (model === '<synthetic>') {
        const t = textOf(blocks);
        if (LIMIT_RE.test(t)) r.limitHit = { text: oneLine(t, 200), ts };
        continue; // an API notice, not something the agent said
      }
      if (model) { r.meta.model = model; r.limitHit = null; } // a real turn after the limit: it lifted
      for (const b of blocks) {
        if (b?.type === 'text' && b.text?.trim()) r.messages.push({ role: 'assistant', text: b.text.trim(), ts });
        else if (b?.type === 'tool_use') {
          const tool = { id: b.id ?? null, name: b.name ?? '?', input: b.input ?? {}, ts };
          r.tools.push(tool);
          if (tool.id) byId.set(tool.id, tool);
          r.messages.push({ role: 'tool', tool, ts });
          if (/^todowrite$/i.test(tool.name) && Array.isArray(tool.input?.todos)) r.todos = tool.input.todos;
          if (/^(exitplanmode|createplan)$/i.test(tool.name) && typeof tool.input?.plan === 'string') r.plan = tool.input.plan;
        }
      }
    }
  }
  return r;
}

// ---------------------------------------------------------------- building the handoff

function gitState(cwd) {
  const run = (args) => execFileSync('git', args, { cwd, timeout: 8000, maxBuffer: 16_000_000, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
  try { run(['rev-parse', '--is-inside-work-tree']); } catch { return null; }
  const g = { branch: null, head: null, status: '', stat: '', diff: '', untracked: [] };
  try { g.branch = run(['rev-parse', '--abbrev-ref', 'HEAD']).trim(); } catch {}
  try { g.head = run(['log', '-1', '--format=%h %s']).trim(); } catch {}
  try { g.status = run(['status', '--porcelain']).trimEnd(); } catch {}
  try { g.stat = run(['diff', 'HEAD', '--stat']).trimEnd(); } catch { try { g.stat = run(['diff', '--stat']).trimEnd(); } catch {} }
  try { g.diff = run(['diff', 'HEAD']); } catch { try { g.diff = run(['diff']); } catch {} }
  g.untracked = g.status.split('\n').filter((l) => l.startsWith('?? ')).map((l) => l.slice(3));
  return g;
}

const rel = (cwd, p) => {
  if (!cwd || !p || !path.isAbsolute(p)) return p;
  const r = path.relative(cwd, p);
  return r && !r.startsWith('..') ? r : p;
};
const when = (ts) => (ts ? new Date(ts).toISOString().replace('T', ' ').slice(0, 16) : '');

function toolLine(tool, cwd) {
  const n = tool.name;
  const i = tool.input ?? {};
  const edits = editedPaths(n, i);
  let what;
  if (isShell(n)) what = `\`${oneLine(shellCmd(i), 140)}\``;
  else if (edits.length) what = edits.map((p) => `\`${rel(cwd, p)}\``).join(', ');
  else if (typeof i === 'object' && i) {
    const v = i.file_path ?? i.path ?? i.pattern ?? i.glob_pattern ?? i.query ?? i.url ?? i.description ?? i.prompt ?? null;
    what = v != null ? `\`${oneLine(rel(cwd, String(v)), 120)}\`` : '';
  } else what = '';
  const res = tool.result != null ? ` → ${tool.isError ? '✗ ' : ''}${oneLine(tool.result, 140)}` : '';
  return `[${n}] ${what}${res}`;
}

/** Plain-text rendering of the whole conversation, for the agent to search when it needs detail. */
function renderFull(tr, cwd) {
  const out = [];
  if (tr.compactSummary) out.push(`=== Earlier context (summary Claude Code wrote when it compacted) ===\n${tr.compactSummary}\n`);
  for (const m of tr.messages) {
    if (m.role === 'tool') out.push(`  · ${toolLine(m.tool, cwd)}`);
    else out.push(`\n--- ${m.role === 'user' ? 'PERSON' : 'AGENT'}${m.ts ? ` · ${when(m.ts)}` : ''} ---\n${m.text}`);
  }
  return out.join('\n');
}

/**
 * Build the handoff for one session.
 * @returns {{id, markdown, transcript, summary}}
 */
export function buildHandoff({ file, agent = null, sessionId = null, cwd = null, title = null, target = null, note = null, now = new Date(), transcriptRef = null }) {
  agent = agent ?? agentForPath(file);
  sessionId = sessionId ?? path.basename(file, '.jsonl');
  const tr = readTranscript(file);
  cwd = cwd ?? tr.meta.cwd ?? (agent === 'cursor' ? cwdFromCursorPath(file) : null);
  const firstUser = tr.messages.find((m) => m.role === 'user');
  title = title ?? tr.title ?? (firstUser ? oneLine(firstUser.text, 70) : `session ${sessionId.slice(0, 8)}`);
  const stamp = now.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
  const id = `h-${stamp}-${crypto.randomBytes(2).toString('hex')}`;
  const srcName = AGENT_NAMES[agent] ?? agent;
  const tgtName = target ? (AGENT_NAMES[target] ?? target) : 'the next agent';
  const git = cwd && fs.existsSync(cwd) ? gitState(cwd) : null;
  // Where the full conversation can be searched: the file written next to this one, or — when
  // nothing is written to disk (an MCP answer) — the agent's own transcript.
  const relTranscript = transcriptRef ?? `${HANDOFF_DIR}/${id}.transcript.md`;

  const L = [];
  L.push(`# Handoff: ${title}`);
  L.push('');
  L.push(`Written by Tether on ${now.toISOString()} from a **${srcName}** session (\`${sessionId}\`)`
    + `${cwd ? ` in \`${cwd}\`` : ''}${git?.branch ? ` on branch \`${git.branch}\`` : ''}, for ${tgtName}.`);
  L.push('');
  L.push('## Read this first');
  L.push('');
  L.push(`You are taking over a coding task that another AI agent (${srcName}) was working on. The person wants to continue exactly where it stopped, with the same context.`);
  L.push('');
  L.push('- Read this whole file before acting. It has the goal, every request the person made, what was done, and the state of the repository.');
  L.push('- Uncommitted changes listed below are the previous agent\'s work in progress. Build on them; do not revert or redo them.');
  L.push(transcriptRef
    ? `- For any detail not covered here, search the original transcript (one JSON object per line): \`${transcriptRef}\`.`
    : `- For any detail not covered here, search the full conversation: \`${relTranscript}\`${tr.skippedBytes ? ' (the middle of a very long session was left out of it)' : ''}. The original transcript is \`${file}\`.`);
  L.push('- Check the working tree (`git status`, `git diff`) before your first change: it may have moved since this file was written.');
  L.push('- Start by saying in two or three lines what you understand the current task and the next step to be, then continue.');
  L.push('');
  if (note?.trim()) { L.push('## Note from the person'); L.push(''); L.push(note.trim()); L.push(''); }
  if (tr.limitHit) {
    L.push('## Why this was handed off');
    L.push('');
    L.push(`${srcName} stopped on a plan limit${tr.limitHit.ts ? ` at ${when(tr.limitHit.ts)} UTC` : ''}: "${tr.limitHit.text}". Its last turn may have been cut off mid-task.`);
    L.push('');
  }
  if (firstUser) {
    L.push('## Original request');
    L.push('');
    L.push(fence(clip(firstUser.text, 6000)));
    L.push('');
  }
  if (tr.compactSummary) {
    L.push(`## Earlier context (${srcName}'s own summary)`);
    L.push('');
    L.push(`${srcName} compacted this conversation${tr.compactAt ? ` at ${when(tr.compactAt)} UTC` : ''} and wrote this summary of everything before that point:`);
    L.push('');
    L.push(demote(clip(tr.compactSummary.replace(/^This session is being continued[^\n]*\n+/, ''), 16000)));
    L.push('');
  }

  // Every request, in order. The newest ones matter most, so when the budget runs out the
  // oldest are shortened first.
  const asks = tr.messages.filter((m) => m.role === 'user');
  if (asks.length) {
    L.push(`## Everything the person asked (${asks.length})`);
    L.push('');
    let budget = 24000;
    const lines = [];
    for (let i = asks.length - 1; i >= 0; i--) {
      const room = Math.max(160, Math.min(2000, budget));
      const t = demote(clip(asks[i].text, room)).replace(/\n/g, '\n   ');
      budget -= t.length;
      lines.unshift(`${i + 1}. ${asks[i].ts ? `_${when(asks[i].ts)}_ ` : ''}${t}`);
      if (budget < 0 && i > 0) { lines.unshift(`… ${i} earlier request(s) omitted here; see the full transcript.`); break; }
    }
    L.push(lines.join('\n'));
    L.push('');
  }
  if (tr.plan || tr.todos?.length) {
    L.push('## Plan and to-dos (latest)');
    L.push('');
    if (tr.plan) { L.push(demote(clip(tr.plan, 8000))); L.push(''); }
    if (tr.todos?.length) {
      const mark = { completed: 'x', in_progress: '~', pending: ' ', cancelled: '-' };
      for (const t of tr.todos.slice(0, 60)) L.push(`- [${mark[t.status] ?? ' '}] ${oneLine(t.content ?? t.activeForm ?? t.title ?? '', 200)}${t.status === 'in_progress' ? ' _(in progress)_' : ''}`);
      L.push('');
    }
  }

  const touched = new Map();
  for (const t of tr.tools) for (const p of editedPaths(t.name, t.input)) {
    const k = rel(cwd, p);
    touched.set(k, (touched.get(k) ?? 0) + 1);
  }
  if (touched.size) {
    L.push(`## Files the agent changed (${touched.size})`);
    L.push('');
    for (const [p, n] of [...touched].slice(0, 120)) L.push(`- \`${p}\`${n > 1 ? ` (${n} edits)` : ''}`);
    if (touched.size > 120) L.push(`- … and ${touched.size - 120} more`);
    L.push('');
  }
  const cmds = tr.tools.filter((t) => isShell(t.name) && shellCmd(t.input));
  if (cmds.length) {
    L.push(`## Commands it ran (last ${Math.min(25, cmds.length)} of ${cmds.length})`);
    L.push('');
    for (const t of cmds.slice(-25)) {
      const res = t.result != null ? ` → ${t.isError ? '✗ ' : ''}${oneLine(t.result, 160)}` : '';
      L.push(`- \`${oneLine(shellCmd(t.input), 180)}\`${res}`);
    }
    L.push('');
  }

  L.push('## Repository state now');
  L.push('');
  if (!git) L.push(cwd ? `\`${cwd}\` is not a git repository.` : 'The working directory of this session is unknown.');
  else {
    L.push(`Branch \`${git.branch ?? '?'}\`${git.head ? `, HEAD \`${git.head}\`` : ''}.`);
    L.push('');
    if (!git.status) L.push('The working tree is clean: everything is committed.');
    else {
      L.push('`git status --porcelain`:');
      L.push(fence(clip(git.status, 6000)));
      if (git.stat) { L.push(''); L.push('`git diff HEAD --stat`:'); L.push(fence(clip(git.stat, 4000))); }
      if (git.diff) {
        L.push('');
        L.push(`Uncommitted diff${git.diff.length > 40000 ? ' (truncated; run `git diff HEAD` for all of it)' : ''}:`);
        L.push(fence(clip(git.diff, 40000), 'diff'));
      }
      if (git.untracked.length) { L.push(''); L.push(`Untracked files are listed above but not shown in the diff: ${git.untracked.slice(0, 30).map((p) => `\`${p}\``).join(', ')}.`); }
    }
  }
  L.push('');

  // The end of the conversation, as it happened.
  const tail = [];
  let budget = 28000;
  for (let i = tr.messages.length - 1; i >= 0 && budget > 0; i--) {
    const m = tr.messages[i];
    let block;
    if (m.role === 'tool') block = `  · ${toolLine(m.tool, cwd)}`;
    else block = `**${m.role === 'user' ? 'Person' : srcName}**${m.ts ? ` _(${when(m.ts)})_` : ''}:\n${demote(clip(m.text, m.role === 'user' ? 4000 : 6000))}`;
    budget -= block.length;
    tail.unshift(block);
    if (tail.filter((b) => !b.startsWith('  ·')).length >= 16) break;
  }
  if (tail.length) {
    L.push('## Where it stopped (the latest turns, verbatim)');
    L.push('');
    L.push(tail.join('\n\n'));
    L.push('');
  }

  return {
    id,
    markdown: L.join('\n'),
    transcript: `# Full conversation: ${title}\n\nSource: ${srcName} session ${sessionId}${cwd ? ` in ${cwd}` : ''}. Tool calls are listed one per line after the turn that made them.\n${renderFull(tr, cwd)}\n`.slice(0, 8_000_000),
    summary: {
      id, sessionId, agent, title, cwd, file, target,
      requests: asks.length, filesChanged: touched.size, commands: cmds.length,
      compacted: !!tr.compactSummary, limitHit: tr.limitHit?.text ?? null,
      dirty: !!git?.status,
    },
  };
}

/** Write the handoff into <cwd>/.tether/handoff/, where the next agent can read it. */
export function writeHandoff(h, cwd) {
  if (!cwd || !fs.existsSync(cwd)) throw new Error(`working directory not found: ${cwd ?? '(unknown)'}`);
  const dir = path.join(cwd, HANDOFF_DIR);
  fs.mkdirSync(dir, { recursive: true });
  // Self-ignoring, so neither the handoff nor the transcript can be committed by accident and
  // the project's own .gitignore is never touched.
  const ignore = path.join(cwd, '.tether', '.gitignore');
  if (!fs.existsSync(ignore)) fs.writeFileSync(ignore, '# written by Tether: session handoffs stay out of git\n*\n');
  const mdPath = path.join(dir, `${h.id}.md`);
  const trPath = path.join(dir, `${h.id}.transcript.md`);
  fs.writeFileSync(mdPath, h.markdown, { mode: 0o600 });
  fs.writeFileSync(trPath, h.transcript, { mode: 0o600 });
  return { path: mdPath, transcriptPath: trPath, relPath: `${HANDOFF_DIR}/${h.id}.md` };
}

/** The first message the next agent receives. One line, so it survives every CLI and tmux. */
export function handoffPrompt({ relPath, source, note = null }) {
  const src = AGENT_NAMES[source] ?? source ?? 'another agent';
  return `Continue a coding session handed off from ${src}. First read ${relPath} in full — it has the goal, `
    + 'every request, what was already done and the current repository state — then pick up exactly where it stopped. '
    + 'Do not redo or revert finished work.'
    + (note?.trim() ? ` The person adds: ${oneLine(note, 600)}` : '');
}

// ---------------------------------------------------------------- lineage

export function readLineage() {
  try { const a = JSON.parse(fs.readFileSync(LINEAGE_PATH, 'utf8')); return Array.isArray(a) ? a : []; } catch { return []; }
}
function writeLineage(list) {
  fs.mkdirSync(TETHER_DIR, { recursive: true });
  fs.writeFileSync(LINEAGE_PATH, JSON.stringify(list.slice(-500), null, 2), { mode: 0o600 });
}
export function recordHandoff(rec) {
  const list = readLineage();
  list.push({ ...rec, at: rec.at ?? Date.now(), to: { ...(rec.to ?? {}), sessionId: rec.to?.sessionId ?? null } });
  writeLineage(list);
}
/** Attach the session a handoff started to its record. Returns the record, or null. */
export function linkHandoff(id, toSessionId) {
  const list = readLineage();
  const rec = list.find((r) => r.id === id);
  if (!rec) return null;
  if (rec.to?.sessionId !== toSessionId) {
    rec.to = { ...(rec.to ?? {}), sessionId: toSessionId };
    writeLineage(list);
  }
  return rec;
}
