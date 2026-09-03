// Per-agent integration: where each agent keeps its hooks, what shape they take, and
// which of its transcript directories Tether can tail.
//
// Everything here is additive and reversible. Installing MERGES Tether's entries into the
// agent's own config (after writing a backup) and never touches anyone else's hooks;
// removing strips only the entries whose command points at Tether's hook-exec.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { whichBin } from './service.mjs';

const HOME = os.homedir();
const MARKER = 'hook-exec.mjs'; // identifies an entry as Tether's

const loadJSON = (p, fallback) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; } };
const saveJSON = (p, o) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(o, null, 2)); };

/** Claude Code and Codex share one hook schema: events -> [{matcher?, hooks:[{type,command,timeout}]}] */
function nestedBuild(cmd, events) {
  const out = {};
  for (const [ev, matcher] of Object.entries(events)) {
    const entry = { hooks: [{ type: 'command', command: cmd(ev), timeout: ev === 'PreToolUse' ? 60 : 10 }] };
    if (matcher) entry.matcher = matcher;
    out[ev] = [entry];
  }
  return out;
}
function nestedMerge(cfg, snippet) {
  cfg.hooks = cfg.hooks ?? {};
  let added = 0;
  for (const [ev, entries] of Object.entries(snippet)) {
    cfg.hooks[ev] = cfg.hooks[ev] ?? [];
    if (!JSON.stringify(cfg.hooks[ev]).includes(MARKER)) { cfg.hooks[ev].push(...entries); added++; }
  }
  return added;
}
function nestedStrip(cfg) {
  if (!cfg?.hooks) return 0;
  let removed = 0;
  for (const ev of Object.keys(cfg.hooks)) {
    const before = Array.isArray(cfg.hooks[ev]) ? cfg.hooks[ev].length : 0;
    if (!before) continue;
    cfg.hooks[ev] = cfg.hooks[ev].filter((e) => !JSON.stringify(e).includes(MARKER));
    removed += before - cfg.hooks[ev].length;
    if (!cfg.hooks[ev].length) delete cfg.hooks[ev];
  }
  if (!Object.keys(cfg.hooks).length) delete cfg.hooks;
  return removed;
}

/** Cursor uses flat arrays and camelCase events: {version, hooks:{preToolUse:[{command,timeout}]}} */
function flatMerge(cfg, cmdFor, events) {
  cfg.version = cfg.version ?? 1;
  cfg.hooks = cfg.hooks ?? {};
  let added = 0;
  for (const ev of events) {
    cfg.hooks[ev] = cfg.hooks[ev] ?? [];
    if (!JSON.stringify(cfg.hooks[ev]).includes(MARKER)) {
      cfg.hooks[ev].push({ command: cmdFor(ev), timeout: 15 });
      added++;
    }
  }
  return added;
}

export const INTEGRATIONS = {
  claude: {
    name: 'Claude Code',
    bins: ['claude'],
    config: () => path.join(HOME, '.claude', 'settings.json'),
    roots: () => [path.join(HOME, '.claude', 'projects')],
    events: { PreToolUse: 'Bash|Write|Edit|NotebookEdit|ExitPlanMode|AskUserQuestion', Stop: null, Notification: null, UserPromptSubmit: null },
    install(cfg, cmd) { return nestedMerge(cfg, nestedBuild(cmd, this.events)); },
    remove: nestedStrip,
  },
  codex: {
    name: 'Codex',
    bins: ['codex'],
    config: () => path.join(HOME, '.codex', 'hooks.json'),
    roots: () => [], // sessions live in SQLite, not tailable jsonl
    events: { PreToolUse: 'shell|apply_patch|Edit|Write', Stop: null, Notification: null, UserPromptSubmit: null },
    install(cfg, cmd) { return nestedMerge(cfg, nestedBuild(cmd, this.events)); },
    remove: nestedStrip,
  },
  cursor: {
    name: 'Cursor',
    bins: ['cursor-agent'],
    config: () => path.join(HOME, '.cursor', 'hooks.json'),
    roots: () => [path.join(HOME, '.cursor', 'projects')], // <proj>/agent-transcripts/<id>/<id>.jsonl
    events: ['preToolUse', 'beforeShellExecution', 'beforeSubmitPrompt', 'stop'],
    install(cfg, cmd) { return flatMerge(cfg, (ev) => cmd(CURSOR_CANON[ev] ?? 'Notification'), this.events); },
    remove: nestedStrip,
  },
};
// map Cursor's event names onto the canonical ones hook-exec speaks
const CURSOR_CANON = { preToolUse: 'PreToolUse', beforeShellExecution: 'PreToolUse', beforeSubmitPrompt: 'UserPromptSubmit', stop: 'Stop' };

/** Which agents are actually installed and runnable on this machine? */
export function detectAgents() {
  const extra = `/usr/local/bin:/opt/homebrew/bin:${path.join(HOME, '.local', 'bin')}:${path.join(HOME, 'bin')}`;
  const env = { ...process.env, PATH: `${process.env.PATH ?? ''}:${extra}` };
  const found = [];
  for (const [key, def] of Object.entries(INTEGRATIONS)) {
    for (const b of def.bins) {
      const p = whichBin(b, env);
      if (p) { found.push({ key, name: def.name, bin: p }); break; }
    }
  }
  return found;
}

/** Install Tether's hooks into one agent's config. Returns a short status line. */
export function installFor(key, hookExecPath, nodeBin) {
  const def = INTEGRATIONS[key];
  if (!def) return { key, ok: false, detail: 'unknown agent' };
  const file = def.config();
  const cmd = (ev) => `"${nodeBin}" "${hookExecPath}" ${ev}`;
  const cfg = loadJSON(file, {});
  if (fs.existsSync(file)) fs.copyFileSync(file, `${file}.tether-backup-${Date.now()}`);
  // Always re-install from scratch: an existing entry may point at an old package path
  // (after an npm upgrade or a move), and silently keeping it would leave dead hooks.
  const stale = def.remove(cfg);
  const added = def.install(cfg, cmd);
  saveJSON(file, cfg);
  return { key, ok: true, detail: stale ? `refreshed ${added} hook event(s) -> ${file}` : `installed ${added} hook event(s) -> ${file}` };
}

/** Strip Tether's hooks back out of one agent's config. */
export function removeFor(key) {
  const def = INTEGRATIONS[key];
  if (!def) return { key, ok: false, detail: 'unknown agent' };
  const file = def.config();
  if (!fs.existsSync(file)) return { key, ok: true, detail: 'no config file; nothing to remove' };
  const cfg = loadJSON(file, {});
  fs.copyFileSync(file, `${file}.tether-backup-${Date.now()}`);
  const removed = def.remove(cfg);
  saveJSON(file, cfg);
  return { key, ok: true, detail: removed ? `removed ${removed} hook entr(ies) from ${file}` : `no Tether hooks in ${file}` };
}

/** Watch roots for the agents present, tagged so the app knows which tool wrote a session. */
export function rootsFor(keys) {
  const out = [];
  for (const k of keys) {
    for (const p of INTEGRATIONS[k]?.roots() ?? []) if (fs.existsSync(p)) out.push({ path: p, agent: k });
  }
  return out;
}
