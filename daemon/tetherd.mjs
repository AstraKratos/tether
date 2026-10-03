#!/usr/bin/env node
// tetherd — the Tether daemon. See plan §3.1.
// Commands: pair | run | hooks print|install | launchd install | status
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawn as spawnProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as C from './crypto.mjs';
import { normalizeLine } from './parser.mjs';
import { Tailer } from './watcher.mjs';
import { HookBridge } from './hookbridge.mjs';
import { Transport } from './transport.mjs';
import { Executor } from './executor.mjs';
import { detectAgents, installFor, removeFor, rootsFor, INTEGRATIONS } from './agents.mjs';
import { serviceFor, killStrays, terminalBackend } from './service.mjs';
import {
  AGENT_NAMES, HANDOFF_TARGETS, HANDOFF_REF_RE, LIMIT_RE, cwdFromCursorPath, listSessions, resolveSession,
  buildHandoff, writeHandoff, handoffPrompt, recordHandoff, linkHandoff,
} from './handoff.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = (() => { try { return JSON.parse(fs.readFileSync(path.join(HERE, '..', 'package.json'), 'utf8')); } catch { return {}; } })();
const VERSION = PKG.version ?? 'dev';
const PKG_NAME = PKG.name ?? 'tetherd';
// TETHER_HOME lets a second, isolated daemon run beside the real one (tests, a second account).
const TETHER_DIR = process.env.TETHER_HOME || path.join(os.homedir(), '.tether');
const ID_PATH = path.join(TETHER_DIR, 'identity.json');
const CFG_PATH = path.join(TETHER_DIR, 'config.json');
const STATE_PATH = path.join(TETHER_DIR, 'state.json');
const LOG_DIR = path.join(TETHER_DIR, 'logs');

const loadJSON = (p, fallback) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; } };
const saveJSON = (p, o, mode) => {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(o, null, 2));
  if (mode) fs.chmodSync(p, mode);
};

fs.mkdirSync(LOG_DIR, { recursive: true });
const logStream = fs.createWriteStream(path.join(LOG_DIR, 'tetherd.log'), { flags: 'a' });
const log = (msg) => {
  const line = `${new Date().toISOString()} ${msg}`;
  console.log(line);
  logStream.write(line + '\n');
};

const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
};

// ---------------------------------------------------------------- pair
async function cmdPair() {
  const code = process.argv[3];
  if (!code) { console.error('usage: tetherd pair <code> [--relay http://host:port] [--name machine-name]'); process.exit(1); }
  const parsed = C.parsePairingCode(code);
  const relay = (arg('--relay', 'http://127.0.0.1:8787')).replace(/\/$/, '');
  const name = arg('--name', os.hostname());
  const keys = C.genDeviceKeys();
  const res = await fetch(`${relay}/api/pair`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ accountId: parsed.a, pairingToken: parsed.t, pubkey: keys.pub, name, platform: process.platform }),
  });
  if (!res.ok) { console.error(`pairing failed: ${res.status} ${await res.text()}`); process.exit(1); }
  const { deviceId } = await res.json();
  saveJSON(ID_PATH, { relay, accountId: parsed.a, accountSecret: parsed.k, deviceId, pub: keys.pub, priv: keys.priv, name }, 0o600);
  if (!fs.existsSync(CFG_PATH)) {
    let claudeBin = 'claude';
    try { claudeBin = execFileSync('which', ['claude']).toString().trim() || 'claude'; } catch {}
    saveJSON(CFG_PATH, {
      claudeBin,
      roots: [path.join(os.homedir(), '.claude', 'projects')],
      approvalTimeoutSec: 25,
    });
  }
  console.log(`Paired as device ${deviceId} ("${name}") with relay ${relay}`);
  console.log(`Identity: ${ID_PATH} (0600). Next: tetherd run   (or: tetherd launchd install)`);
}

// ---------------------------------------------------------------- run
function cmdRun() {
  const id = loadJSON(ID_PATH, null);
  if (!id) { console.error('not paired: run `tetherd pair <code>` first'); process.exit(1); }
  const cfg = loadJSON(CFG_PATH, {});
  let state = loadJSON(STATE_PATH, { offsets: {}, cursors: {}, meta: {} });
  // Sync-state (byte offsets, relay cursors) is per-device. If we've been re-paired to a
  // different device/account, the old offsets would make us skip re-announcing every session
  // to the new account. Detect the change and start clean.
  if (state.deviceId && state.deviceId !== id.deviceId) {
    log(`identity changed (${state.deviceId} -> ${id.deviceId}); resetting sync state so all sessions re-announce`);
    state = { offsets: {}, cursors: {}, meta: {} };
  }
  state.deviceId = id.deviceId;
  state.offsets = state.offsets ?? {};
  state.cursors = state.cursors ?? {};
  state.meta = state.meta ?? {};
  const executor = new Executor(cfg.claudeBin || 'claude', log);
  // Each watch root is tagged with the agent that writes there, so the app can show
  // which tool produced each chat. Default: ~/.claude/projects -> 'claude'. Add more
  // roots as {path, agent:'codex'|'cursor'|...} in config.json when those adapters land.
  const rootDefs = (cfg.roots ?? [path.join(os.homedir(), '.claude', 'projects')])
    .map((r) => (typeof r === 'string' ? { path: r, agent: 'claude' } : { path: r.path, agent: r.agent || 'claude' }));
  const agentForFile = (file) => {
    let best = null;
    for (const r of rootDefs) if (file.startsWith(r.path) && (!best || r.path.length > best.path.length)) best = r;
    return best?.agent || 'claude';
  };
  const cleanTitle = (t) => String(t)
    .replace(/<timestamp>[\s\S]*?<\/timestamp>/g, '')
    .replace(/<\/?user_query>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 70);

  const sessionKey = new Map();
  const keyFor = (sid) => {
    if (!sessionKey.has(sid)) sessionKey.set(sid, C.deriveKey(id.accountSecret, `session:${sid}`));
    return sessionKey.get(sid);
  };

  let watchers = 0;      // browsers currently connected to this account (from the relay)
  let relayCursors = {}; // per-session max seq the relay holds (from authed)
  let syncing = false;
  let syncTargets = new Map(); // sid -> cursor we must reach for initial sync to be 'done'
  const sessions = new Map(); // sid -> session
  const fileSid = (file) => path.basename(file, '.jsonl');
  const getSession = (sid, file) => {
    let s = sessions.get(sid);
    if (!s) {
      s = { sid, file, agent: agentForFile(file || ''), meta: {}, title: null, state: 'idle',
            cursor: state.cursors[sid] ?? 0, ackSeq: relayCursors[sid] ?? 0, ring: [], ringStart: (state.cursors[sid] ?? 0) + 1,
            lastEventTs: 0, queue: [], inflight: false, announced: false, metaDirty: true };
      const saved = state.meta[sid];
      if (saved?.cwd) s.meta.cwd = saved.cwd;
      if (saved?.projectCwd) s.meta.projectCwd = saved.projectCwd;
      if (saved?.title) s.title = saved.title; // survive restarts; else the UI renames the chat
      // where this chat came from / went to, and whether it stopped on a plan limit
      for (const k of ['handoffFrom', 'handoffTo', 'limitHit']) if (saved?.[k]) s.meta[k] = saved[k];
      if (saved?.handoffChecked) s.handoffChecked = true;
      if (!file && saved?.file) s.file = saved.file;
      sessions.set(sid, s);
    }
    if (file) { s.file = file; s.agent = agentForFile(file); }
    if (!s.meta.cwd && s.file && s.agent === 'cursor') {
      const c = cwdFromCursorPath(s.file);
      if (c) { s.meta.cwd = c; s.meta.projectCwd = c; s.metaDirty = true; }
    }
    return s;
  };

  let persistTimer = null;
  const persist = () => {
    if (persistTimer) return;
    persistTimer = setTimeout(() => {
      persistTimer = null;
      for (const s of sessions.values()) {
        state.cursors[s.sid] = s.cursor;
        if (s.meta.cwd) {
          state.meta[s.sid] = { cwd: s.meta.cwd, file: s.file, title: s.title ?? null, projectCwd: s.meta.projectCwd ?? s.meta.cwd };
          for (const k of ['handoffFrom', 'handoffTo', 'limitHit']) if (s.meta[k]) state.meta[s.sid][k] = s.meta[k];
          if (s.handoffChecked) state.meta[s.sid].handoffChecked = true;
        }
      }
      saveJSON(STATE_PATH, state);
    }, 1000);
  };

  // ---- outbound to relay
  const announce = (s) => {
    if (!transport.ready) return;
    const metaCt = C.encryptJSON(keyFor(s.sid), { title: s.title, ...s.meta, projectDir: path.basename(path.dirname(s.file)) });
    transport.send({ type: 'session_upsert', sessionId: s.sid, agent: s.agent, state: s.state, metaCt });
    s.announced = true; s.metaDirty = false;
  };

  const flush = (sid) => {
    const s = sessions.get(sid);
    if (!s || !transport.ready || s.inflight) return;
    if (s.ackSeq > s.cursor) return resetSession(s, `relay ahead of local cursor (${s.ackSeq} > ${s.cursor})`);
    if (s.ackSeq >= s.cursor) return;
    const from = s.ackSeq + 1;
    if (from < s.ringStart) return resetSession(s, `relay needs seq ${from} but ring starts at ${s.ringStart}`);
    if (!s.announced || s.metaDirty) announce(s);
    const batch = s.ring.slice(from - s.ringStart, from - s.ringStart + 100)
      .map((ev, i) => ({ seq: from + i, ts: ev.ts, ct: C.encryptJSON(keyFor(sid), ev) }));
    if (!batch.length) return;
    s.inflight = true;
    transport.send({ type: 'events_append', sessionId: sid, events: batch });
  };

  const resetSession = (s, why) => {
    log(`resetting session ${s.sid}: ${why}`);
    transport.send({ type: 'session_reset', sessionId: s.sid });
    s.ring = []; s.ringStart = 1; s.cursor = 0; s.ackSeq = 0; s.inflight = false; s.announced = false;
    delete state.cursors[s.sid];
    tailer.retail(s.file);
    persist();
  };

  const noteCt = (sid, note) => (note ? C.encryptJSON(keyFor(sid), note) : undefined);
  const markState = (sid, newState, note) => {
    const s = sessions.get(sid) ?? getSession(sid, null);
    // a repeated prompt is still new information, so always deliver a note even if the
    // state itself has not changed (two permission asks in a row keep the same state)
    if (s.state === newState && !note) return;
    s.state = newState;
    transport.send({ type: 'state_change', sessionId: sid, state: newState, noteCt: noteCt(sid, note) });
    if (newState === 'idle') drain(s);
  };

  const drain = (s) => {
    if (!s.queue.length) return;
    const job = s.queue.shift();
    runPrompt(job);
  };

  let syncStartedAt = 0;
  const maybeSyncDone = () => {
    if (!syncing) return;
    const behind = [];
    for (const [sid, target] of syncTargets) {
      const s = sessions.get(sid);
      if (!s || s.ackSeq < target) behind.push(sid);
    }
    // Never hang in "syncing" forever. A session whose transcript was deleted (or that the
    // relay dropped) can never ack, and the old code waited on it indefinitely — leaving
    // the UI spinning. Give the backlog a bounded window, then finish and say what lagged.
    const timedOut = syncStartedAt && Date.now() - syncStartedAt > 45_000;
    if (behind.length && !timedOut) return;
    syncing = false;
    transport.send({ type: 'device_sync', state: 'idle' });
    if (behind.length) {
      log(`initial sync finished with ${behind.length} session(s) still behind after 45s: ${behind.slice(0, 5).map((x) => x.slice(0, 8)).join(', ')}`);
      for (const sid of behind) { // stop chasing sessions whose file is gone
        const s = sessions.get(sid);
        if (!s?.file || !fs.existsSync(s.file)) { sessions.delete(sid); delete state.cursors[sid]; delete state.meta[sid]; }
      }
      persist();
    } else log(`initial sync complete (${syncTargets.size} sessions)`);
  };

  // locate a session's transcript file across watch roots and read its cwd
  const hydrateFromFile = (sid) => {
    for (const root of cfg.roots ?? [path.join(os.homedir(), '.claude', 'projects')]) {
      const stack = [root];
      while (stack.length) {
        const dir = stack.pop();
        let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
        for (const e of entries) {
          const p = path.join(dir, e.name);
          if (e.isDirectory()) stack.push(p);
          else if (e.name === `${sid}.jsonl`) {
            const s = getSession(sid, p);
            if (!s.meta.cwd) {
              try {
                const head = fs.readFileSync(p, 'utf8').split('\n').slice(0, 10);
                for (const line of head) {
                  try { const o = JSON.parse(line); if (o.cwd) { s.meta.cwd = o.cwd; break; } } catch {}
                }
              } catch {}
            }
            return s;
          }
        }
      }
    }
    return null;
  };

  // Attached images arrive base64 inside the encrypted prompt body. `claude -p` only takes
  // image input as file paths, so they're written under ~/.tether/images and the prompt text
  // points the agent at them; files older than a day are pruned on the next write.
  const IMG_EXT = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif' };
  const materializeImages = (body, promptId) => {
    const text = body.text ?? '';
    const imgs = Array.isArray(body.images) ? body.images.slice(0, 8) : [];
    if (!imgs.length) return text;
    const dir = path.join(TETHER_DIR, 'images');
    fs.mkdirSync(dir, { recursive: true });
    try {
      for (const f of fs.readdirSync(dir)) {
        const p = path.join(dir, f);
        if (Date.now() - fs.statSync(p).mtimeMs > 86_400_000) fs.unlinkSync(p);
      }
    } catch {}
    const lines = [];
    imgs.forEach((im, i) => {
      const ext = IMG_EXT[im.type];
      if (!ext) return;
      const buf = Buffer.from(String(im.data ?? ''), 'base64');
      if (!buf.length || buf.length > 8_000_000) return;
      const f = path.join(dir, `${String(promptId).replace(/[^a-zA-Z0-9_-]/g, '')}-${i}${ext}`);
      fs.writeFileSync(f, buf);
      lines.push(`[Attached image ${i + 1}${im.name ? ` (${String(im.name).slice(0, 80)})` : ''}: ${f} — open it with the Read tool]`);
    });
    if (!lines.length) return text;
    return `${text || 'Please look at the attached image(s).'}\n\n${lines.join('\n')}`;
  };

  // ---- live delivery: type a prompt into an ALREADY-RUNNING interactive Claude instead
  // of spawning a second headless process. Requires the session to be running inside a
  // tmux pane (the only supported way to reach a live TUI's stdin from outside).
  const TMUX_ENV = () => ({ ...process.env, PATH: `${process.env.PATH ?? ''}:/opt/homebrew/bin:/usr/local/bin` });
  const tmux = (args) => execFileSync('tmux', args, { timeout: 5000, maxBuffer: 2_000_000, env: TMUX_ENV() }).toString();
  function livePanes() {
    if (terminalBackend().kind !== 'tmux') return []; // no way to reach a live TUI here
    let out, ps;
    try { out = tmux(['list-panes', '-a', '-F', '#{pane_id}\t#{pane_pid}\t#{pane_current_path}\t#{session_name}:#{window_index}.#{pane_index}']); }
    catch { return []; } // no tmux, or no server running
    try { ps = execFileSync('ps', ['-axo', 'pid=,ppid=,command='], { timeout: 5000, maxBuffer: 8_000_000 }).toString(); }
    catch { return []; }
    const kids = new Map(), cmd = new Map();
    for (const l of ps.split('\n')) {
      const m = l.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
      if (!m) continue;
      cmd.set(m[1], m[3]);
      if (!kids.has(m[2])) kids.set(m[2], []);
      kids.get(m[2]).push(m[1]);
    }
    const runsClaude = (pid, depth = 0) => {
      if (depth > 4) return false;
      const c = cmd.get(String(pid)) ?? '';
      if (/claude/i.test(c) && !/tetherd|tmux/i.test(c)) return true;
      return (kids.get(String(pid)) ?? []).some((k) => runsClaude(k, depth + 1));
    };
    const panes = [];
    for (const line of out.split('\n')) {
      if (!line.trim()) continue;
      const [id, pid, cwd, label] = line.split('\t');
      if (id && cwd && runsClaude(pid)) panes.push({ id, cwd, label: label ?? id });
    }
    return panes;
  }
  // Extract the numbered choices a TUI prompt is offering, e.g. " ❯ 1. Yes" / "   3. No"
  const parsePromptOptions = (text) => {
    const out = [];
    for (const l of String(text ?? '').split('\n')) {
      const m = l.match(/^\s*[\u276f>*]?\s*([1-9])[.)]\s+(\S.{0,90}?)\s*$/);
      if (m && !out.some((o) => o.key === m[1])) out.push({ key: m[1], label: m[2] });
    }
    return out.length >= 2 ? out.slice(0, 6) : null;
  };
  const paneForSession = (sid) => {
    const cwd = cwdForSession(sid);
    if (!cwd) return null;
    return livePanes().find((p) => p.cwd === cwd) ?? null;
  };
  function injectToPane(paneId, text) {
    // newlines inside the message become M-Enter (soft newline in the TUI); a final
    // Enter submits. Control characters are stripped so nothing else can be "typed".
    const lines = String(text).replace(/\r/g, '').replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (i) tmux(['send-keys', '-t', paneId, 'M-Enter']);
      if (lines[i]) tmux(['send-keys', '-t', paneId, '-l', lines[i]]);
    }
    tmux(['send-keys', '-t', paneId, 'Enter']);
  }

  // shift+tab cycles the TUI through these four, in this order (verified against Claude
  // Code 2.1.258); the TUI calls 'default' "manual". bypassPermissions and dontAsk are not
  // on the cycle, so a session already running cannot be switched into them.
  // Setting the model on a live TUI must NOT touch the machine default. The inline form
  // (`/model sonnet`) answers "saved as your default for new sessions", and typing a row's
  // number confirms it the same way — both were measured. Only the picker's `s` says "for
  // this session only", so drive the picker: open it, walk down to the row, press s.
  const pause = (ms) => new Promise((r) => setTimeout(r, ms));
  const MODEL_ROW = {
    default: 'default', opus: 'opus', 'opus[1m]': 'opus (1m context)', fable: 'fable',
    'fable[1m]': 'fable (1m context)', sonnet: 'sonnet', 'sonnet[1m]': 'sonnet (1m context)',
    haiku: 'haiku', opusplan: 'opus plan', best: 'best available',
  };
  const normRow = (t) => String(t ?? '').toLowerCase().replace(/[^a-z0-9( )]/g, '').trim();
  const pickerRow = (paneId) => {
    const line = tmux(['capture-pane', '-t', paneId, '-p']).split('\n').find((l) => /\u276f\s*\d+\./.test(l));
    // cut the description off at the column gap so 'sonnet' cannot match a neighbouring row
    return line ? normRow(line.replace(/.*\u276f\s*\d+\.\s*/, '').split(/ {2,}/)[0]) : null;
  };
  async function setModelForSession(paneId, model) {
    const want = normRow(MODEL_ROW[model] ?? model);
    injectToPane(paneId, '/model');
    await pause(1200);
    for (let i = 0; i < 14; i++) {
      const row = pickerRow(paneId);
      if (row && (row === want || row.startsWith(want))) {
        tmux(['send-keys', '-t', paneId, '-l', 's']);
        await pause(600);
        return true;
      }
      tmux(['send-keys', '-t', paneId, 'Down']);
      await pause(450);
    }
    tmux(['send-keys', '-t', paneId, 'Escape']); // never fall back to the inline form
    await pause(400);
    return false;
  }

  const MODE_CYCLE = ['default', 'acceptEdits', 'plan', 'auto'];
  const modeIdx = (m) => MODE_CYCLE.indexOf(m === 'manual' ? 'default' : m);
  const modeSteps = (from, to) => {
    const a = modeIdx(from ?? 'default'), b = modeIdx(to);
    return a < 0 || b < 0 ? null : (b - a + MODE_CYCLE.length) % MODE_CYCLE.length;
  };

  // A session whose opening request points at a handoff file was started from another chat.
  // Link both ways, so each side of the web UI can jump to the other.
  function linkHandedOff(s, id) {
    const rec = linkHandoff(id, s.sid);
    if (!rec) return;
    s.meta.handoffFrom = { id, sessionId: rec.from?.sessionId ?? null, agent: rec.from?.agent ?? null, title: rec.from?.title ?? null };
    s.metaDirty = true;
    const src = rec.from?.sessionId ? sessions.get(rec.from.sessionId) : null;
    if (src) {
      const to = (src.meta.handoffTo ?? []).find((t) => t.id === id);
      if (to && to.sessionId !== s.sid) { to.sessionId = s.sid; src.metaDirty = true; if (src.announced) announce(src); }
    }
    log(`handoff ${id}: ${s.agent} session ${s.sid.slice(0, 8)} continues ${rec.from?.agent ?? '?'} session ${String(rec.from?.sessionId ?? '?').slice(0, 8)}`);
    persist();
  }

  // Hand a session over to another agent: write the context into the project, then start the
  // target with it. mode: 'interactive' (tmux TUI), 'headless' (one-shot run) or 'file' (write
  // only — for an IDE chat the person drives themselves).
  async function startHandoff(req) {
    let src = sessions.get(req.sessionId);
    if (!src && state.meta[req.sessionId]) src = getSession(req.sessionId, state.meta[req.sessionId].file);
    if (!src) src = hydrateFromFile(req.sessionId);
    if (!src?.file || !fs.existsSync(src.file)) return { error: 'this session\'s transcript is not on this machine' };
    const target = HANDOFF_TARGETS.includes(req.target) ? req.target : null;
    if (!target) return { error: `cannot hand off to "${req.target}"` };
    const mode = ['interactive', 'headless', 'file'].includes(req.mode) ? req.mode : 'interactive';
    const cwd = src.meta.projectCwd || src.meta.cwd || cwdFromCursorPath(src.file);
    if (!cwd || !fs.existsSync(cwd)) return { error: `the session's project folder is missing (${cwd ?? 'unknown'})` };
    const note = typeof req.note === 'string' ? req.note.slice(0, 4000) : null;
    let h, w;
    try {
      h = buildHandoff({ file: src.file, agent: src.agent, sessionId: src.sid, cwd, title: src.title, target, note });
      w = writeHandoff(h, cwd);
    } catch (e) { return { error: `could not write the handoff: ${e.message}` }; }
    const prompt = handoffPrompt({ relPath: w.relPath, source: src.agent, note });
    recordHandoff({ id: h.id, from: { sessionId: src.sid, agent: src.agent, title: src.title ?? h.summary.title }, to: { agent: target }, cwd, path: w.path, mode });
    src.meta.handoffTo = [...(src.meta.handoffTo ?? []), { id: h.id, agent: target, at: Date.now(), sessionId: null }].slice(-10);
    src.metaDirty = true;
    if (transport.ready) announce(src);
    persist();
    log(`handoff ${h.id}: ${src.agent} ${src.sid.slice(0, 8)} -> ${target} (${mode}) at ${w.path}`);
    const out = { ok: true, id: h.id, path: w.path, relPath: w.relPath, prompt, mode, target, summary: h.summary };
    if (mode === 'file') return out;
    // Interactive: answer once the agent is up (or failed to start). Headless: answer once it is
    // running — the run itself can take minutes, and its outcome shows up as a new session.
    return new Promise((resolve) => {
      let answered = false;
      const answer = (extra) => { if (!answered) { answered = true; resolve({ ...out, ...extra }); } };
      executor.startHandoff({ promptId: h.id, agent: target, cwd, text: prompt, interactive: mode === 'interactive', opts: req.opts ?? null },
        (status, detail) => {
          if (status === 'failed') {
            if (answered) noteError(`handoff ${h.id} to ${target}: ${detail}`);
            answer({ ok: false, error: detail });
          } else if (status === 'done' || (status === 'executing' && mode === 'headless')) {
            answer({ started: detail ?? `${AGENT_NAMES[target] ?? target} is running headless` });
          }
        });
    });
  }

  const runPrompt = (job) => {
    const report = (status, detail) => {
      if (status === 'failed') noteError(`prompt ${job.promptId}: ${detail}`);
      transport.send({ type: 'prompt_status', promptId: job.promptId, status, detail });
    };
    if (job.sessionId) {
      let s = sessions.get(job.sessionId);
      if (!s && state.meta[job.sessionId]) s = getSession(job.sessionId, state.meta[job.sessionId].file);
      if (!s) s = hydrateFromFile(job.sessionId);
      if (!s) return report('failed', 'unknown session');
      // deliver into the live terminal when asked and reachable — the running TUI shows
      // the message and answers in place, exactly as if it had been typed there
      if (job.live) {
        const pane = paneForSession(job.sessionId);
        if (!pane) return report('failed', 'no live tmux pane found for this session');
        // Apply the chosen model and mode to the running TUI through its own controls, then
        // type the message. Both are session-scoped: neither writes to ~/.claude/settings.json.
        const o = job.opts ?? {};
        (async () => {
          const applied = [];
          try {
            if (o.model && o.model !== s.liveModel) {
              const ok = await setModelForSession(pane.id, o.model);
              if (ok) s.liveModel = o.model; // don't re-run the picker for every message
              applied.push(ok ? `model → ${o.model} (this session only)` : `model ${o.model} not offered by the picker`);
            }
            const turns = o.mode ? modeSteps(s.meta.permissionMode, o.mode) : 0;
            if (o.mode && turns === null) applied.push(`mode ${o.mode} needs a fresh run`);
            else if (turns) {
              for (let i = 0; i < turns; i++) { tmux(['send-keys', '-t', pane.id, 'BTab']); await pause(350); }
              applied.push(`mode → ${o.mode}`);
            }
            await pause(400);
            injectToPane(pane.id, job.text);
          } catch (e) { return report('failed', `live delivery failed: ${e.message}`); }
          log(`live: delivered prompt ${job.promptId} to pane ${pane.id} (${pane.label})${applied.length ? ` [${applied.join(', ')}]` : ''}`);
          report('done', `delivered to live terminal ${pane.label}${applied.length ? ` — ${applied.join(', ')}` : ''}`);
        })();
        return;
      }
      if (s.state !== 'idle') { s.queue.push(job); return report('queued', 'session is mid-turn; will run when idle'); }
      job.cwd = job.cwd || s.meta.cwd;
      if (!job.cwd) return report('failed', 'session cwd unknown; cannot resume');
      s.state = 'running'; // optimistic; watcher confirms
      transport.send({ type: 'state_change', sessionId: s.sid, state: 'running' });
    }
    executor.run(job, report);
  };

  // ---- inbound lines from watcher
  const onLines = (file, lines) => {
    const sid = fileSid(file);
    const s = getSession(sid, file);
    let touched = false;
    for (const raw of lines) {
      const { events, meta, title } = normalizeLine(raw);
      // a turn served by a different model = the model was switched (here or from the web UI):
      // record it inline so both sides show the same history
      if (meta?.model && s.meta.model && meta.model !== s.meta.model) { // not on the first turn
        s.cursor += 1;
        s.ring.push({ ts: new Date().toISOString(), kind: 'model_switch', model: meta.model, from: s.meta.model });
        if (s.ring.length > 2000) { s.ring.shift(); s.ringStart += 1; }
        touched = true;
      }
      if (meta) {
        Object.assign(s.meta, meta);
        if (meta.cwd && !s.meta.projectCwd) s.meta.projectCwd = meta.cwd;
        s.metaDirty = true;
      }
      // A real model turn after a plan limit means the limit lifted (or the model changed).
      if (meta?.model && s.meta.limitHit) { delete s.meta.limitHit; s.metaDirty = true; }
      for (const ev of events) {
        if (ev.kind !== 'text') continue;
        if (ev.role === 'assistant' && ev.model === '<synthetic>' && LIMIT_RE.test(ev.text ?? '')) {
          s.meta.limitHit = { text: String(ev.text).replace(/\s+/g, ' ').trim().slice(0, 200), ts: ev.ts ?? new Date().toISOString() };
          s.metaDirty = true;
        } else if (ev.role === 'user' && !s.handoffChecked) {
          s.handoffChecked = true; // only the opening request can be a handoff
          const m = String(ev.text ?? '').match(HANDOFF_REF_RE);
          if (m) linkHandedOff(s, m[1]);
        }
      }
      if (title && title !== s.title) { s.title = title; s.metaDirty = true; }
      if (!s.title) { // agents like Cursor never emit a title: use the opening request
        const first = events.find((e) => e.kind === 'text' && e.role === 'user' && e.text?.trim());
        if (first) { const t = cleanTitle(first.text); if (t) { s.title = t; s.metaDirty = true; } }
      }
      for (const ev of events) {
        s.cursor += 1;
        s.ring.push(ev);
        if (s.ring.length > 2000) { s.ring.shift(); s.ringStart += 1; }
        touched = true;
      }
    }
    if (touched) {
      s.lastEventTs = Date.now();
      // trailing transcript writes right after a Stop hook are not new activity
      if (s.state === 'idle' && Date.now() > (s.idleGraceUntil ?? 0)) markState(sid, 'running');
      persist();
      flush(sid);
    } else if (s.metaDirty && s.announced) announce(s);
  };

  const tailer = new Tailer(rootDefs.map((r) => r.path),
    onLines, (file) => { const s = sessions.get(fileSid(file)); if (s) resetSession(s, 'file truncated'); },
    state.offsets, log);

  // ---- hooks
  //
  // Whether a PermissionRequest may be held for the web UI. The CLI has already decided a
  // human must answer, so the agent is stopped either way; the only question is whether
  // anyone can answer from the UI. No heuristics belong here — they belonged to the old
  // PreToolUse gate, which had to GUESS whether a prompt was coming. This one is told.
  const canHold = () => cfg.remoteApprovals !== false && watchers > 0;

  const bridge = new HookBridge({
    canHold,
    onApprovalOpen: (a) => {
      markState(a.sessionId, 'waiting_approval');
      const requestCt = C.encryptJSON(C.deriveKey(id.accountSecret, `approval:${a.id}`),
        { toolName: a.toolName, toolInput: a.toolInput, cwd: a.cwd, permissionMode: a.permissionMode });
      transport.send({ type: 'approval_open', approvalId: a.id, sessionId: a.sessionId, deadline: a.deadline, requestCt });
    },
    // A `claude -p` run this machine started has hit something the CLI could not decide.
    // It is blocked until we answer, and there is no terminal to answer it at — so this is
    // the one place a decision genuinely has to come from the web UI.
    onPermissionRequest: (r) => {
      markState(r.sessionId, 'waiting_approval');
      const requestCt = C.encryptJSON(C.deriveKey(id.accountSecret, `approval:${r.id}`),
        { toolName: r.toolName, toolInput: r.toolInput, cwd: r.cwd, kind: r.kind });
      // No real deadline — the run waits indefinitely — but the relay only lists approvals
      // whose deadline is still ahead, so give it one far enough out to stay visible.
      transport.send({ type: 'approval_open', approvalId: r.id, sessionId: r.sessionId,
                       deadline: Date.now() + 86_400_000, requestCt });
      log(`permission request ${r.id} (${r.kind}: ${r.toolName}) sent to the web UI`);
    },
    onApprovalSettled: (approvalId, outcome) => {
      // allow/deny came FROM the relay, which already knows. Everything else ended here —
      // timed out, or the session moved past the prompt — and the UI has to be told, or
      // the card sits there looking live for something that was settled minutes ago.
      if (outcome !== 'allow' && outcome !== 'deny') transport.send({ type: 'approval_update', approvalId, status: outcome });
      for (const s of sessions.values()) if (s.state === 'waiting_approval' && !bridge.hasPendingFor(s.sid)) markState(s.sid, 'running');
    },
    onStop: (sid) => {
      const s = getSession(sid, null);
      s.idleGraceUntil = Date.now() + 5000;
      markState(sid, 'idle', { message: 'Turn finished' });
    },
    // The agent is really asking the user something (permission, a choice, plain input).
    // Mirror it verbatim, with the tool call it refers to, so the web UI can show the same
    // question — and say whether we can answer it remotely (only tmux-backed sessions).
    onNotification: (sid, message, pendingTool) => {
      let pane = null, screen = null, options = null;
      try { pane = paneForSession(sid); } catch {}
      if (pane) {
        // Read the terminal itself: that is the real question, with the real choices.
        try {
          const raw = tmux(['capture-pane', '-t', pane.id, '-p']);
          const lines = raw.split('\n').map((l) => l.replace(/\s+$/, '')).filter((l) => l.trim());
          screen = lines.slice(-16).join('\n');
          options = parsePromptOptions(screen);
        } catch {}
      }
      const fresh = pendingTool && (Date.now() - pendingTool.at) < 600_000 ? pendingTool : null;
      markState(sid, 'waiting_input', {
        message,
        tool: fresh ? { name: fresh.toolName, input: fresh.toolInput, mode: fresh.permissionMode } : null,
        screen, options, answerable: !!pane, pane: pane?.label ?? null,
        reason: pane ? null : (terminalBackend().reason ?? null),
      });
    },
    onPromptSubmit: (sid) => markState(sid, 'running'),
  }, {
    // Long enough for a person to notice their phone and decide. 25s was a script's
    // timeout, not a human's: the card expired before anyone could reach it, and the
    // prompt fell back to the machine — which is the exact problem this exists to solve.
    approvalTimeoutMs: (cfg.approvalTimeoutSec ?? 600) * 1000,
  }, log);

  // ---- health: a small self-report so the web UI can say exactly what this daemon is
  // doing and what last went wrong. Encrypted like session meta — the relay can't read it.
  const health = { startedAt: Date.now(), lastError: null, lastErrorAt: null };
  function noteError(msg) {
    health.lastError = String(msg).slice(0, 300);
    health.lastErrorAt = Date.now();
    log(`health: ${health.lastError}`);
    pushHealth();
  }
  function pushHealth() {
    try {
      const healthCt = C.encryptJSON(C.deriveKey(id.accountSecret, `health:${id.deviceId}`), {
        startedAt: health.startedAt, pid: process.pid, version: VERSION,
        roots: rootDefs.length, sessions: sessions.size,
        lastError: health.lastError, lastErrorAt: health.lastErrorAt, at: Date.now(),
      });
      transport.send({ type: 'daemon_status', healthCt });
    } catch (e) { log(`health encrypt failed: ${e.message}`); }
  }

  // ---- workspace inspector: read-only explorer + git changes for the web UI.
  // Requests and results are e2e-encrypted (scope fs:<deviceId>); every path is
  // resolved against the session's cwd and must stay inside it. No writes, no shell.
  let _fsKey = null;
  const fsKey = () => (_fsKey ??= C.deriveKey(id.accountSecret, `fs:${id.deviceId}`));
  const cwdForSession = (sid) => sessions.get(sid)?.meta?.cwd || state.meta[sid]?.cwd || null;
  const safeResolve = (cwd, rel) => {
    const root = fs.realpathSync(cwd);
    const abs = path.resolve(root, rel || '.');
    const real = fs.existsSync(abs) ? fs.realpathSync(abs) : abs;
    if (real !== root && !real.startsWith(root + path.sep)) throw new Error('path outside workspace');
    return real;
  };
  const git = (cwd, args) => execFileSync('git', args, { cwd, timeout: 8000, maxBuffer: 4_000_000 }).toString();

  // Claude account + plan-limit usage, as Claude Code's own /usage shows it. The OAuth
  // token is read locally (Keychain / credentials file) and NEVER leaves this machine —
  // only derived percentages travel, e2e-encrypted like every other fs result.
  let usageCache = { at: 0, data: null };
  const claudeAccount = () => {
    try {
      const oa = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.claude.json'), 'utf8')).oauthAccount ?? {};
      const PLANS = { claude_team: 'Claude team', claude_pro: 'Claude Pro', claude_max: 'Claude Max', claude_enterprise: 'Claude enterprise' };
      return { method: 'Claude AI', email: oa.emailAddress ?? null, org: oa.organizationName ?? null,
               plan: PLANS[oa.organizationType] ?? oa.organizationType ?? null };
    } catch { return null; }
  };
  const claudeToken = () => {
    try {
      const raw = process.platform === 'darwin'
        ? execFileSync('security', ['find-generic-password', '-s', 'Claude Code-credentials', '-w'], { timeout: 4000 }).toString()
        : fs.readFileSync(path.join(os.homedir(), '.claude', '.credentials.json'), 'utf8');
      return JSON.parse(raw).claudeAiOauth?.accessToken ?? null;
    } catch { return null; }
  };
  async function claudeLimits() {
    if (Date.now() - usageCache.at < 60_000 && usageCache.data) return usageCache.data;
    const token = claudeToken();
    if (!token) return { error: 'no Claude login found on this machine' };
    try {
      const res = await fetch('https://api.anthropic.com/api/oauth/usage', {
        headers: { authorization: `Bearer ${token}`, 'anthropic-beta': 'oauth-2025-04-20' },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) return { error: res.status === 401 ? 'Claude token expired — run Claude Code once on this machine to refresh it' : `usage endpoint: HTTP ${res.status}` };
      const d = await res.json();
      const LABELS = { session: 'Session (5hr)', weekly_all: 'Weekly (7 day)' };
      const limits = (d.limits ?? []).map((l) => ({
        label: l.kind === 'weekly_scoped' ? `Weekly ${l.scope?.model?.display_name ?? ''}`.trim() : (LABELS[l.kind] ?? l.kind),
        percent: l.percent ?? 0, severity: l.severity ?? 'normal', resetsAt: l.resets_at ?? null,
      }));
      usageCache = { at: Date.now(), data: { limits } };
      return usageCache.data;
    } catch (e) { return { error: `usage fetch failed: ${e.message}` }; }
  }

  // live discovery of installed agent CLIs and the models each one ACTUALLY offers.
  // "Available" means the binary runs, not merely exists (a broken install is reported
  // as broken). Model lists come from each tool's own source of truth, cached 10 min.
  let agentsCache = { at: 0, data: null };
  let modelsCache = { at: 0, data: null };
  // Claude Code's picker is NOT the raw API model list: it offers version-aware ALIASES
  // (fable, opus, sonnet, haiku, opus[1m], …) that always resolve to what the installed
  // CLI supports. We mirror that, then append full API ids, disabling any the CLI is too
  // old to accept — so the web UI can never offer a model that would fail locally.
  const cmpVer = (a, b) => { // -1 / 0 / 1
    const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
    for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return Math.sign(d); }
    return 0;
  };
  const MODEL_MIN_CLI = { 'claude-fable-5-1': '2.1.255' }; // model id -> minimum Claude Code version
  async function apiModels() {
    if (Date.now() - modelsCache.at < 600_000 && modelsCache.data) return modelsCache.data;
    const token = claudeToken();
    if (!token) return [];
    try {
      const res = await fetch('https://api.anthropic.com/v1/models?limit=50', {
        headers: { authorization: `Bearer ${token}`, 'anthropic-beta': 'oauth-2025-04-20', 'anthropic-version': '2023-06-01' },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) return [];
      const d = await res.json();
      modelsCache = { at: Date.now(), data: (d.data ?? []).map((m) => ({ id: m.id, name: m.display_name ?? m.id })) };
      return modelsCache.data;
    } catch { return []; }
  }
  async function claudeModels(cliVersion) {
    const api = await apiModels();
    const usable = (m) => { // an alias can only resolve to a model THIS CLI version supports
      const min = MODEL_MIN_CLI[m.id];
      return !(min && cliVersion && cmpVer(cliVersion, min) < 0);
    };
    const newest = (frag) => api.find((m) => m.id.startsWith(frag) && usable(m))?.name ?? null; // API returns newest first
    const ALIASES = [
      ['default', 'Default (recommended)', 'the CLI’s own default model'],
      ['opus', 'Opus', newest('claude-opus')],
      ['opus[1m]', 'Opus (1M context)', newest('claude-opus')],
      ['fable', 'Fable', newest('claude-fable')],
      ['fable[1m]', 'Fable (1M context)', newest('claude-fable')],
      ['sonnet', 'Sonnet', newest('claude-sonnet')],
      ['sonnet[1m]', 'Sonnet (1M context)', newest('claude-sonnet')],
      ['haiku', 'Haiku', newest('claude-haiku')],
      ['opusplan', 'Opus plan mode', 'Opus while planning, Sonnet to execute'],
      ['best', 'Best available', 'highest-capability model on your plan'],
    ];
    const out = ALIASES.map(([id, name, desc]) => ({ id, name, desc: desc ?? undefined, alias: true }));
    for (const m of api) {
      const min = MODEL_MIN_CLI[m.id];
      const tooOld = min && cliVersion && cmpVer(cliVersion, min) < 0;
      out.push({ id: m.id, name: m.name, desc: m.id, disabled: !!tooOld,
                 reason: tooOld ? `needs Claude Code ${min}+ (you have ${cliVersion})` : undefined });
    }
    return out;
  }

  async function handleFs(req) {
    // device-level ops (no session needed): pick an agent + folder for a NEW session
    if (req.op === 'agents') {
      if (Date.now() - agentsCache.at < 600_000 && agentsCache.data) return agentsCache.data;
      const AGENT_BINS = { claude: ['claude'], codex: ['codex'], opencode: ['opencode'], cursor: ['cursor-agent'], gemini: ['gemini'], aider: ['aider'] };
      const extra = `/usr/local/bin:/opt/homebrew/bin:${path.join(os.homedir(), '.local', 'bin')}:${path.join(os.homedir(), 'bin')}`;
      const env = { ...process.env, PATH: `${process.env.PATH ?? ''}:${extra}` };
      const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');
      const tryRun = (bin, args, t) => { try { return execFileSync(bin, args, { env, timeout: t, maxBuffer: 2_000_000 }).toString(); } catch { return null; } };
      const which = (b) => { try { return execFileSync('which', [b], { env, timeout: 3000 }).toString().trim() || null; } catch { return null; } };
      const agents = [];
      for (const [agent, bins] of Object.entries(AGENT_BINS)) {
        const bin = bins.map(which).find(Boolean);
        if (!bin) continue;
        const ver = tryRun(bin, ['--version'], 10_000);
        if (ver === null) { agents.push({ agent, bin, broken: true }); continue; }
        const verNum = (stripAnsi(ver).match(/(\d+\.\d+\.\d+)/) ?? [])[1] ?? null;
        let models = [];
        if (agent === 'claude') {
          models = await claudeModels(verNum);
        } else if (agent === 'opencode') {
          const o = tryRun(bin, ['models'], 20_000);
          if (o) models = stripAnsi(o).split('\n').map((l) => l.trim())
            .filter((l) => /^[\w.-]+\/[\w.:@,-]+$/.test(l)).slice(0, 80).map((id) => ({ id, name: id }));
        } else if (agent === 'cursor') {
          const o = tryRun(bin, ['--list-models'], 20_000);
          if (o) models = stripAnsi(o).split('\n').map((l) => l.trim())
            .filter((l) => l && !/loading|no models/i.test(l)).slice(0, 40).map((id) => ({ id, name: id }));
        }
        agents.push({ agent, bin, version: stripAnsi(ver).trim().split('\n')[0].slice(0, 60), models });
      }
      // What "default" really resolves to: `/model` writes the choice here. Absent means the
      // CLI's own built-in default, which we cannot name — report null rather than guess.
      let claudeDefaultModel = null;
      try { claudeDefaultModel = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.claude', 'settings.json'), 'utf8')).model ?? null; } catch {}
      agentsCache = { at: Date.now(), data: { agents, claudeDefaultModel } };
      return agentsCache.data;
    }
    if (req.op === 'projects') { // folders this machine has run sessions in before
      const seen = new Set();
      for (const s of sessions.values()) if (s.meta?.cwd) seen.add(s.meta.cwd);
      for (const m of Object.values(state.meta)) if (m?.cwd) seen.add(m.cwd);
      const projects = [...seen]
        .filter((p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } })
        .sort()
        .slice(0, 100)
        .map((p) => ({ path: p, repo: fs.existsSync(path.join(p, '.git')) }));
      return { home: os.homedir(), projects };
    }
    if (req.op === 'browse') { // navigate directories, rooted at (and capped to) the home dir
      const home = fs.realpathSync(os.homedir());
      const abs = path.resolve(home, req.path || '.');
      const real = fs.existsSync(abs) ? fs.realpathSync(abs) : abs;
      if (real !== home && !real.startsWith(home + path.sep)) throw new Error('path outside home');
      const entries = fs.readdirSync(real, { withFileTypes: true })
        .filter((e) => e.isDirectory() && !e.name.startsWith('.') && e.name !== 'node_modules')
        .sort((a, b) => a.name.localeCompare(b.name))
        .slice(0, 300)
        .map((e) => ({ name: e.name, repo: fs.existsSync(path.join(real, e.name, '.git')) }));
      return { path: real, parent: real === home ? null : path.dirname(real), entries };
    }
    if (req.op === 'answer') { // reply to a prompt that is open in the live terminal
      const pane = paneForSession(req.sessionId);
      if (!pane) return { error: 'this session has no live terminal to answer in' };
      const key = String(req.key ?? '');
      if (!/^[1-9]$|^(Enter|Escape|Up|Down|y|n)$/.test(key)) return { error: 'unsupported key' };
      try {
        if (/^[1-9]$|^[yn]$/.test(key)) { tmux(['send-keys', '-t', pane.id, '-l', key]); }
        else { tmux(['send-keys', '-t', pane.id, key]); }
        log(`answered live prompt in pane ${pane.id} with "${key}"`);
        return { ok: true, pane: pane.label };
      } catch (e) { return { error: e.message } }
    }
    if (req.op === 'disconnect') { // tear this machine down, requested from the web UI
      const results = [];
      for (const key of Object.keys(INTEGRATIONS)) {
        const r = removeFor(key);
        results.push(`${INTEGRATIONS[key].name}: ${r.detail}`);
      }
      log(`disconnect requested remotely — ${results.join(' | ')}`);
      // Reply first, then stop the service. bootout terminates this process, and because
      // launchd owns it that is also what prevents KeepAlive from restarting us.
      setTimeout(() => {
        const svc = serviceFor();
        try { svc.stop(); } catch {}
        try { svc.remove(); } catch {}
        process.exit(0);
      }, 1200);
      return { ok: true, results, note: 'hooks removed; sync service stopping' };
    }
    if (req.op === 'handoff') return startHandoff(req);
    if (req.op === 'live') { // is this session reachable as a live terminal?
      const pane = paneForSession(req.sessionId);
      if (pane) return { live: true, label: pane.label };
      return { live: false, reason: terminalBackend().reason ?? null };
    }
    if (req.op === 'usage') { // account, plan limits (like Claude Code's /usage) + this session's tokens
      const s = sessions.get(req.sessionId);
      const file = s?.file || state.meta[req.sessionId]?.file;
      if (!file || !fs.existsSync(file)) return { error: 'transcript file not found' };
      const st = fs.statSync(file);
      if (st.size > 50_000_000) return { error: 'transcript too large to summarize' };
      let turns = 0, input = 0, output = 0, cacheRead = 0, cacheWrite = 0;
      const models = {};
      for (const l of fs.readFileSync(file, 'utf8').split('\n')) {
        if (!l) continue;
        let o; try { o = JSON.parse(l); } catch { continue; }
        const u = o.message?.usage;
        if (o.type === 'assistant' && u) {
          turns++;
          input += u.input_tokens ?? 0;
          output += u.output_tokens ?? 0;
          cacheRead += u.cache_read_input_tokens ?? 0;
          cacheWrite += u.cache_creation_input_tokens ?? 0;
          if (o.message.model) models[o.message.model] = (models[o.message.model] ?? 0) + 1;
        }
      }
      const lim = await claudeLimits();
      return { turns, input, output, cacheRead, cacheWrite, models, sizeKb: (st.size / 1024) | 0,
               account: claudeAccount(), limits: lim.limits ?? null, limitsError: lim.error ?? null };
    }
    const cwd = cwdForSession(req.sessionId);
    if (!cwd) return { error: 'session cwd unknown' };
    if (req.op === 'status') {
      try {
        const out = git(cwd, ['status', '--porcelain']);
        let branch = null;
        try { branch = git(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim(); } catch {}
        const files = out.split('\n').filter(Boolean).slice(0, 300)
          .map((l) => ({ st: l.slice(0, 2), path: l.slice(3).replace(/^"|"$/g, '') }));
        return { git: true, branch, files, root: cwd };
      } catch { return { git: false, root: cwd }; }
    }
    if (req.op === 'list') {
      const dir = safeResolve(cwd, req.path);
      const entries = fs.readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.name !== '.git')
        .sort((a, b) => (b.isDirectory() - a.isDirectory()) || a.name.localeCompare(b.name))
        .slice(0, 400)
        .map((e) => ({ name: e.name, dir: e.isDirectory() }));
      return { entries };
    }
    if (req.op === 'read') {
      const f = safeResolve(cwd, req.path);
      const st = fs.statSync(f);
      if (st.size > 300_000) return { error: `file too large (${(st.size / 1024) | 0} KB)` };
      const buf = fs.readFileSync(f);
      return buf.includes(0) ? { binary: true, size: st.size } : { content: buf.toString('utf8'), size: st.size };
    }
    if (req.op === 'diff') {
      let out;
      try { out = git(cwd, ['diff', 'HEAD', '--', req.path]); }
      catch { out = git(cwd, ['diff', '--', req.path]); } // no HEAD yet (fresh repo)
      if (!out.trim()) { // untracked file: render the whole thing as added
        const buf = fs.readFileSync(safeResolve(cwd, req.path));
        if (buf.includes(0)) return { binary: true };
        return { diff: buf.toString('utf8').split('\n').map((l) => '+' + l).join('\n'), untracked: true };
      }
      return { diff: out.slice(0, 300_000) };
    }
    return { error: 'unknown op' };
  }

  // ---- transport
  const transport = new Transport(
    { relayUrl: id.relay, deviceId: id.deviceId, privKey: id.priv },
    {
      onAuthed: (cursors, retainDays) => {
        relayCursors = cursors;
        syncing = true;
        syncStartedAt = Date.now();
        syncTargets = new Map();
        transport.send({ type: 'device_sync', state: 'syncing' });
        // The relay drops events past its retention window. A session it has swept has no
        // cursor, which reads as 0 — so without this we would re-upload history the relay
        // deliberately forgot, and it would sweep it again an hour later, forever. The
        // transcript's mtime is the honest answer to "has anything happened here lately".
        const floor = retainDays ? Date.now() - retainDays * 86_400_000 : 0;
        let skipped = 0;
        for (const s of sessions.values()) {
          if (floor && !cursors[s.sid]) {
            let touched = s.lastEventTs;
            try { if (!touched && s.file) touched = fs.statSync(s.file).mtimeMs; } catch {}
            if (touched && touched < floor) { skipped += 1; continue; } // older than the relay keeps
          }
          const relaySeq = cursors[s.sid] ?? 0;
          if (relaySeq > s.cursor) { resetSession(s, `relay ahead (${relaySeq} > ${s.cursor})`); continue; }
          s.ackSeq = relaySeq;
          s.inflight = false;
          s.announced = false;
          syncTargets.set(s.sid, s.cursor);
          flush(s.sid);
        }
        if (skipped) log(`${skipped} session(s) older than the relay's ${retainDays}-day window; not re-uploading them`);
        maybeSyncDone(); // handles the zero-sessions / already-caught-up case
        pushHealth();
      },
      onMessage: (m) => {
        if (m.type === 'ack') {
          const s = sessions.get(m.sessionId);
          if (s) { s.ackSeq = Math.max(s.ackSeq, m.upTo); s.inflight = false; flush(s.sid); maybeSyncDone(); }
        } else if (m.type === 'approval_result') {
          const by = m.decidedBy ?? 'remote';
          if (m.decision === 'allow' && m.answersCt) {
            // Someone answered a question in the web UI. Only the answers travelled; the
            // questions are still here, and settlePermission puts the two back together.
            try {
              const { answers } = C.decryptJSON(C.deriveKey(id.accountSecret, `approval:${m.approvalId}`), m.answersCt);
              bridge.settlePermission(m.approvalId, { behavior: 'allow', answers }, by);
            } catch (e) {
              noteError(`answer for ${m.approvalId} could not be read: ${e.message}`);
              bridge.settlePermission(m.approvalId, { behavior: 'deny', message: 'Tether could not read that answer.' }, by);
            }
          } else {
            bridge.settle(m.approvalId, m.decision === 'allow' ? 'allow' : 'deny', by);
          }
        } else if (m.type === 'prompt_execute') {
          try {
            const body = C.decryptJSON(C.deriveKey(id.accountSecret, `prompt:${m.promptId}`), m.bodyCt);
            runPrompt({ promptId: m.promptId, sessionId: m.sessionId ?? null, text: materializeImages(body, m.promptId), cwd: body.cwd ?? null, agent: body.agent ?? 'claude', opts: body.opts ?? null, live: !!body.live, interactive: !!body.interactive });
          } catch (e) {
            transport.send({ type: 'prompt_status', promptId: m.promptId, status: 'failed', detail: `decrypt: ${e.message}` });
            noteError(`prompt ${m.promptId} decrypt failed: ${e.message}`);
          }
        } else if (m.type === 'status_request') {
          pushHealth();
        } else if (m.type === 'clients_present') {
          const was = watchers;
          watchers = Number(m.watchers) || 0;
          if (!!was !== !!watchers) log(`${watchers} browser${watchers === 1 ? '' : 's'} watching`);
        } else if (m.type === 'fs_request') {
          (async () => {
            let result;
            try { result = await handleFs(C.decryptJSON(fsKey(), m.reqCt)); }
            catch (e) { result = { error: String(e.message).slice(0, 200) }; }
            try { transport.send({ type: 'fs_result', reqId: m.reqId, resultCt: C.encryptJSON(fsKey(), result) }); } catch {}
          })();
        }
      },
      onDown: () => {
        watchers = 0; // relay unreachable: never hold a local tool call hostage
        log('relay connection lost; buffering locally (files are the log)');
        health.lastError = 'relay connection lost (recovered on reconnect)';
        health.lastErrorAt = Date.now(); // reported with the next successful push
      },
    }, log);

  setInterval(pushHealth, 60_000).unref(); // heartbeat: keeps "last report" fresh in the UI
  setInterval(maybeSyncDone, 10_000).unref(); // watchdog: releases a stalled initial sync

  // ---- idle fallback for sessions without hooks (plan §3.1 state machine)
  setInterval(() => {
    const now = Date.now();
    for (const s of sessions.values()) {
      if (s.state === 'running' && !bridge.hasPendingFor(s.sid) && s.lastEventTs && now - s.lastEventTs > 90_000) {
        markState(s.sid, 'idle');
      }
    }
  }, 15_000).unref();

  bridge.start();
  tailer.start();
  transport.start();
  log(`tetherd running: device ${id.deviceId} ("${id.name}") -> ${id.relay}`);

  const bye = () => { log('shutting down'); saveJSON(STATE_PATH, state); bridge.stop(); tailer.stop(); transport.stop(); process.exit(0); };
  process.on('SIGINT', bye); process.on('SIGTERM', bye);
}

// ---------------------------------------------------------------- hooks
function hooksSnippet() {
  const exec = path.join(HERE, 'hook-exec.mjs');
  const node = process.execPath;
  const cmd = (ev) => ({ type: 'command', command: `"${node}" "${exec}" ${ev}`, timeout: ev === 'PreToolUse' ? 300 : 10 });
  return {
    // ExitPlanMode/AskUserQuestion are gates too: they surface plan approvals and
    // multiple-choice questions remotely instead of stranding them in the terminal
    PreToolUse: [{ matcher: 'Bash|Write|Edit|NotebookEdit|ExitPlanMode|AskUserQuestion', hooks: [cmd('PreToolUse')] }],
    Stop: [{ hooks: [cmd('Stop')] }],
    Notification: [{ hooks: [cmd('Notification')] }],
    UserPromptSubmit: [{ hooks: [cmd('UserPromptSubmit')] }],
  };
}

function cmdHooks() {
  const sub = process.argv[3];
  const snippet = hooksSnippet();
  if (sub === 'print' || !sub) {
    console.log(JSON.stringify({ hooks: snippet }, null, 2));
    if (!sub) console.log('\nInstall with: tetherd hooks install --settings <path to settings.json>');
    return;
  }
  if (sub !== 'install') { console.error('usage: tetherd hooks print | install --settings <path>'); process.exit(1); }
  const target = arg('--settings', null);
  if (!target) {
    console.error('Refusing to guess. Pass the settings file explicitly, e.g.:');
    console.error('  tetherd hooks install --settings ~/.claude/settings.json         # all sessions on this machine');
    console.error('  tetherd hooks install --settings <project>/.claude/settings.json # one project only');
    process.exit(1);
  }
  const abs = target.replace(/^~\//, os.homedir() + '/');
  const existing = loadJSON(abs, {});
  if (fs.existsSync(abs)) fs.copyFileSync(abs, `${abs}.tether-backup-${Date.now()}`);
  existing.hooks = existing.hooks ?? {};
  let added = 0;
  for (const [ev, entries] of Object.entries(snippet)) {
    existing.hooks[ev] = existing.hooks[ev] ?? [];
    const already = JSON.stringify(existing.hooks[ev]).includes('hook-exec.mjs');
    if (!already) { existing.hooks[ev].push(...entries); added++; }
  }
  saveJSON(abs, existing);
  console.log(added ? `Installed Tether hooks into ${abs} (${added} events; backup written alongside).`
                    : `Tether hooks already present in ${abs}; nothing changed.`);
}

// ---------------------------------------------------------------- launchd
function cmdLaunchd() {
  if (process.argv[3] !== 'install') { console.error('usage: tetherd launchd install'); process.exit(1); }
  const label = 'ai.tether.tetherd';
  const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', `${label}.plist`);
  const self = path.join(HERE, 'tetherd.mjs');
  const logPath = path.join(LOG_DIR, 'tetherd.launchd.log');
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>
    <string>${process.execPath}</string>
    <string>${self}</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${logPath}</string>
  <key>StandardErrorPath</key><string>${logPath}</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:${os.homedir()}/.local/bin:/usr/bin:/bin</string>
  </dict>
</dict></plist>\n`;
  fs.mkdirSync(path.dirname(plistPath), { recursive: true });
  fs.writeFileSync(plistPath, plist);
  console.log(`Wrote ${plistPath}`);
  console.log('Enable with:');
  console.log(`  launchctl bootstrap gui/$(id -u) ${plistPath}`);
  console.log('Disable with:');
  console.log(`  launchctl bootout gui/$(id -u)/${label}`);
}

// The relay deserves the same treatment as the daemon. Started by hand it is an orphan: if
// it crashes, or you log out, it stays down until someone notices and runs the command again
// — and a relay that is down looks exactly like a relay that was never set up.
function cmdRelayService() {
  if (process.argv[3] !== 'install' && process.argv[3] !== 'uninstall') {
    console.error('usage: tetherd relay-service install | uninstall');
    process.exit(1);
  }
  const label = 'ai.tether.relay';
  const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', `${label}.plist`);
  if (process.platform !== 'darwin') {
    console.error(`relay-service is macOS-only. On Linux, run the relay under a systemd user unit;
on Windows, register it with Task Scheduler. The command is: ${process.execPath} ${path.join(HERE, 'tetherd.mjs')} relay`);
    process.exit(1);
  }
  if (process.argv[3] === 'uninstall') {
    try { fs.unlinkSync(plistPath); console.log(`Removed ${plistPath}`); }
    catch { console.log(`No ${plistPath} to remove.`); }
    console.log('Stop it now with:');
    console.log(`  launchctl bootout gui/$(id -u)/${label}`);
    return;
  }
  const self = path.join(HERE, 'tetherd.mjs');
  const logPath = path.join(LOG_DIR, 'relay.launchd.log');
  // Env vars are read at launch, so whatever you would have exported goes in here.
  const env = { PATH: `/opt/homebrew/bin:/usr/local/bin:${os.homedir()}/.local/bin:/usr/bin:/bin` };
  for (const k of ['TETHER_DB', 'HOST', 'PORT']) if (process.env[k]) env[k] = process.env[k];
  const envXml = Object.entries(env).map(([k, v]) => `    <key>${k}</key><string>${v}</string>`).join('\n');
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>
    <string>${process.execPath}</string>
    <string>${self}</string>
    <string>relay</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${logPath}</string>
  <key>StandardErrorPath</key><string>${logPath}</string>
  <key>EnvironmentVariables</key><dict>
${envXml}
  </dict>
</dict></plist>\n`;
  fs.mkdirSync(path.dirname(plistPath), { recursive: true });
  fs.writeFileSync(plistPath, plist);
  console.log(`Wrote ${plistPath}`);
  if (env.TETHER_DB || env.HOST || env.PORT) {
    console.log(`Captured from this shell: ${['TETHER_DB', 'HOST', 'PORT'].filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join(' ')}`);
  }
  console.log('Enable with:');
  console.log(`  launchctl bootstrap gui/$(id -u) ${plistPath}`);
  console.log('Disable with:');
  console.log(`  launchctl bootout gui/$(id -u)/${label}`);
}

// ---------------------------------------------------------------- connect / disconnect
// One command to make this machine fully managed by Tether, and one to undo it cleanly:
// pair -> install hooks for every AI agent present -> register their transcript roots ->
// install and start the background sync service. Disconnect reverses each step.
const sh = (cmd, args) => { try { return { ok: true, out: execFileSync(cmd, args, { timeout: 15000 }).toString().trim() }; } catch (e) { return { ok: false, out: (e.stderr?.toString() || e.message).trim() }; } };


async function cmdConnect() {
  const code = process.argv[3];
  const already = loadJSON(ID_PATH, null);
  if (!code && !already) { console.error('usage: tetherd connect <pairing-code> [--relay url] [--name name]'); process.exit(1); }
  if (code) { await cmdPair(); } else { console.log(`Already paired as ${already.deviceId} ("${already.name}") — (re)installing integrations.`); }

  // Hooks embed an absolute path, so it must NOT point into the installed package: an
  // npm upgrade, an `npx` temp dir, or an uninstall would leave every agent calling a file
  // that no longer exists. Copy the (dependency-free) hook shim to a stable home instead.
  const hookExec = path.join(TETHER_DIR, 'bin', 'hook-exec.mjs');
  fs.mkdirSync(path.dirname(hookExec), { recursive: true });
  fs.copyFileSync(path.join(HERE, 'hook-exec.mjs'), hookExec);
  const agents = detectAgents();
  console.log(`\nAgents found: ${agents.length ? agents.map((a) => a.name).join(', ') : 'none'}`);
  const keys = [];
  for (const a of agents) {
    const r = installFor(a.key, hookExec, process.execPath);
    console.log(`  ${r.ok ? '✓' : '✗'} ${INTEGRATIONS[a.key].name}: ${r.detail}`);
    if (r.ok) keys.push(a.key);
  }

  // session context for every agent, so any of them can pick up another's chat
  for (const r of installMcpFor(keys)) console.log(`  ${r.name} (sessions MCP): ${r.detail}`);

  // watch roots: every agent whose transcripts Tether can actually tail
  const roots = rootsFor(keys);
  const cfg = loadJSON(CFG_PATH, {});
  const prev = new Set((cfg.roots ?? []).map((r) => (typeof r === 'string' ? r : r.path)));
  cfg.roots = roots.length ? roots : cfg.roots;
  saveJSON(CFG_PATH, cfg);
  // A newly added root must be read from the start. Drop any stale byte offsets under it
  // so previously-skipped transcripts are ingested instead of being treated as done.
  const fresh = roots.filter((r) => !prev.has(r.path));
  if (fresh.length) {
    const st = loadJSON(STATE_PATH, null);
    if (st?.offsets) {
      let cleared = 0;
      for (const f of Object.keys(st.offsets)) if (fresh.some((r) => f.startsWith(r.path))) { delete st.offsets[f]; cleared++; }
      if (cleared) { saveJSON(STATE_PATH, st); console.log(`  reset ${cleared} stale read offset(s) under the new root(s)`); }
    }
  }
  console.log(`\nSync roots (${roots.length}):`);
  for (const r of roots) console.log(`  ${r.agent.padEnd(8)} ${r.path}`);
  const noSync = keys.filter((k) => !(INTEGRATIONS[k].roots() ?? []).length);
  if (noSync.length) console.log(`  note: ${noSync.map((k) => INTEGRATIONS[k].name).join(', ')} expose no tailable transcript, so their chats are not mirrored (hooks still report state).`);

  const svc = serviceFor();
  const selfPath = path.join(HERE, 'tetherd.mjs');
  // The service records this script's absolute path. Run from an npx cache that directory
  // is deleted when the command exits, leaving a service that points at nothing — so say so
  // rather than installing something that breaks on the next reboot.
  if (/[\\/](_npx|\.npm[\\/]_cacache)[\\/]/.test(selfPath)) {
    console.log(`\n⚠ Running from a temporary npx directory (${selfPath}).`);
    console.log('  Hooks are installed to a stable path and will keep working, but the background');
    console.log('  service cannot be: this directory disappears when npx exits.');
    console.log(`  Install it properly first:  npm i -g ${PKG_NAME}\n`);
  }
  const unit = svc.write(process.execPath, selfPath, path.join(LOG_DIR, 'tetherd.service.log'));
  const boot = svc.start();
  console.log(`\nSync service (${svc.name}): ${boot.ok ? 'installed and started'
    : unit ? `unit written to ${unit} but not started — ${boot.out.slice(0, 140)}`
           : `not supported on ${process.platform}. Run it yourself: tetherd run`}`);
  console.log(`\nConnected. Disconnect any time with: tetherd disconnect`);
}

function cmdDisconnect() {
  const keepIdentity = !process.argv.includes('--forget');
  console.log('Disconnecting this machine from Tether…\n');

  const svc = serviceFor();
  const boot = svc.stop();
  console.log(`  ${boot.ok ? '✓' : '·'} sync service stopped${boot.ok ? '' : ' (was not running)'}`);
  if (svc.remove()) console.log(`  ✓ removed the ${svc.name} unit`);

  for (const key of Object.keys(INTEGRATIONS)) {
    const r = removeFor(key);
    console.log(`  ${r.ok ? '✓' : '✗'} ${INTEGRATIONS[key].name}: ${r.detail}`);
  }

  for (const r of removeMcpAll()) console.log(`  · ${r.name} (sessions MCP): ${r.detail}`);

  // stop any daemon still running outside launchd
  killStrays();
  console.log('  ✓ stopped any running daemon');
  try { fs.rmSync(path.join(TETHER_DIR, 'bin'), { recursive: true, force: true }); console.log('  ✓ removed the installed hook shim'); } catch {}

  if (keepIdentity) {
    console.log(`\nKept ${ID_PATH} so "tetherd connect" can re-enable everything without re-pairing.`);
    console.log('Use "tetherd disconnect --forget" to also delete the device identity and local state.');
  } else {
    for (const f of [ID_PATH, STATE_PATH]) { try { fs.unlinkSync(f); console.log(`  ✓ deleted ${f}`); } catch {} }
    console.log('\nThis machine is fully unpaired. Pair again with: tetherd connect <code>');
  }
}

// ---------------------------------------------------------------- sessions / handoff
// Continue a chat in a different agent: when Claude Code hits its limit, pick the work up in
// Cursor or Codex with the same context (and the other way round). See handoff.mjs.
const AGENT_CLI = { claude: 'claude', cursor: 'cursor-agent', codex: 'codex' };
const HEADLESS_ARGS = { claude: (t) => ['-p', t], cursor: (t) => ['-p', t], codex: (t) => ['exec', t] };
const agoText = (ms) => {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  return s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`;
};

function cmdSessions() {
  const all = process.argv.includes('--all');
  const cwd = all ? null : path.resolve(arg('--cwd', process.cwd()));
  const rows = listSessions({ cwd, agent: arg('--agent', null), limit: Number(arg('--limit', 20)) || 20 });
  if (!rows.length) {
    console.log(cwd ? `No sessions for ${cwd}. Use --all to list every project.` : 'No sessions found.');
    return;
  }
  for (const r of rows) {
    console.log(`${r.sessionId.slice(0, 8)}  ${(AGENT_NAMES[r.agent] ?? r.agent).padEnd(11)}  ${agoText(r.updatedAt).padEnd(8)}  ${r.title ?? '(untitled)'}${all && r.cwd ? `  — ${r.cwd}` : ''}`);
  }
  console.log(`\nContinue one elsewhere with: tetherd handoff <id> --to claude|cursor|codex`);
}

function cmdHandoff() {
  const ref = process.argv[3] && !process.argv[3].startsWith('--') ? process.argv[3] : 'latest';
  const target = arg('--to', null);
  if (!HANDOFF_TARGETS.includes(target)) {
    console.error('usage: tetherd handoff [<session-id>|latest] --to claude|cursor|codex [--cwd <dir>] [--note "..."] [--headless | --file-only] [--model m] [--mode acceptEdits|plan|…]');
    console.error('       (see ids with: tetherd sessions)');
    process.exit(1);
  }
  const cwdArg = arg('--cwd', null) ? path.resolve(arg('--cwd')) : null;
  let src;
  try { src = resolveSession(ref, { cwd: ref === 'latest' ? (cwdArg ?? process.cwd()) : null }); }
  catch (e) { console.error(`${e.message}. See: tetherd sessions --all`); process.exit(1); }
  const cwd = cwdArg ?? src.cwd;
  if (!cwd || !fs.existsSync(cwd)) {
    console.error(`The session's project folder is missing (${cwd ?? 'unknown'}). Pass --cwd <folder> to write the handoff there.`);
    process.exit(1);
  }
  const note = arg('--note', null);
  const h = buildHandoff({ file: src.file, agent: src.agent, sessionId: src.sessionId, cwd, title: src.title, target, note });
  const w = writeHandoff(h, cwd);
  const prompt = handoffPrompt({ relPath: w.relPath, source: src.agent, note });
  const mode = process.argv.includes('--file-only') ? 'file' : process.argv.includes('--headless') ? 'headless' : 'interactive';
  recordHandoff({ id: h.id, from: { sessionId: src.sessionId, agent: src.agent, title: src.title ?? h.summary.title }, to: { agent: target }, cwd, path: w.path, mode });
  const sm = h.summary;
  console.log(`Handoff ${h.id}: ${AGENT_NAMES[src.agent]} "${sm.title}" -> ${AGENT_NAMES[target]}`);
  console.log(`  ${sm.requests} request(s), ${sm.filesChanged} file(s) changed, ${sm.commands} command(s)${sm.compacted ? ', includes its compaction summary' : ''}${sm.limitHit ? `, stopped on: ${sm.limitHit}` : ''}`);
  console.log(`  written to ${w.path}`);
  if (mode === 'file') {
    console.log(`\nPaste this into ${AGENT_NAMES[target]}:\n\n${prompt}\n`);
    return;
  }
  const cfg = loadJSON(CFG_PATH, {});
  const bin = target === 'claude' ? (cfg.claudeBin || 'claude') : AGENT_CLI[target];
  const args = mode === 'headless' ? HEADLESS_ARGS[target](prompt) : [prompt];
  // the same runtime options the web UI offers: a model, and Claude Code's permission mode
  const model = arg('--model', null), pmode = arg('--mode', null);
  if (model && /^[A-Za-z0-9 ._\/:@,\[\]-]{1,100}$/.test(model)) args.unshift(target === 'codex' ? '-m' : '--model', model);
  if (pmode && target === 'claude') args.unshift('--permission-mode', pmode);
  console.log(`  starting ${bin}${mode === 'headless' ? ' (headless)' : ''} in ${cwd}\n`);
  const env = { ...process.env, PATH: `${process.env.PATH ?? ''}:/usr/local/bin:/opt/homebrew/bin:${path.join(os.homedir(), '.local', 'bin')}` };
  const child = spawnProcess(bin, args, { cwd, stdio: 'inherit', env });
  child.on('error', (e) => { console.error(`could not start ${bin}: ${e.message}`); process.exit(1); });
  child.on('exit', (code) => process.exit(code ?? 0));
}

// ---------------------------------------------------------------- MCP server (session context)
// `tether-sessions` gives any MCP-capable agent list_sessions / get_session_context. Like the
// hook shim it runs from ~/.tether/bin, so an npm upgrade or npx cleanup cannot break it.
const MCP_NAME = 'tether-sessions';
const MCP_FILES = ['context-mcp.mjs', 'handoff.mjs'];
const mcpEntry = () => ({ command: process.execPath, args: [path.join(TETHER_DIR, 'bin', 'context-mcp.mjs')] });
const CODEX_TOML = () => path.join(os.homedir(), '.codex', 'config.toml');
const CODEX_BEGIN = '# >>> tether-sessions (managed by tetherd)';
const CODEX_END = '# <<< tether-sessions';

function installMcpFiles() {
  const dir = path.join(TETHER_DIR, 'bin');
  fs.mkdirSync(dir, { recursive: true });
  for (const f of MCP_FILES) fs.copyFileSync(path.join(HERE, f), path.join(dir, f));
}

// Each installer returns a one-line status; none of them touches anything but our own entry.
const MCP_INSTALLERS = {
  claude: {
    name: 'Claude Code',
    install() {
      const cfg = loadJSON(CFG_PATH, {});
      const bin = cfg.claudeBin || 'claude';
      sh(bin, ['mcp', 'remove', '--scope', 'user', MCP_NAME]); // re-add fresh: the path may have moved
      const e = mcpEntry();
      const r = sh(bin, ['mcp', 'add', '--scope', 'user', MCP_NAME, '--', e.command, ...e.args]);
      return r.ok ? `added "${MCP_NAME}" (user scope)` : `failed: ${r.out.slice(0, 160)}`;
    },
    remove() {
      const cfg = loadJSON(CFG_PATH, {});
      const r = sh(cfg.claudeBin || 'claude', ['mcp', 'remove', '--scope', 'user', MCP_NAME]);
      return r.ok ? `removed "${MCP_NAME}"` : 'not installed';
    },
  },
  cursor: {
    name: 'Cursor',
    file: () => path.join(os.homedir(), '.cursor', 'mcp.json'),
    install() {
      const f = this.file();
      const cfg = loadJSON(f, {});
      if (fs.existsSync(f)) fs.copyFileSync(f, `${f}.tether-backup-${Date.now()}`);
      cfg.mcpServers = { ...(cfg.mcpServers ?? {}), [MCP_NAME]: mcpEntry() };
      saveJSON(f, cfg);
      return `added "${MCP_NAME}" -> ${f}`;
    },
    remove() {
      const f = this.file();
      const cfg = loadJSON(f, null);
      if (!cfg?.mcpServers?.[MCP_NAME]) return 'not installed';
      fs.copyFileSync(f, `${f}.tether-backup-${Date.now()}`);
      delete cfg.mcpServers[MCP_NAME];
      saveJSON(f, cfg);
      return `removed "${MCP_NAME}" from ${f}`;
    },
  },
  codex: {
    name: 'Codex',
    install() {
      const f = CODEX_TOML();
      let txt = ''; try { txt = fs.readFileSync(f, 'utf8'); } catch {}
      if (txt) fs.copyFileSync(f, `${f}.tether-backup-${Date.now()}`);
      txt = stripCodexBlock(txt);
      const e = mcpEntry();
      const block = `${CODEX_BEGIN}\n[mcp_servers.${MCP_NAME}]\ncommand = ${JSON.stringify(e.command)}\nargs = [${e.args.map((a) => JSON.stringify(a)).join(', ')}]\n${CODEX_END}\n`;
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, `${txt}${txt && !txt.endsWith('\n') ? '\n' : ''}${txt ? '\n' : ''}${block}`);
      return `added [mcp_servers.${MCP_NAME}] -> ${f}`;
    },
    remove() {
      const f = CODEX_TOML();
      let txt; try { txt = fs.readFileSync(f, 'utf8'); } catch { return 'not installed'; }
      if (!txt.includes(CODEX_BEGIN)) return 'not installed';
      fs.copyFileSync(f, `${f}.tether-backup-${Date.now()}`);
      fs.writeFileSync(f, stripCodexBlock(txt));
      return `removed [mcp_servers.${MCP_NAME}] from ${f}`;
    },
  },
};
function stripCodexBlock(txt) {
  const a = txt.indexOf(CODEX_BEGIN), b = txt.indexOf(CODEX_END);
  if (a < 0 || b < 0) return txt;
  return (txt.slice(0, a) + txt.slice(b + CODEX_END.length).replace(/^\n/, '')).replace(/\n{3,}$/, '\n\n');
}

function installMcpFor(keys) {
  installMcpFiles();
  return keys.filter((k) => MCP_INSTALLERS[k]).map((k) => {
    let detail; try { detail = MCP_INSTALLERS[k].install(); } catch (e) { detail = `failed: ${e.message}`; }
    return { key: k, name: MCP_INSTALLERS[k].name, detail };
  });
}
function removeMcpAll() {
  return Object.entries(MCP_INSTALLERS).map(([k, m]) => {
    let detail; try { detail = m.remove(); } catch (e) { detail = `failed: ${e.message}`; }
    return { key: k, name: m.name, detail };
  });
}

function cmdMcp() {
  const sub = process.argv[3];
  if (sub === 'print' || !sub) {
    console.log(JSON.stringify({ mcpServers: { [MCP_NAME]: mcpEntry() } }, null, 2));
    if (!sub) console.log('\nInstall into every agent found with: tetherd mcp install   (or --for claude,cursor,codex)');
    return;
  }
  if (sub === 'install') {
    const only = arg('--for', null);
    const keys = only ? only.split(',').map((x) => x.trim()) : detectAgents().map((a) => a.key);
    for (const r of installMcpFor(keys)) console.log(`  ${r.name}: ${r.detail}`);
    console.log(`\nIn any of them, ask: "load my latest Claude Code session for this project" (tools: list_sessions, get_session_context).`);
    return;
  }
  if (sub === 'uninstall') {
    for (const r of removeMcpAll()) console.log(`  ${r.name}: ${r.detail}`);
    return;
  }
  console.error('usage: tetherd mcp print | install [--for claude,cursor,codex] | uninstall');
  process.exit(1);
}

// ---------------------------------------------------------------- relay (self-hosting)
// The same package can run the server side, so a self-hoster installs one thing:
//   tetherd relay            -> http://127.0.0.1:8787
//   HOST=0.0.0.0 PORT=443 tetherd relay
function cmdRelay() {
  const server = path.join(HERE, '..', 'relay', 'server.mjs');
  if (!fs.existsSync(server)) { console.error('relay/server.mjs is missing from this install'); process.exit(1); }
  const child = spawnProcess(process.execPath, [server, ...process.argv.slice(3)], { stdio: 'inherit', env: process.env });
  child.on('exit', (code) => process.exit(code ?? 0));
}

// ---------------------------------------------------------------- status
function cmdStatus() {
  const id = loadJSON(ID_PATH, null);
  if (!id) { console.log('not paired'); return; }
  console.log(`device   ${id.deviceId} ("${id.name}")`);
  console.log(`relay    ${id.relay}`);
  const st = loadJSON(STATE_PATH, null);
  console.log(`sessions tracked: ${st ? Object.keys(st.cursors ?? {}).length : 0}`);
  try {
    const m = fs.statSync(STATE_PATH).mtimeMs;
    console.log(`state.json last written ${Math.round((Date.now() - m) / 1000)}s ago`);
  } catch { console.log('daemon has not run yet'); }
}

// ---------------------------------------------------------------- main
const cmd = process.argv[2];
if (cmd === 'pair') cmdPair();
else if (cmd === 'run') cmdRun();
else if (cmd === 'hooks') cmdHooks();
else if (cmd === 'launchd') cmdLaunchd();
else if (cmd === 'relay') cmdRelay();
else if (cmd === 'relay-service') cmdRelayService();
else if (cmd === 'connect') cmdConnect();
else if (cmd === 'disconnect') cmdDisconnect();
else if (cmd === 'status') cmdStatus();
else if (cmd === 'sessions') cmdSessions();
else if (cmd === 'handoff') cmdHandoff();
else if (cmd === 'mcp') cmdMcp();
else {
  console.log('tetherd — mirror & control local agent sessions remotely');
  console.log('usage: tetherd pair <code> [--relay url] [--name name]');
  console.log('       tetherd run');
  console.log('       tetherd connect <pairing-code>   # pair + install agent hooks + start sync');
  console.log('       tetherd disconnect [--forget]    # remove hooks, stop and remove sync');
  console.log('       tetherd relay                    # self-host the relay + web UI');
  console.log('       tetherd relay-service install    # keep the relay running (macOS launchd)');
  console.log('       tetherd hooks print | install --settings <path>');
  console.log('       tetherd launchd install');
  console.log('       tetherd status');
  console.log('       tetherd sessions [--all]              # chats on this machine');
  console.log('       tetherd handoff [<id>|latest] --to claude|cursor|codex [--note ".."] [--headless|--file-only]');
  console.log('       tetherd mcp print | install | uninstall   # let any agent load another\'s session');
  process.exit(cmd ? 1 : 0);
}
