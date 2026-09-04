// Tether client app. All transcript/meta/approval/prompt payloads are decrypted
// locally with keys derived from the account secret in localStorage (plan §6).
import { b64u, sha256hex, randBytes, randHex, deriveKey, encryptJSON, decryptJSON, passKeys, wrapSecret, unwrapSecret } from '/crypto.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let cfg = null;
try { cfg = JSON.parse(localStorage.getItem('tether') ?? 'null'); } catch {}

const S = {
  ws: null, connected: false,
  devices: new Map(),            // id -> {id,name,platform,online}
  sessions: new Map(),           // "dev/sid" -> {deviceId,sessionId,agent,state,meta,updatedAt}
  events: new Map(),             // key -> sorted array of decrypted events {seq,ts,kind,text,...}
  approvals: new Map(),          // id -> {approvalId,deviceId,sessionId,deadline,req}
  current: null,                 // key
  queueNotes: new Map(),         // promptId -> detail
  follow: true,                  // pinned to the latest message; false once the user scrolls up
  health: new Map(),             // deviceId -> decrypted daemon health report (or null)
  agentOpts: new Map(),          // session key -> chosen runtime options (model, mode, …)
  agentInfo: new Map(),          // deviceId -> detected agent CLIs + their live model lists
  pendingStates: new Map(),      // key -> state seen before the session snapshot arrived
  agentFilter: 'all',            // sidebar filter: 'all' or an agent key
};
const keyOf = (deviceId, sessionId) => `${deviceId}/${sessionId}`;
// the published package users install to connect a machine
const TETHERD_PKG = '@astrakratos/tetherd';

// ---------------------------------------------------------------- setup
function saveCfg() {
  try { localStorage.setItem('tether', JSON.stringify(cfg)); }
  catch { alert('Heads up: this browser is blocking site storage (private window?). Tether will work until you close the tab, then you will need to sign in again.'); }
}
function readCreds(err) {
  const email = $('setupEmail').value.trim().toLowerCase();
  const password = $('setupPass').value;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { err('Enter a valid email.'); return null; }
  if (password.length < 8) { err('Password must be at least 8 characters.'); return null; }
  return { email, password };
}

async function createAccount() {
  const err = (t) => { $('setupErr').textContent = t; };
  err('');
  const creds = readCreds(err);
  if (!creds) return;
  const btn = $('createBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    const name = $('setupName').value.trim() || 'me';
    const accountId = randHex(16);
    const accountSecret = b64u.enc(randBytes(32));
    // the password never leaves this browser: it derives an auth hash (sent) and a
    // wrap key (kept) that seals the e2e account key into keyCt for the relay to hold
    const passSalt = b64u.enc(randBytes(16));
    const { authHash, wrapKey } = await passKeys(creds.email, creds.password, passSalt);
    const keyCt = await wrapSecret(wrapKey, accountSecret);
    const res = await fetch('/api/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ accountId, name, email: creds.email, passSalt, authHash, keyCt }),
    });
    if (!res.ok) return err(`Could not register: ${(await res.json().catch(() => ({}))).error ?? res.status}`);
    const { clientToken } = await res.json();
    cfg = { accountId, accountSecret, clientToken, name, email: creds.email };
    saveCfg();
    boot();
  } catch (e) {
    err(`Sign up failed: ${e.message}. Is the relay reachable?`);
  } finally {
    btn.disabled = false;
  }
}

async function signIn() {
  const err = (t) => { $('setupErr').textContent = t; };
  err('');
  const creds = readCreds(err);
  if (!creds) return;
  const btn = $('signinBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    const name = $('setupName').value.trim() || 'device';
    const saltRes = await fetch('/api/login-salt', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: creds.email }),
    });
    if (!saltRes.ok) return err(`Sign in failed: ${(await saltRes.json().catch(() => ({}))).error ?? saltRes.status}`);
    const { passSalt } = await saltRes.json();
    const { authHash, wrapKey } = await passKeys(creds.email, creds.password, passSalt);
    const res = await fetch('/api/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: creds.email, authHash, name }),
    });
    if (!res.ok) return err(`Sign in failed: ${(await res.json().catch(() => ({}))).error ?? res.status}`);
    const { accountId, clientToken, keyCt } = await res.json();
    let accountSecret;
    try { accountSecret = await unwrapSecret(wrapKey, keyCt); }
    catch { return err('Could not unlock your encryption key with that password — contact the account owner.'); }
    cfg = { accountId, accountSecret, clientToken, name, email: creds.email };
    saveCfg();
    boot();
  } catch (e) {
    err(`Sign in failed: ${e.message}. Is the relay reachable?`);
  } finally {
    btn.disabled = false;
  }
}

// attach an email login to a legacy (code-only) account, from the Link dialog
async function attachEmailLogin() {
  const msg = $('attachMsg');
  const email = $('attachEmail').value.trim().toLowerCase();
  const password = $('attachPass').value;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { msg.textContent = 'Enter a valid email.'; return; }
  if (password.length < 8) { msg.textContent = 'Password must be at least 8 characters.'; return; }
  const passSalt = b64u.enc(randBytes(16));
  const { authHash, wrapKey } = await passKeys(email, password, passSalt);
  const keyCt = await wrapSecret(wrapKey, cfg.accountSecret);
  const res = await fetch('/api/account/email', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.clientToken}`, 'x-account-id': cfg.accountId },
    body: JSON.stringify({ email, passSalt, authHash, keyCt }),
  });
  if (!res.ok) { msg.textContent = `Failed: ${(await res.json().catch(() => ({}))).error ?? res.status}`; return; }
  cfg.email = email;
  saveCfg();
  msg.textContent = `✓ Saved — you can now sign in anywhere as ${email}.`;
}

async function loginWithCode() {
  const err = (t) => { $('setupErr').textContent = t; };
  err('');
  const code = $('loginCode').value.trim();
  const name = $('setupName').value.trim() || 'linked-device';
  if (!code.startsWith('TETHERC.')) return err('That is not a login code (expected TETHERC.…)');
  let parsed;
  try { parsed = JSON.parse(new TextDecoder().decode(b64u.dec(code.slice('TETHERC.'.length)))); }
  catch { return err('Malformed login code.'); }
  const btn = $('loginBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    const res = await fetch('/api/client-link/redeem', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ accountId: parsed.a, linkToken: parsed.t, name }),
    });
    if (!res.ok) return err(`Login failed: ${(await res.json().catch(() => ({}))).error ?? res.status}`);
    const { clientToken, email } = await res.json();
    cfg = { accountId: parsed.a, accountSecret: parsed.k, clientToken, name, email: email ?? undefined };
    try { localStorage.setItem('tether', JSON.stringify(cfg)); }
    catch { alert('Heads up: this browser is blocking site storage (private window?). Tether will work until you close the tab, then you will need to log in again with a link code.'); }
    boot();
  } catch (e) {
    err(`Login failed: ${e.message}. Is the relay reachable?`);
  } finally {
    btn.disabled = false;
  }
}

async function openLink() {
  const linkToken = b64u.enc(randBytes(16));
  const res = await fetch('/api/client-links', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.clientToken}`, 'x-account-id': cfg.accountId },
    body: JSON.stringify({ codeHash: await sha256hex(linkToken) }),
  });
  if (!res.ok) return alert('could not create login code');
  const code = 'TETHERC.' + b64u.enc(new TextEncoder().encode(JSON.stringify({ a: cfg.accountId, k: cfg.accountSecret, t: linkToken })));
  $('linkCode').textContent = code;
  $('linkCopy').onclick = () => navigator.clipboard.writeText(code);
  linkDlg.showModal();
}

// ---------------------------------------------------------------- ws
let reconnT = null;
function connect() {
  clearTimeout(reconnT);
  // drop any previous socket without letting its close handler schedule a rival retry
  try { if (S.ws && S.ws.readyState <= 1) { S.ws.onclose = null; S.ws.close(); } } catch {}
  const ws = new WebSocket(`${location.origin.replace(/^http/, 'ws')}/ws`);
  S.ws = ws;
  ws.onmessage = async (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'challenge') return ws.send(JSON.stringify({ type: 'auth', role: 'client', accountId: cfg.accountId, clientToken: cfg.clientToken, name: cfg.name }));
    if (m.type === 'ping') return ws.send(JSON.stringify({ type: 'pong' }));
    try { await handle(m); } catch (e) { console.error('handle', m.type, e); }
  };
  ws.onclose = () => { setConn(false); reconnT = setTimeout(connect, 2000); };
  ws.onerror = () => {};
}
// waking from sleep / regaining focus: reconnect immediately instead of waiting out the timer
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && cfg && (!S.ws || S.ws.readyState > 1)) connect();
});
const send = (obj) => { if (S.ws?.readyState === 1) S.ws.send(JSON.stringify(obj)); };
function updateLive() {
  const t = document.querySelector('.live-t');
  if (!t) return;
  if (!S.connected) { t.textContent = 'offline'; return; }
  const n = [...S.devices.values()].filter((d) => d.online).length;
  t.textContent = n ? `${n} online` : (S.devices.size ? 'all machines offline' : 'live');
}
function setConn(on) {
  S.connected = on;
  $('connDot').className = `dot ${on ? 'on' : 'off'}`;
  const b = $('connBanner');
  if (b) b.hidden = on;
  updateLive();
  if ($('statusDlg')?.open) renderStatusDlg();
}

// ---------------------------------------------------------------- message handling
async function decMeta(sessionId, metaCt) {
  if (!metaCt) return {};
  try { return await decryptJSON(await deriveKey(cfg.accountSecret, `session:${sessionId}`), metaCt); }
  catch { return { title: '(cannot decrypt — key mismatch)' }; }
}
async function decHealth(deviceId, healthCt) {
  if (!healthCt) return null;
  try { return await decryptJSON(await deriveKey(cfg.accountSecret, `health:${deviceId}`), healthCt); }
  catch { return null; }
}

async function handle(m) {
  switch (m.type) {
    case 'authed': setConn(true); break;
    case 'fleet': {
      S.devices.clear(); S.sessions.clear(); S.approvals.clear();
      for (const d of m.devices) {
        S.devices.set(d.id, d);
        if (d.healthCt) S.health.set(d.id, await decHealth(d.id, d.healthCt));
      }
      const askOf = async (sid, noteCt) => { // an open question carried in the snapshot
        if (!noteCt) return null;
        try {
          const n = await decryptJSON(await deriveKey(cfg.accountSecret, `session:${sid}`), noteCt);
          return { message: n.message || 'Waiting for your input.', tool: n.tool ?? null,
                   screen: n.screen ?? null, options: n.options ?? null,
                   answerable: !!n.answerable, pane: n.pane ?? null, reason: n.reason ?? null };
        } catch { return null; }
      };
      for (const s of m.sessions) {
        S.sessions.set(keyOf(s.deviceId, s.sessionId),
          { ...s, meta: await decMeta(s.sessionId, s.metaCt), ask: await askOf(s.sessionId, s.noteCt) });
      }
      for (const a of m.approvals) await addApproval(a, { silent: true });
      for (const [k, st] of S.pendingStates) { const ps = S.sessions.get(k); if (ps) ps.state = st; }
      S.pendingStates.clear(); // anything still unmatched was not a real session
      renderFleet(); renderApprovals(); updateAttention();
      if (S.current) subscribe(S.current);
      break;
    }
    case 'device_presence': {
      const d = S.devices.get(m.deviceId);
      if (d) {
        d.online = m.online;
        if ('syncing' in m) d.syncing = m.syncing;
        if (m.lastSeen) d.lastSeen = m.lastSeen;
        renderFleet();
        if ($('statusDlg')?.open) renderStatusDlg();
      }
      break;
    }
    case 'device_health': {
      const d = S.devices.get(m.deviceId);
      if (d) d.healthAt = m.at;
      S.health.set(m.deviceId, await decHealth(m.deviceId, m.healthCt));
      if ($('statusDlg')?.open) renderStatusDlg();
      break;
    }
    case 'fs_result': {
      const p = INSP.pending.get(m.reqId);
      if (!p) break;
      INSP.pending.delete(m.reqId);
      clearTimeout(p.to);
      if (m.error) { p.resolve({ error: m.error }); break; }
      try { p.resolve(await decryptJSON(await deriveKey(cfg.accountSecret, `fs:${p.deviceId}`), m.resultCt)); }
      catch { p.resolve({ error: 'decrypt failed' }); }
      break;
    }
    case 'device_sync': {
      const d = S.devices.get(m.deviceId);
      if (d) { d.syncing = m.syncing; renderFleet(); }
      break;
    }
    case 'session_upsert': {
      const k = keyOf(m.deviceId, m.sessionId);
      S.sessions.set(k, { deviceId: m.deviceId, sessionId: m.sessionId, agent: m.agent, state: m.state, updatedAt: m.updatedAt, meta: await decMeta(m.sessionId, m.metaCt) });
      if (S.pendingStates.has(k)) { S.sessions.get(k).state = S.pendingStates.get(k); S.pendingStates.delete(k); }
      renderFleet();
      if (S.current === k) { renderPaneHeader(); redrawAgentOpts(); } // model may have changed
      break;
    }
    case 'state_change': {
      const k = keyOf(m.deviceId, m.sessionId);
      const s = S.sessions.get(k);
      // A state change can arrive for a session we have no record of (a sub-agent, or one
      // the daemon learned about from a hook). Never invent a sidebar row for it: park the
      // state and let the authoritative snapshot decide whether the session is real.
      if (!s) { S.pendingStates.set(k, m.state); send({ type: 'refresh' }); break; }
      s.state = m.state; s.updatedAt = Date.now();
      let note = null;
      if (m.noteCt) {
        try { note = await decryptJSON(await deriveKey(cfg.accountSecret, `session:${m.sessionId}`), m.noteCt); } catch {}
      }
      // remember WHAT it is waiting for, so the pane can show the question itself
      if (m.state === 'waiting_input') s.ask = { message: note?.message || 'The session is waiting for your input.',
                                                 tool: note?.tool ?? null, screen: note?.screen ?? null,
                                                 options: note?.options ?? null,
                                                 answerable: !!note?.answerable, pane: note?.pane ?? null, reason: note?.reason ?? null };
      else delete s.ask;
      renderFleet(); renderApprovals();
      if (S.current === k) { renderPaneHeader(); renderTranscript(); } // show/hide the responding row
      if (S.current === k && m.state === 'idle' && INSP.open) refreshChanges();
      if (note && (m.state === 'waiting_input' || m.state === 'idle')) {
        notify(`${sessName(s) ?? m.sessionId}: ${m.state === 'idle' ? 'finished' : 'needs input'}`, note.message ?? '',
               { urgent: m.state === 'waiting_input' });
      }
      break;
    }
    case 'events': {
      const k = keyOf(m.deviceId, m.sessionId);
      const key = await deriveKey(cfg.accountSecret, `session:${m.sessionId}`);
      const list = S.events.get(k) ?? [];
      const have = new Set(list.map((e) => e.seq));
      for (const raw of m.events) {
        if (have.has(raw.seq)) continue;
        let ev;
        try { ev = { seq: raw.seq, ts: raw.ts, ...(await decryptJSON(key, raw.ct)) }; }
        catch { ev = { seq: raw.seq, ts: raw.ts, kind: 'system', text: '(cannot decrypt event)' }; }
        list.push(ev);
      }
      list.sort((a, b) => a.seq - b.seq);
      S.events.set(k, list);
      if (S.current === k) renderTranscript(!m.earlier);
      break;
    }
    case 'session_reset': {
      S.events.delete(keyOf(m.deviceId, m.sessionId));
      if (S.current === keyOf(m.deviceId, m.sessionId)) renderTranscript();
      break;
    }
    case 'approval_open': await addApproval(m); break;
    case 'approval_resolved': {
      S.approvals.delete(m.approvalId);
      renderApprovals(); renderFleet();
      break;
    }
    case 'prompt_status': {
      if (m.status === 'queued') S.queueNotes.set(m.promptId, m.detail ?? 'queued');
      else S.queueNotes.delete(m.promptId);
      if (m.status === 'failed') notify('Prompt failed', m.detail ?? '');
      renderQueueNote();
      break;
    }
    case 'error': console.warn('relay error:', m.message); break;
  }
}

async function addApproval(a, { silent = false } = {}) {
  let req = {};
  try { req = await decryptJSON(await deriveKey(cfg.accountSecret, `approval:${a.approvalId}`), a.requestCt); } catch {}
  S.approvals.set(a.approvalId, { ...a, req });
  renderApprovals(); renderFleet();
  if (!silent) {
    const s = S.sessions.get(keyOf(a.deviceId, a.sessionId));
    notify(`Approval needed: ${req.toolName ?? 'tool'}`, `${sessName(s) ?? a.sessionId} — ${previewInput(req)}`, { urgent: true });
  }
}

// ---------------------------------------------------------------- rendering
// Which coding agent produced a session — identified by its own mark for clear differentiation.
// Real product logos (app/agents/) are drawn as tiny app-icon tiles to attribute the source
// tool of each chat; inline glyphs remain only for agents without a bundled image.
const G = {
  devin: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M12 2.8l8.2 4.6v9.2L12 21.2l-8.2-4.6V7.4z"/><path d="M12 12l8.2-4.6M12 12v9.2M12 12L3.8 7.4"/></svg>',
  gemini: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2c.7 5.2 3.1 7.6 8 8-4.9.4-7.3 2.8-8 8-.7-5.2-3.1-7.6-8-8 4.9-.4 7.3-2.8 8-8z"/></svg>',
  aider: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 4l7 16M12 4L5 20M7.5 14h9"/></svg>',
  other: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="7" cy="12" r="2"/><circle cx="17" cy="12" r="2"/></svg>',
};
const AGENTS = {
  claude:   { name: 'Claude Code', color: '#E0785B', img: 'agents/claude-code.png' },
  codex:    { name: 'Codex',       color: '#7B8CFF', img: 'agents/codex.webp' },
  cursor:   { name: 'Cursor',      color: '#C7CED8', img: 'agents/cursor.png' },
  windsurf: { name: 'Windsurf',    color: '#2FBFA5', img: 'agents/windsurf.png' },
  opencode: { name: 'OpenCode',    color: '#C9D2DB', img: 'agents/opencode.webp' },
  devin:    { name: 'Devin',       color: '#7C93FF', glyph: G.devin },
  gemini:   { name: 'Gemini CLI',  color: '#77A7FF', glyph: G.gemini },
  aider:    { name: 'Aider',       color: '#33C7AC', glyph: G.aider },
  other:    { name: 'Agent',       color: '#8493A0', glyph: G.other },
};
const agentDef = (a) => AGENTS[a] ?? AGENTS.other;
function agentChip(a, full = false) {
  const d = agentDef(a);
  const mark = d.img ? `<img src="${d.img}" alt="">` : d.glyph;
  return `<span class="achip" style="--ac:${d.color}" title="${esc(d.name)}"><span class="amono${d.img ? ' aimg' : ''}">${mark}</span>${full ? `<span class="aname">${esc(d.name)}</span>` : ''}</span>`;
}

const sessName = (s) => s ? (s.meta?.title || ((s.meta?.projectCwd || s.meta?.cwd) ? (s.meta.projectCwd || s.meta.cwd).split('/').pop() : null) || s.sessionId.slice(0, 8)) : null;

// Where a session was started: its working directory (repo folder emphasized) and git branch.
function sessOrigin(s) {
  const cwd = s.meta?.projectCwd || s.meta?.cwd; // the project, not a drifted shell cwd
  if (!cwd) return '';
  const p = shortPath(cwd);
  const i = p.lastIndexOf('/');
  const dir = i >= 0 ? p.slice(0, i + 1) : '';
  const repo = i >= 0 ? p.slice(i + 1) : p;
  const branch = s.meta?.gitBranch ? `<span class="obranch">⎇ ${esc(s.meta.gitBranch)}</span>` : '';
  return `<span class="origin mono" title="${esc(cwd)}"><span class="opath">${esc(dir)}</span><span class="orepo">${esc(repo)}</span>${branch}</span>`;
}
const STATE_LABEL = { running: 'running', idle: 'idle', waiting_approval: 'needs approval', waiting_input: 'needs input', completed: 'done' };
const STATE_RANK = { waiting_approval: 0, waiting_input: 1, running: 2, idle: 3, completed: 4 };

function timeago(t) {
  if (!t) return '';
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return `${s | 0}s`;
  if (s < 3600) return `${(s / 60) | 0}m`;
  if (s < 86400) return `${(s / 3600) | 0}h`;
  return `${(s / 86400) | 0}d`;
}

// Sidebar filter: one chip per agent that actually has sessions, so chat history can be
// browsed per tool (Claude, Cursor, Codex, OpenCode, …).
function renderAgentFilter() {
  const el = $('agentFilter');
  if (!el) return;
  const counts = {};
  for (const s of S.sessions.values()) { const a = s.agent ?? 'other'; counts[a] = (counts[a] ?? 0) + 1; }
  const keys = Object.keys(counts).sort((a, b) => counts[b] - counts[a] || a.localeCompare(b));
  if (keys.length < 2) { el.hidden = true; el.innerHTML = ''; return; } // nothing to choose between
  if (S.agentFilter !== 'all' && !counts[S.agentFilter]) S.agentFilter = 'all';
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const chip = (key, label, n, mark) =>
    `<button type="button" class="fchip ${S.agentFilter === key ? 'sel' : ''}" data-a="${esc(key)}" title="${esc(label)}">
      ${mark}<span class="fname">${esc(label)}</span><span class="fn">${n}</span></button>`;
  el.hidden = false;
  el.innerHTML = chip('all', 'All', total, '')
    + keys.map((k) => {
        const d = agentDef(k);
        const mark = d.img ? `<img src="${d.img}" alt="">` : `<span class="amono" style="--ac:${d.color}">${d.glyph}</span>`;
        return chip(k, d.name, counts[k], mark);
      }).join('');
  el.querySelectorAll('.fchip').forEach((b) => b.addEventListener('click', () => {
    S.agentFilter = b.dataset.a;
    try { localStorage.setItem('tether.agentFilter', S.agentFilter); } catch {}
    renderFleet();
  }));
}
try { S.agentFilter = localStorage.getItem('tether.agentFilter') || 'all'; } catch {}

// One dot says everything about a machine:
//   green  — connected and in sync
//   yellow — reachable but not fully healthy (catching up, or the daemon reported an error)
//   red    — not connected
function deviceDot(d) {
  const h = S.health.get(d.id);
  const staleHealth = d.online && d.healthAt && Date.now() - d.healthAt > 5 * 60_000;
  let cls = 'off', why = 'offline — the daemon on this machine is not connected';
  if (d.online) {
    if (d.syncing) { cls = 'warn'; why = 'catching up — mirroring this machine’s sessions'; }
    else if (h?.lastError) { cls = 'warn'; why = `last error: ${h.lastError}`; }
    else if (staleHealth) { cls = 'warn'; why = 'connected, but the daemon has not reported in for a while'; }
    else { cls = 'on'; why = 'connected and in sync'; }
  }
  return `<span class="dot ${cls}" title="${esc(why)}"></span>`;
}

function renderFleet() {
  const el = $('fleet');
  renderAgentFilter();
  const byDev = new Map();
  for (const s of S.sessions.values()) {
    if (S.agentFilter !== 'all' && (s.agent ?? 'other') !== S.agentFilter) continue;
    if (!byDev.has(s.deviceId)) byDev.set(s.deviceId, []);
    byDev.get(s.deviceId).push(s);
  }
  let html = '';
  for (const [id, d] of S.devices) {
    const sess = (byDev.get(id) ?? []).sort((a, b) =>
      (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9) || (b.updatedAt ?? 0) - (a.updatedAt ?? 0)).slice(0, 200);
    const statusEl = deviceDot(d);
    const seen = !d.online && d.lastSeen ? `<span class="lastseen">offline · ${timeago(d.lastSeen)}</span>` : '';
    html += `<div class="device"><div class="device-h">${statusEl}<span class="dname">${esc(d.name)}</span>${seen} <span class="plat">${esc(d.platform ?? '')}</span><button class="dstat" data-d="${esc(id)}" title="Status &amp; diagnostics"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11.5V16"/></svg></button></div>`;
    for (const s of sess) {
      const k = keyOf(s.deviceId, s.sessionId);
      html += `<button class="sess ${S.current === k ? 'current' : ''}" data-k="${esc(k)}">
        ${agentChip(s.agent)}
        <span class="smain">
          <span class="srow">
            <span class="name">${esc(sessName(s))}</span>
            <span class="pill ${esc(s.state)}">${esc(STATE_LABEL[s.state] ?? s.state)}</span>
            <span class="when">${timeago(s.updatedAt)}</span>
          </span>
          ${sessOrigin(s)}
        </span></button>`;
    }
    if (!sess.length) html += `<p class="hint" style="padding:2px 8px 4px">${d.syncing ? 'loading sessions…' : (d.online ? 'no sessions yet' : 'offline — start tetherd on this machine')}</p>`;
    html += `</div>`;
  }
  if (!S.devices.size) html = `<p class="hint" style="padding:8px">No machines paired yet. Click “Pair a machine”.</p>`;
  el.innerHTML = html;
  el.querySelectorAll('.sess').forEach((b) => b.addEventListener('click', () => select(b.dataset.k)));
  el.querySelectorAll('.dstat').forEach((b) => b.addEventListener('click', () => openStatus(b.dataset.d)));
  updateLive();
}

// ---------------------------------------------------------------- device status panel
let statusDev = null;
function openStatus(deviceId) {
  statusDev = deviceId;
  send({ type: 'device_ping', deviceId }); // fresh presence + a health report if the daemon is up
  renderStatusDlg();
  $('statusDlg').showModal();
}
const stRow = (k, v, cls = '') => `<div class="strow"><span class="stk">${k}</span><span class="stv ${cls}">${v}</span></div>`;
function fmtDur(ms) {
  const s = Math.max(0, ms / 1000) | 0;
  if (s < 90) return `${s}s`;
  const m = (s / 60) | 0;
  if (m < 120) return `${m}m`;
  const h = (m / 60) | 0;
  return h < 48 ? `${h}h ${m % 60}m` : `${(h / 24) | 0}d ${h % 24}h`;
}
function renderStatusDlg() {
  const d = statusDev ? S.devices.get(statusDev) : null;
  if (!d) return;
  $('stTitle').textContent = `${d.name} — status`;
  const h = S.health.get(statusDev);
  let rows = stRow('Browser ↔ relay', S.connected ? 'connected' : 'reconnecting…', S.connected ? 'ok' : 'bad');
  rows += stRow('Relay ↔ daemon', d.online ? (d.syncing ? 'online · syncing' : 'online') : 'offline', d.online ? 'ok' : 'bad');
  if (d.lastSeen) rows += stRow('Last seen', `${timeago(d.lastSeen)} ago`);
  if (h) {
    rows += stRow('Daemon uptime', fmtDur(Date.now() - h.startedAt));
    rows += stRow('Version · pid', `${esc(String(h.version ?? '?'))} · ${h.pid ?? '?'}`);
    rows += stRow('Watched roots', h.roots ?? '?');
    rows += stRow('Sessions tracked', h.sessions ?? '?');
    if (d.healthAt) rows += stRow('Health reported', `${timeago(d.healthAt)} ago`);
    rows += h.lastError
      ? stRow('Last error', `${esc(h.lastError)}<br><span class="stwhen">${timeago(h.lastErrorAt)} ago</span>`, 'warn')
      : stRow('Last error', 'none', 'ok');
  } else {
    rows += stRow('Daemon health', 'no report yet (daemon predates health reports, or never connected)', 'warn');
  }
  let help = '';
  if (!d.online) {
    help = `<p class="dlg-p">The daemon isn't connected to the relay, so it can't be revived from here. On <b>${esc(d.name)}</b>:</p>
      <pre class="wrap">tetherd status
tetherd run          # or: tetherd launchd install</pre>
      <p class="dlg-p">Logs: <code>~/.tether/logs/tetherd.log</code></p>`;
  } else if (!S.connected) {
    help = `<p class="dlg-p">Your browser lost the relay — use “Reconnect now” in the banner above.</p>`;
  }
  $('stBody').innerHTML = rows + help;
}

// ---------------------------------------------------------------- workspace inspector
// VS Code-style right panel: collapsible Changes (git) + Files (lazy tree) for the
// selected session's cwd. Requests are e2e-encrypted; the daemon answers read-only.
const INSP = { open: false, expanded: new Set(), tree: new Map(), status: null, pending: new Map() };
try { INSP.open = localStorage.getItem('tether.insp') === '1'; } catch {}

function fsReq(op, extra = {}, forDevice = null) {
  return new Promise((resolve) => {
    const [curDev, curSess] = (S.current ?? '/').split('/');
    const deviceId = forDevice ?? curDev;
    const sessionId = forDevice ? null : curSess;
    if (!deviceId || !S.connected) return resolve({ error: 'not connected' });
    const reqId = randHex(8);
    const to = setTimeout(() => { INSP.pending.delete(reqId); resolve({ error: 'timed out' }); }, 15_000);
    INSP.pending.set(reqId, { resolve, to, deviceId });
    (async () => {
      const reqCt = await encryptJSON(await deriveKey(cfg.accountSecret, `fs:${deviceId}`), { op, sessionId, ...extra });
      send({ type: 'fs', reqId, deviceId, reqCt });
    })();
  });
}

function toggleInspector(open = !INSP.open) {
  INSP.open = open;
  try { localStorage.setItem('tether.insp', open ? '1' : '0'); } catch {}
  $('inspector').hidden = !open || !S.current;
  $('inspToggle')?.classList.toggle('on', open);
  if (open && S.current) refreshInspector();
}

async function refreshInspector() {
  INSP.tree.clear(); INSP.expanded.clear(); closeViewer();
  $('inspRepo').textContent = '…';
  $('changesList').innerHTML = '<p class="ihint">loading…</p>';
  $('fileTree').innerHTML = '<p class="ihint">loading…</p>';
  const [st, root] = await Promise.all([fsReq('status'), fsReq('list', { path: '.' })]);
  INSP.status = st;
  $('inspRepo').textContent = st.root ? shortPath(st.root) + (st.branch ? ` ⎇ ${st.branch}` : '') : '';
  renderChanges();
  INSP.tree.set('.', root.entries ?? []);
  renderTree(root.error);
}

async function refreshChanges() {
  const st = await fsReq('status');
  INSP.status = st;
  renderChanges();
}

// file-type marks, VS Code-explorer style: colored short badges for languages,
// glyphs for folders / images / everything else
const FI_TEXT = {
  js: ['JS', '#E8D44D'], mjs: ['JS', '#E8D44D'], cjs: ['JS', '#E8D44D'], jsx: ['JS', '#61DAFB'],
  ts: ['TS', '#4E9CFF'], tsx: ['TS', '#61DAFB'], py: ['PY', '#6FA8DC'], ipynb: ['NB', '#FF8256'],
  sh: ['$', '#8BC34A'], bash: ['$', '#8BC34A'], zsh: ['$', '#8BC34A'],
  json: ['{}', '#E8B34D'], jsonc: ['{}', '#E8B34D'], html: ['<>', '#FF7043'], htm: ['<>', '#FF7043'],
  css: ['#', '#7C93FF'], scss: ['#', '#FF7BAC'], less: ['#', '#7C93FF'],
  md: ['M', '#77A7FF'], mdx: ['M', '#77A7FF'], txt: ['≡', '#8493A0'],
  yml: ['Y', '#FF8256'], yaml: ['Y', '#FF8256'], toml: ['T', '#FF8256'], xml: ['<>', '#B39DDB'],
  go: ['GO', '#56C7E0'], rs: ['RS', '#FFA26B'], rb: ['RB', '#FF5C6A'], java: ['JV', '#FF8256'],
  c: ['C', '#7C93FF'], h: ['H', '#7C93FF'], cpp: ['C+', '#7C93FF'], cc: ['C+', '#7C93FF'], cs: ['C#', '#8BC34A'],
  php: ['PH', '#8993BE'], swift: ['SW', '#FF8256'], kt: ['KT', '#B39DDB'], sql: ['DB', '#77A7FF'],
  vue: ['V', '#41B883'], svelte: ['SV', '#FF3E00'], env: ['⚙', '#8BC34A'], lock: ['⌀', '#8493A0'],
  gitignore: ['◆', '#F05033'], gitattributes: ['◆', '#F05033'],
};
const FI_IMG = new Set(['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg', 'ico', 'bmp', 'avif', 'tiff']);
const SVG_DOC = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M13 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9z"/><path d="M13 3v6h6"/></svg>';
const SVG_IMGF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2.5"/><circle cx="8.5" cy="8.5" r="1.6"/><path d="M21 15.5l-5-5L5 21"/></svg>';
const SVG_FOLDER = '<svg viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M3 6.2A1.7 1.7 0 0 1 4.7 4.5h4.4l2 2.3h8.2A1.7 1.7 0 0 1 21 8.5v9.3a1.7 1.7 0 0 1-1.7 1.7H4.7A1.7 1.7 0 0 1 3 17.8z" opacity=".85"/></svg>';
function fileIcon(name) {
  const dot = name.lastIndexOf('.');
  const ext = dot >= 0 ? name.slice(dot + 1).toLowerCase() : '';
  if (FI_IMG.has(ext)) return `<span class="fico" style="color:#B39DDB">${SVG_IMGF}</span>`;
  const t = FI_TEXT[ext];
  if (t) return `<span class="fico" style="color:${t[1]}">${esc(t[0])}</span>`;
  return `<span class="fico" style="color:#66757F">${SVG_DOC}</span>`;
}

const CH_CLS = { U: 'add', A: 'add', D: 'del', M: 'mod', R: 'mod', C: 'mod' };
function renderChanges() {
  const st = INSP.status;
  const el = $('changesList');
  if (!st || st.error) { el.innerHTML = `<p class="ihint">${esc(st?.error ?? 'no data')}</p>`; $('chCount').textContent = ''; return; }
  if (!st.git) { el.innerHTML = '<p class="ihint">not a git repository</p>'; $('chCount').textContent = ''; return; }
  const files = st.files ?? [];
  $('chCount').textContent = files.length ? String(files.length) : '';
  if (!files.length) { el.innerHTML = '<p class="ihint">no changes</p>'; return; }
  el.innerHTML = files.map((f) => {
    const letter = f.st === '??' ? 'U' : (f.st.trim()[0] ?? 'M');
    return `<button type="button" class="chg" data-p="${esc(f.path)}" title="${esc(f.path)}">
      ${fileIcon(f.path.split('/').pop())}
      <span class="chname">${esc(f.path.split('/').pop())}</span>
      <span class="chdir">${esc(f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '')}</span>
      <span class="chst ${CH_CLS[letter] ?? 'mod'}">${letter}</span></button>`;
  }).join('');
  el.querySelectorAll('.chg').forEach((b) => b.addEventListener('click', () => openDiff(b.dataset.p)));
}

function renderTree(error) {
  const el = $('fileTree');
  if (error) { el.innerHTML = `<p class="ihint">${esc(error)}</p>`; return; }
  const build = (relDir, depth) => {
    let h = '';
    for (const e of INSP.tree.get(relDir) ?? []) {
      const rel = relDir === '.' ? e.name : `${relDir}/${e.name}`;
      if (e.dir) {
        const open = INSP.expanded.has(rel);
        h += `<button type="button" class="tnode dir" data-p="${esc(rel)}" style="--d:${depth}"><span class="chev">${open ? '▾' : '▸'}</span><span class="fico" style="color:#7FA3C8">${SVG_FOLDER}</span><span class="tname">${esc(e.name)}</span></button>`;
        if (open) h += build(rel, depth + 1);
      } else {
        h += `<button type="button" class="tnode" data-p="${esc(rel)}" style="--d:${depth}"><span class="chev"></span>${fileIcon(e.name)}<span class="tname">${esc(e.name)}</span></button>`;
      }
    }
    return h;
  };
  el.innerHTML = build('.', 0) || '<p class="ihint">empty</p>';
  el.querySelectorAll('.tnode.dir').forEach((b) => b.addEventListener('click', () => toggleDir(b.dataset.p)));
  el.querySelectorAll('.tnode:not(.dir)').forEach((b) => b.addEventListener('click', () => openFile(b.dataset.p)));
}

async function toggleDir(rel) {
  if (INSP.expanded.has(rel)) { INSP.expanded.delete(rel); renderTree(); return; }
  INSP.expanded.add(rel);
  if (!INSP.tree.has(rel)) {
    renderTree();
    const r = await fsReq('list', { path: rel });
    INSP.tree.set(rel, r.entries ?? []);
  }
  renderTree();
}

async function openFile(rel) {
  showViewer(rel, 'loading…');
  const r = await fsReq('read', { path: rel });
  showViewer(rel, r.error ? `⚠ ${r.error}` : r.binary ? `binary file · ${((r.size ?? 0) / 1024) | 0} KB` : r.content ?? '');
}
async function openDiff(rel) {
  showViewer(rel, 'loading…');
  const r = await fsReq('diff', { path: rel });
  if (r.error || r.binary) return showViewer(rel, r.error ? `⚠ ${r.error}` : 'binary file');
  showViewer(rel, r.diff || '(no changes)', true);
}
function showViewer(title, content, isDiff = false) {
  $('inspBody').hidden = true;
  $('inspView').hidden = false;
  $('iviewTitle').textContent = title;
  const b = $('iviewBody');
  if (isDiff) {
    b.innerHTML = content.split('\n').map((l) => {
      const c = /^(\+\+\+|---|diff |index )/.test(l) ? 'dhead'
        : l.startsWith('@@') ? 'dhunk'
        : l.startsWith('+') ? 'dadd'
        : l.startsWith('-') ? 'ddel' : '';
      return `<span class="dl ${c}">${esc(l) || ' '}</span>`;
    }).join('\n');
  } else b.textContent = content;
}
function closeViewer() { $('inspView').hidden = true; $('inspBody').hidden = false; }

$('inspClose')?.addEventListener('click', () => toggleInspector(false));
$('inspRefresh')?.addEventListener('click', () => refreshInspector());
$('iviewBack')?.addEventListener('click', closeViewer);
document.querySelectorAll('.isec-h').forEach((h) => h.addEventListener('click', () => {
  const body = $(h.dataset.s);
  body.hidden = !body.hidden;
  h.querySelector('.chev').textContent = body.hidden ? '▸' : '▾';
}));

// a session running inside a tmux pane can receive prompts in its LIVE terminal
async function refreshLiveTarget(store) {
  const k = S.current;
  const r = await fsReq('live');
  if (S.current !== k) return;
  const wrap = $('liveWrap'), chk = $('liveChk');
  if (!wrap || !chk) return;
  if (r.live) {
    wrap.hidden = false;
    $('liveLbl').textContent = `live terminal (${r.label})`;
    wrap.title = `Type this message straight into the running Claude in tmux pane ${r.label}, instead of starting a separate headless run.`;
    if (store.__live === undefined) { store.__live = true; chk.checked = true; } // prefer live when it exists
  } else {
    wrap.hidden = true;
    store.__live = false;
    chk.checked = false;
  }
  syncOptsForLive(!!store.__live);
}

function redrawAgentOpts() {
  const k = S.current;
  const s = k && S.sessions.get(k);
  if (!s) return;
  agentOptsControls($('agentOpts'), s.agent ?? 'claude', S.agentOpts.get(k) ?? {},
    { usage: true, deviceId: k.split('/')[0], meta: s.meta ?? null });
}

function select(k) {
  S.current = k;
  S.follow = true; // opening a chat always lands on the latest activity
  showSessionPane();
  // Push a history entry so the phone's own back gesture returns to the list rather than
  // leaving the app — the thing people actually reach for before finding a button.
  if (!history.state?.pane) history.pushState({ pane: true }, '');
  renderFleet(); renderPaneHeader();
  $('composer').hidden = false;
  if (!S.agentOpts.has(k)) S.agentOpts.set(k, {});
  const dev = k.split('/')[0];
  redrawAgentOpts();
  ensureAgentInfo(dev).then(() => { if (S.current === k) redrawAgentOpts(); }); // re-render once real model lists arrive
  subscribe(k);
  renderTranscript();
  renderApprovals(); // this session may already be blocked on a question
  $('inspector').hidden = !INSP.open;
  if (INSP.open) refreshInspector();
}
function subscribe(k) {
  const [deviceId, sessionId] = k.split('/');
  send({ type: 'subscribe', deviceId, sessionId });
}

function renderPaneHeader() {
  const s = S.sessions.get(S.current);
  if (!s) return;
  $('paneHeader').innerHTML = `<button class="backBtn" id="backBtn" title="Back to sessions" aria-label="Back to sessions"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg></button>${agentChip(s.agent, true)}<span class="title">${esc(sessName(s))}</span>
    <span class="pill ${esc(s.state)}">${esc(STATE_LABEL[s.state] ?? s.state)}</span>
    <span class="path mono">${esc(s.meta?.cwd ?? '')}${s.meta?.gitBranch ? ' · ' + esc(s.meta.gitBranch) : ''}</span>
    ${s.meta?.model ? `<span class="mbadge" title="model serving this session">${esc(modelName(s.meta.model))}</span>` : ''}
    ${s.meta?.permissionMode ? `<span class="mbadge" title="permission mode in the local session">${esc(s.meta.permissionMode)}</span>` : ''}
    <span class="spacer"></span>
    <button id="inspToggle" class="ibtn ${INSP.open ? 'on' : ''}" title="Files &amp; changes">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 5.5A1.5 1.5 0 0 1 4.5 4h5l2 2.5h8A1.5 1.5 0 0 1 21 8v10a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18z"/></svg>
    </button>`;
  $('inspToggle').addEventListener('click', () => toggleInspector());
  // On a phone the pane IS the screen, so leaving it means going back to the list. The
  // button is display:none above 760px, where both are visible at once and back is meaningless.
  $('backBtn')?.addEventListener('click', () => showSessionList());
}

// Phone navigation. Desktop ignores both of these — the class only does anything inside the
// 760px media query, so the same code drives one layout or two without branching on width.
function showSessionPane() { document.body.classList.add('on-pane'); }
function showSessionList() {
  document.body.classList.remove('on-pane');
  history.state?.pane && history.back(); // keep the back button and the gesture in step
}

// --- minimal, safe markdown -> HTML (escapes first, then formats) ---
function mdInline(s) {
  s = esc(s);
  // protect code spans and links so bold/italic never touch their insides
  const held = [];
  const hold = (html) => { held.push(html); return `\u0000${held.length - 1}\u0000`; };
  s = s.replace(/`([^`]+)`/g, (_, c) => hold(`<code>${c}</code>`));
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_, t, u) => hold(`<a href="${u}" target="_blank" rel="noopener noreferrer">${t}</a>`));
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');   // bold first; .+? tolerates inner italic
  s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
  s = s.replace(/(^|[^*])\*([^*\n]+?)\*/g, '$1<em>$2</em>'); // then italic
  s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => held[+i]);   // restore protected spans
  return s;
}
function mdBlock(text) {
  const lines = text.split('\n');
  let html = '', list = null, items = [], para = [];
  const flushList = () => { if (list) { html += `<${list}>` + items.map((li) => `<li>${mdInline(li)}</li>`).join('') + `</${list}>`; list = null; items = []; } };
  const flushPara = () => { if (para.length) { html += `<p>${mdInline(para.join(' '))}</p>`; para = []; } };
  for (const line of lines) {
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    const ul = line.match(/^\s*[-*+]\s+(.*)$/);
    const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (h) { flushList(); flushPara(); const lvl = Math.min(h[1].length + 2, 6); html += `<h${lvl} class="md-h">${mdInline(h[2])}</h${lvl}>`; }
    else if (ul) { flushPara(); if (list !== 'ul') flushList(); list = 'ul'; items.push(ul[1]); }
    else if (ol) { flushPara(); if (list !== 'ol') flushList(); list = 'ol'; items.push(ol[1]); }
    else if (line.trim() === '') { flushList(); flushPara(); }
    else { flushList(); para.push(line); }
  }
  flushList(); flushPara();
  return html;
}
function mdToHtml(srcText) {
  const fence = /```(\w*)\n?([\s\S]*?)```/g;
  let out = '', last = 0, m;
  while ((m = fence.exec(srcText))) {
    out += mdBlock(srcText.slice(last, m.index));
    out += `<pre class="md-code"><code>${esc(m[2].replace(/\n$/, ''))}</code></pre>`;
    last = fence.lastIndex;
  }
  out += mdBlock(srcText.slice(last));
  return out || '<p></p>';
}

// ---------------------------------------------------------------- Claude Code-faithful rendering
const CIRCLE = '⏺'; // ⏺
const BRANCH = '⎿'; // ⎿ (rendered via ::before actually; we use a span)

function shortPath(p) {
  if (!p) return '';
  const home = '/Users/';
  let s = String(p);
  const m = s.match(/^\/Users\/[^/]+(\/.*)?$/);
  if (m) s = '~' + (m[1] ?? '');
  return s;
}
function firstLines(text, n) {
  const lines = String(text ?? '').split('\n');
  const shown = lines.slice(0, n).join('\n');
  const extra = lines.length - n;
  return { shown, extra: extra > 0 ? extra : 0, total: lines.length };
}

// unified-ish diff for Edit: old_string -> new_string
function diffHtml(oldStr, newStr) {
  const a = String(oldStr ?? '').split('\n');
  const b = String(newStr ?? '').split('\n');
  // longest-common-subsequence line diff (small inputs)
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--)
    dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const rows = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { rows.push(['ctx', a[i]]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { rows.push(['del', a[i]]); i++; }
    else { rows.push(['add', b[j]]); j++; }
  }
  while (i < n) rows.push(['del', a[i++]]);
  while (j < m) rows.push(['add', b[j++]]);
  return `<div class="diff">` + rows.map(([t, line]) =>
    `<div class="dl ${t}"><span class="dg">${t === 'add' ? '+' : t === 'del' ? '-' : ' '}</span>${esc(line) || '&nbsp;'}</div>`).join('') + `</div>`;
}

function resultBlock(result, { lines = 6 } = {}) {
  if (!result) return '';
  const cls = result.isError ? 'res error' : 'res';
  let inner = '';
  if (result.images?.length) inner += result.images.map((u) => `<img class="res-img" src="${esc(u)}" alt="tool image">`).join('');
  const text = (result.text ?? '').replace(/\s+$/, '');
  if (text) {
    const { shown, extra } = firstLines(text, lines);
    inner += `<pre class="res-pre">${esc(shown)}</pre>`;
    if (extra) inner += `<details class="more"><summary>+${extra} lines</summary><pre class="res-pre">${esc(text)}</pre></details>`;
  }
  if (!inner) inner = `<span class="res-empty">${result.isError ? '(error, no output)' : '(no output)'}</span>`;
  return `<div class="${cls}"><span class="branch">⎿</span><div class="res-body">${inner}</div></div>`;
}

// tool_use header + optional inline body, in Claude Code's grammar
const CHEV = '<svg class="chev-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M9 6l6 6-6 6"/></svg>';

function toolLabel(t, inp) {
  if (t === 'Bash') return { label: 'Bash', arg: undefined };
  if (t === 'Read') return { label: 'Read', arg: shortPath(inp.file_path) };
  if (t === 'Write') return { label: 'Write', arg: shortPath(inp.file_path) };
  if (t === 'Edit') return { label: 'Update', arg: shortPath(inp.file_path) };
  if (t === 'TodoWrite') return { label: 'Update Todos', arg: undefined };
  const label = t.startsWith('mcp__') ? t.replace(/^mcp__/, '').replace(/__/g, '·') : t;
  const argStr = Object.entries(inp).map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`).join(', ').slice(0, 120);
  return { label, arg: argStr || undefined };
}
function toolPreview(t, inp, result) {
  if (t === 'Bash') return (inp.command ?? '').split('\n')[0].slice(0, 80);
  if (t === 'Edit') { const a = String(inp.old_string ?? '').split('\n').length, b = String(inp.new_string ?? '').split('\n').length; return `~${Math.max(a, b)} lines changed`; }
  if (t === 'TodoWrite') { const td = inp.todos ?? []; return `${td.filter((x) => x.status === 'completed').length}/${td.length} done`; }
  const rt = (result?.text ?? '').replace(/\s+/g, ' ').trim();
  return rt ? rt.slice(0, 80) : '';
}
function toolIsLong(t, inp, result) {
  const cmdLines = String(inp.command ?? inp.content ?? '').split('\n').length;
  const resLines = String(result?.text ?? '').split('\n').length;
  if (t === 'Write') return true;
  if (t === 'Edit') return (String(inp.old_string ?? '').split('\n').length + String(inp.new_string ?? '').split('\n').length) > 8;
  return cmdLines > 3 || String(inp.command ?? '').length > 160 || resLines > 6 || (result?.images?.length > 0);
}
function toolBody(t, inp, result) {
  if (t === 'Bash') return `<pre class="cmd">${esc(inp.command ?? '')}</pre>${inp.description ? `<div class="tdesc">${esc(inp.description)}</div>` : ''}${resultBlock(result)}`;
  if (t === 'Read') return resultBlock(result, { lines: 4 });
  if (t === 'Write') { const f = firstLines(inp.content ?? '', 20); return `${inp.content ? `<pre class="cmd">${esc(f.shown)}${f.extra ? `\n… +${f.extra} lines` : ''}</pre>` : ''}${resultBlock(result, { lines: 2 })}`; }
  if (t === 'Edit') return `${diffHtml(inp.old_string, inp.new_string)}${resultBlock(result, { lines: 2 })}`;
  if (t === 'TodoWrite') {
    const box = (st) => st === 'completed' ? '☒' : st === 'in_progress' ? '◐' : '☐';
    const items = (inp.todos ?? []).map((td) => `<div class="todo ${esc(td.status)}">${box(td.status)} ${esc(td.status === 'in_progress' ? (td.activeForm || td.content) : td.content)}</div>`).join('');
    return `<div class="todos">${items}</div>`;
  }
  return resultBlock(result);
}
function toolHtml(e, result) {
  const t = e.tool, inp = e.input ?? {};
  const { label, arg } = toolLabel(t, inp);
  const prev = toolPreview(t, inp, result);
  const body = toolBody(t, inp, result);
  const open = !toolIsLong(t, inp, result);
  const errCls = result?.isError ? ' err' : '';
  return `<div class="ev tool${errCls}"><details class="tcol"${open ? ' open' : ''}>` +
    `<summary class="tool-head"><span class="chev">${CHEV}</span><span class="bullet">${CIRCLE}</span>` +
    `<span class="tname">${esc(label)}</span>${arg !== undefined ? `<span class="targ">${esc(arg)}</span>` : ''}` +
    `${prev ? `<span class="tprev">${esc(prev)}</span>` : ''}</summary>` +
    `<div class="tbody">${body}</div></details></div>`;
}

function textHtml(e) {
  if (e.role === 'user') return `<div class="ev user"><div class="body md">${mdToHtml(e.text)}</div></div>`;
  return `<div class="ev assistant"><span class="bullet">${CIRCLE}</span><div class="body md">${mdToHtml(e.text)}</div></div>`;
}
function thinkingHtml(e) {
  const { shown, extra } = firstLines(e.text, 3);
  return `<div class="ev thinking"><details><summary><span class="spark">✻</span> Thinking${extra ? '…' : ''}</summary><div class="think-body md">${mdToHtml(e.text)}</div></details><div class="think-peek">${esc(shown)}${extra ? '…' : ''}</div></div>`;
}

function renderTranscript(autoscroll = true) {
  const el = $('transcript');
  const list = S.events.get(S.current) ?? [];

  // pair tool_result to its tool_use so results render under the call, as in Claude Code
  const resultByTool = new Map();
  for (const e of list) if (e.kind === 'tool_result' && e.toolUseId) resultByTool.set(e.toolUseId, e);

  let html = '';
  if (list.length && list[0].seq > 1) html += `<button id="loadEarlier" class="ghost">Load earlier</button>`;
  for (const e of list) {
    if (e.kind === 'text') html += textHtml(e);
    else if (e.kind === 'thinking') html += thinkingHtml(e);
    else if (e.kind === 'tool_use') html += toolHtml(e, resultByTool.get(e.toolUseId));
    else if (e.kind === 'tool_result') { if (!e.toolUseId || !seenToolUse(list, e.toolUseId)) html += `<div class="ev tool">${resultBlock(e)}</div>`; }
    else if (e.kind === 'image') html += `<div class="ev"><img class="res-img" src="${esc(e.dataUrl)}" alt="image"></div>`;
    else if (e.kind === 'model_switch') html += `<div class="ev mswitch"><span>Switched to ${esc(modelName(e.model))}</span></div>`;
    else if (e.kind === 'system') html += `<div class="ev system"><div class="body">${esc(e.text)}</div></div>`;
    else html += `<div class="ev unknown">${esc(e.text ?? e.kind)}</div>`;
  }
  const st = S.sessions.get(S.current)?.state;
  // Mid-turn the transcript just sits there: the next event can be a minute away. Say it is
  // working where the answer will appear, not only as a pill up in the header.
  const responding = st === 'running'
    ? `<div class="ev responding"><span class="spinner"></span><span>responding<i>.</i><i>.</i><i>.</i></span></div>`
    : '';
  if (!list.length) {
    const dev = S.devices.get(S.current.split('/')[0]);
    html = dev?.syncing
      ? `<div class="loading-pane"><span class="spinner big"></span><p class="hint">Syncing this session…</p></div>`
      : responding || `<p class="hint center">No events yet in this session.</p>`;
  } else {
    html += responding;
    html += `<div class="jumpwrap"><button id="jumpLatest" class="jump" ${S.follow ? 'hidden' : ''}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12l7 7 7-7"/></svg>
      <span>Jump to latest${st ? ` · ${esc(STATE_LABEL[st] ?? st)}` : ''}</span></button></div>`;
  }
  el.innerHTML = html;
  const le = $('loadEarlier');
  if (le) le.addEventListener('click', () => {
    const [deviceId, sessionId] = S.current.split('/');
    send({ type: 'load_earlier', deviceId, sessionId, beforeSeq: list[0].seq });
  });
  $('jumpLatest')?.addEventListener('click', () => {
    setFollow(true);
    pinToLatest(true);
  });
  // new data always pushes the chat up while we're tracking the latest state
  if (autoscroll && S.follow) pinToLatest();
}
function seenToolUse(list, id) { for (const e of list) if (e.kind === 'tool_use' && e.toolUseId === id) return true; return false; }

function previewInput(req) {
  const i = req.toolInput ?? {};
  return (i.command ?? i.file_path ?? JSON.stringify(i)).slice(0, 120);
}

function renderApprovals() {
  const el = $('approvals');
  const items = [...S.approvals.values()].filter((a) => a.deadline > Date.now());
  // An approval belongs to ONE session. Only show its card while that session is open;
  // approvals for other sessions become a banner that jumps you there, so a prompt can
  // never look like it came from the chat you happen to be reading.
  const mine = items.filter((a) => keyOf(a.deviceId, a.sessionId) === S.current);
  const others = items.filter((a) => keyOf(a.deviceId, a.sessionId) !== S.current);

  // A session can also be blocked on plain input (Claude asked something, or a TUI
  // prompt is open) with no tool approval attached. Show that here too, with whatever
  // the session told us it is waiting for — otherwise "needs input" is a dead end.
  const cur = S.current && S.sessions.get(S.current);
  let html = '';
  if (cur?.state === 'waiting_input' && cur.ask) {
    const a = cur.ask;
    const t = a.tool;
    // Context, always: what the agent asked, and the exact call it refers to.
    const ctx = a.screen ? `<pre class="screen">${esc(a.screen)}</pre>`
      : (t ? `<pre>${esc(t.name)}: ${esc(previewLong({ toolInput: t.input }))}</pre>` : '');
    // Choices, mirrored from the terminal when we could read them.
    const btns = a.options?.length
      ? a.options.map((o, i) => `<button class="${i === 0 ? 'allow' : 'deny'}" data-ans="${esc(o.key)}">${esc(o.key)}. ${esc(o.label)}</button>`).join('')
      : `<button class="allow" data-ans="1">Yes</button><button class="deny" data-ans="3">No</button>`;
    html += `<div class="approval needsinput">
      <div class="head"><span class="tool">${esc(t?.name ? `${t.name} — needs you` : 'needs input')}</span>
        <span class="where">${esc(cur.meta?.cwd ?? '')}</span></div>
      <p class="askq">${esc(a.message)}</p>
      ${ctx}
      ${a.answerable
        ? `<div class="row askrow askopts">${btns}</div>
           <p class="dlg-hint">Sent as a keypress to the live terminal (${esc(a.pane ?? '')}).</p>`
        : `<p class="dlg-hint">⚠ This prompt is open on the machine itself and must be answered there.${
             a.reason ? ` ${esc(a.reason)}` : ' Remote answering needs the session to be running inside tmux.'}</p>`}
    </div>`;
  }
  html += mine.map((a) => {
    const body = approvalBody(a.req);
    const q = isQuestion(a.req) && Array.isArray(a.req.toolInput?.questions) && a.req.toolInput.questions.length;
    return `<div class="approval${q ? ' isq' : ''}" data-card="${esc(a.approvalId)}">
      <div class="head"><span class="tool">${esc(q ? 'Claude is asking you' : (a.req.toolName ?? 'tool'))}</span>
        <span class="where">${esc(a.req.cwd ?? '')}</span>
        <span class="count" data-deadline="${a.deadline}"></span></div>
      ${body}
      <div class="row">
        ${q
          ? `<button class="allow" data-send="${esc(a.approvalId)}">Send answer</button>
             <button class="deny" data-id="${esc(a.approvalId)}" data-d="deny">Cancel</button>`
          : `<button class="allow" data-id="${esc(a.approvalId)}" data-d="allow">Approve</button>
             <button class="deny" data-id="${esc(a.approvalId)}" data-d="deny">Deny</button>`}
      </div></div>`;
  }).join('');

  if (others.length) {
    html += others.map((a) => {
      const s = S.sessions.get(keyOf(a.deviceId, a.sessionId));
      return `<button class="apx" data-go="${esc(keyOf(a.deviceId, a.sessionId))}">
        <span class="apx-dot"></span>
        <span class="apx-t"><b>${esc(sessName(s) ?? a.sessionId.slice(0, 8))}</b> needs approval — ${esc(a.req.toolName ?? 'tool')}</span>
        <span class="count" data-deadline="${a.deadline}"></span>
        <span class="apx-go">open →</span></button>`;
    }).join('');
  }
  el.innerHTML = html;
  el.querySelectorAll('button[data-id]').forEach((b) =>
    b.addEventListener('click', () => send({ type: 'approve', approvalId: b.dataset.id, decision: b.dataset.d })));
  el.querySelectorAll('button[data-go]').forEach((b) =>
    b.addEventListener('click', () => select(b.dataset.go)));
  // Pick an option: single-select replaces the choice within its question, multi toggles.
  el.querySelectorAll('button.aqopt').forEach((b) => b.addEventListener('click', () => {
    const box = b.closest('.aq');
    if (!box) return;
    if (!box.dataset.multi) box.querySelectorAll('.aqopt').forEach((o) => { if (o !== b) o.classList.remove('sel'); });
    b.classList.toggle('sel');
    box.classList.remove('needs');
  }));
  // Answer the question. Claude expects { questions, answers } back; the daemon still holds
  // the original questions, so only the answers travel — encrypted like every other payload.
  el.querySelectorAll('button[data-send]').forEach((b) => b.addEventListener('click', async () => {
    const id = b.dataset.send;
    const card = el.querySelector(`.approval[data-card="${id}"]`);
    if (!card) return;
    const answers = {};
    let missing = 0;
    card.querySelectorAll('.aq').forEach((box) => {
      const picked = [...box.querySelectorAll('.aqopt.sel')].map((o) => o.dataset.label);
      if (!picked.length) { missing++; box.classList.add('needs'); return; }
      answers[box.dataset.q] = box.dataset.multi ? picked : picked[0];
    });
    if (missing) return; // every question needs an answer before this means anything
    b.disabled = true;
    try {
      const answersCt = await encryptJSON(await deriveKey(cfg.accountSecret, `approval:${id}`), { answers });
      send({ type: 'approve', approvalId: id, decision: 'allow', answersCt });
    } catch (e) { b.disabled = false; alert(`Could not send the answer: ${e.message}`); }
  }));
  el.querySelectorAll('button[data-ans]').forEach((b) =>
    b.addEventListener('click', async () => {
      b.disabled = true;
      const r = await fsReq('answer', { key: b.dataset.ans });
      if (r.error) { b.disabled = false; alert(`Could not answer: ${r.error}`); }
    }));
  updateAttention();
}

// Render what is actually being asked. AskUserQuestion carries the question and its
// options, so show them instead of dumping raw JSON.
function approvalBody(req) {
  const i = req.toolInput ?? {};
  if (isQuestion(req) && Array.isArray(i.questions) && i.questions.length) {
    // Pick the answer HERE. Approving an AskUserQuestion without one sends Claude an empty
    // answer set, which is worse than useless — it looks answered and says nothing.
    return i.questions.map((q, qi) => `<div class="aq" data-qi="${qi}" data-q="${esc(q.question ?? '')}" data-multi="${q.multiSelect ? '1' : ''}">
      <div class="aq-q">${esc(q.question ?? q.header ?? 'Question')}${q.multiSelect ? ' <em>(choose any)</em>' : ''}</div>
      <div class="aq-opts">${(q.options ?? []).map((o) => {
        const label = o.label ?? String(o);
        return `<button type="button" class="aqopt" data-qi="${qi}" data-label="${esc(label)}">
          <b>${esc(label)}</b>${o.description ? `<span>${esc(o.description)}</span>` : ''}</button>`;
      }).join('')}</div>
    </div>`).join('');
  }
  if (req.toolName === 'ExitPlanMode' && i.plan) return `<pre>${esc(String(i.plan).slice(0, 1500))}</pre>`;
  return `<pre>${esc(previewLong(req))}</pre>`;
}
// The daemon tags these; fall back to the tool name for anything it did not tag.
const isQuestion = (req) => req?.kind === 'question' || req?.toolName === 'AskUserQuestion';
function previewLong(req) {
  const i = req.toolInput ?? {};
  if (i.command) return i.command.slice(0, 1500);
  if (i.file_path) return `${i.file_path}\n\n${String(i.content ?? i.new_string ?? '').slice(0, 1200)}`;
  return JSON.stringify(i, null, 1).slice(0, 1500);
}

// Tab-title badge + favicon cue: works even when notifications are denied or the tab is open.
function updateAttention() {
  const live = [...S.approvals.values()].filter((a) => a.deadline > Date.now()).length;
  const needy = [...S.sessions.values()].filter((s) => s.state === 'waiting_input').length;
  const n = live + needy;
  document.title = n ? `(${n}) Tether` : 'Tether';
}
setInterval(() => {
  let changed = false;
  document.querySelectorAll('.count[data-deadline]').forEach((c) => {
    const left = Math.max(0, Math.round((+c.dataset.deadline - Date.now()) / 1000));
    c.textContent = `${left}s`;
    if (left === 0) changed = true;
  });
  if (changed) renderApprovals();
}, 1000);

function renderQueueNote() {
  document.querySelectorAll('.qnote').forEach((n) => n.remove());
  if (!S.queueNotes.size) return;
  const div = document.createElement('div');
  div.className = 'qnote';
  div.textContent = `⏳ ${S.queueNotes.size} prompt(s) queued — ${[...S.queueNotes.values()][0]}`;
  $('composer').before(div);
}

// ---------------------------------------------------------------- actions
// image attachments: picked, pasted, or dropped into the composer; downscaled client-side
// and sent e2e-encrypted inside the prompt body, so the relay never sees pixels
const IMG_MAX = 6, IMG_DIM = 1600;
const pendingImgs = []; // {name,type,dataUrl}
function renderAttachments() {
  const strip = $('attachStrip');
  strip.hidden = !pendingImgs.length;
  strip.innerHTML = pendingImgs.map((im, i) =>
    `<span class="att" title="${esc(im.name)}"><img src="${im.dataUrl}" alt=""><button type="button" class="rm" data-i="${i}" title="Remove">×</button></span>`).join('');
  strip.querySelectorAll('.rm').forEach((b) => b.addEventListener('click', () => { pendingImgs.splice(+b.dataset.i, 1); renderAttachments(); }));
}
async function addImage(file) {
  if (!file?.type?.startsWith('image/')) return;
  if (pendingImgs.length >= IMG_MAX) return alert(`Up to ${IMG_MAX} images per message.`);
  const dataUrl = await downscaleImage(file);
  if (!dataUrl) return alert(`Couldn't read ${file.name || 'that image'}.`);
  if (dataUrl.length > 3_500_000) return alert(`${file.name || 'Image'} is too large even after downscaling.`);
  pendingImgs.push({ name: file.name || 'pasted-image', type: dataUrl.slice(5, dataUrl.indexOf(';')), dataUrl });
  renderAttachments();
}
function downscaleImage(file) {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      const scale = Math.min(1, IMG_DIM / Math.max(img.width, img.height));
      if (scale === 1 && file.size < 800_000) { // small enough — keep the original bytes
        const r = new FileReader();
        r.onload = () => resolve(r.result);
        r.onerror = () => resolve(null);
        r.readAsDataURL(file);
        return;
      }
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      const keepPng = file.type === 'image/png' || file.type === 'image/gif'; // screenshots/text stay crisp
      resolve(c.toDataURL(keepPng ? 'image/png' : 'image/jpeg', 0.85));
    };
    img.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
    img.src = url;
  });
}

async function sendPrompt() {
  const text = $('promptText').value.trim();
  if ((!text && !pendingImgs.length) || !S.current) return;
  const [deviceId, sessionId] = S.current.split('/');
  const promptId = randHex(8);
  const body = { text };
  if (pendingImgs.length) body.images = pendingImgs.map((im) => ({ name: im.name, type: im.type, data: im.dataUrl.slice(im.dataUrl.indexOf(',') + 1) }));
  const store = S.agentOpts.get(S.current) ?? {};
  const opts = cleanOpts(store);
  if (Object.keys(opts).length) body.opts = opts;
  if (store.__live) body.live = true; // deliver into the running terminal, not a new process
  const bodyCt = await encryptJSON(await deriveKey(cfg.accountSecret, `prompt:${promptId}`), body);
  send({ type: 'prompt', promptId, deviceId, sessionId, bodyCt });
  $('promptText').value = '';
  autosize($('promptText')); // back to one row once it is sent
  pendingImgs.length = 0;
  renderAttachments();
}

async function newSession() {
  const deviceId = $('newDevice').value;
  const cwd = $('newCwd').value.trim();
  const text = $('newText').value.trim();
  if (!deviceId || !cwd || !text) return;
  const promptId = randHex(8);
  const body = { text, cwd, agent: NEWS.agent };
  // interactive => a live tmux TUI we can mirror and answer remotely later
  if ($('newInteractive')?.checked) body.interactive = true;
  const opts = cleanOpts(NEWS.opts);
  if (Object.keys(opts).length) body.opts = opts;
  const bodyCt = await encryptJSON(await deriveKey(cfg.accountSecret, `prompt:${promptId}`), body);
  send({ type: 'prompt', promptId, deviceId, bodyCt });
  newDlg.close();
}

// per-agent runtime options shown at the composer and in the new-session dialog.
// Every value maps to a real CLI flag on the daemon (whitelisted there); 'default' sends nothing.
// model dropdowns are filled from LIVE detection on the machine (each CLI's own list);
// mode/sandbox sets are the fixed flags those CLIs accept. 'default' = the CLI's own config.
const AGENT_OPTS = {
  claude: { usage: true, selects: [
    { k: 'model', label: 'model', models: true, live: 'model', fallback: ['sonnet', 'opus', 'haiku'] },
    { k: 'mode', label: 'mode', live: 'permissionMode', values: ['default', 'manual', 'auto', 'acceptEdits', 'plan', 'dontAsk', 'bypassPermissions'] },
  ] },
  codex: { selects: [
    { k: 'model', label: 'model', models: true, fallback: ['gpt-5-codex', 'gpt-5'] },
    { k: 'sandbox', label: 'sandbox', values: ['default', 'read-only', 'workspace-write', 'full-auto'] },
  ] },
  cursor: { selects: [{ k: 'model', label: 'model', models: true, fallback: [] }] },
  opencode: { selects: [{ k: 'model', label: 'model', models: true, fallback: [] }] },
  gemini: { selects: [{ k: 'model', label: 'model', models: true, fallback: ['gemini-2.5-pro', 'gemini-2.5-flash'] }] },
  aider: { selects: [{ k: 'model', label: 'model', models: true, fallback: [] }] },
};
// '__'-prefixed keys are UI-only state (e.g. __live), never sent as CLI options
const cleanOpts = (o) => { const r = {}; for (const [k, v] of Object.entries(o ?? {})) if (v && v !== 'default' && !k.startsWith('__')) r[k] = v; return r; };
async function ensureAgentInfo(deviceId) {
  if (S.agentInfo.has(deviceId)) return S.agentInfo.get(deviceId);
  const r = await fsReq('agents', {}, deviceId);
  if (!r.error && r.agents) S.agentInfo.set(deviceId, r);
  return r;
}
const detectedModels = (agent, deviceId) =>
  S.agentInfo.get(deviceId)?.agents?.find((a) => a.agent === agent)?.models ?? null;
// friendly name for a raw model id, using whatever the device reported
function modelName(id) {
  if (!id) return 'unknown model';
  for (const info of S.agentInfo.values())
    for (const a of info.agents ?? [])
      for (const m of a.models ?? []) if (m.id === id) return m.name;
  return id;
}
function agentOptsControls(container, agent, store, { usage = false, deviceId = null, meta = null } = {}) {
  const def = AGENT_OPTS[agent];
  if (!def) { container.innerHTML = ''; container.hidden = true; return; }
  container.hidden = false;
  container.innerHTML = def.selects.map((s) => {
    let opts;
    if (s.models) {
      const det = detectedModels(agent, deviceId);
      const list = det?.length ? det : (s.fallback ?? []).map((id) => ({ id, name: id }));
      const opt = (m) => {
        const label = m.desc ? `${m.name} — ${m.desc}` : m.name;
        return `<option value="${esc(m.id)}" ${m.disabled ? 'disabled' : ''} ${store[s.k] === m.id ? 'selected' : ''}
          title="${esc(m.reason ?? m.desc ?? '')}">${esc(label)}${m.disabled ? ` (${esc(m.reason ?? 'unavailable')})` : ''}</option>`;
      };
      // "default" means no --model flag, so it resolves to the CLI's CONFIGURED default —
      // not to whatever model happened to serve the last turn. Labelling it with the latter
      // made a one-off pick (a single Fable turn) read as if it were the machine default.
      const cliDefault = S.agentInfo.get(deviceId)?.claudeDefaultModel ?? null;
      const live = cliDefault ? ` — ${modelName(cliDefault)}` : '';
      const aliases = list.filter((m) => m.alias).map((m) => m.id === 'default'
        ? { ...m, desc: cliDefault ? `CLI default: ${modelName(cliDefault)}` : m.desc } : m);
      const full = list.filter((m) => !m.alias);
      opts = (list.some((m) => m.id === 'default') ? ''
        : `<option value="default" ${!store[s.k] || store[s.k] === 'default' ? 'selected' : ''}>default (CLI config)${esc(live)}</option>`)
        + (aliases.length ? `<optgroup label="Recommended (CLI aliases)">${aliases.map(opt).join('')}</optgroup>` : '')
        + (full.length ? `<optgroup label="${aliases.length ? 'All models on your plan' : 'Models'}">${full.map(opt).join('')}</optgroup>` : '');
    } else {
      // plain select (mode): mirror whatever the local session is actually in
      const cur = s.live ? meta?.[s.live] : null;
      opts = s.values.map((v) => {
        const label = v === 'default'
          ? (cur ? `default — now: ${esc(cur)}` : 'default (leave as set locally)')
          : esc(v);
        return `<option value="${esc(v)}" ${(store[s.k] ?? 'default') === v ? 'selected' : ''}>${label}</option>`;
      }).join('');
    }
    return `<label class="aopt">${esc(s.label)}<select data-k="${esc(s.k)}">${opts}</select></label>`;
  }).join('')
    + (usage && def.usage ? `<button type="button" class="btn ghost small" id="usageBtn">usage</button>` : '')
    + (usage ? `<label class="aopt live" id="liveWrap" hidden><input type="checkbox" id="liveChk"> <span id="liveLbl">live terminal</span></label>` : '');
  container.querySelectorAll('select').forEach((el) => el.addEventListener('change', () => { store[el.dataset.k] = el.value; }));
  container.querySelector('#usageBtn')?.addEventListener('click', openUsage);
  const chk = container.querySelector('#liveChk');
  if (chk) {
    chk.checked = !!store.__live;
    chk.addEventListener('change', () => { store.__live = chk.checked; syncOptsForLive(chk.checked); });
    syncOptsForLive(!!store.__live);
    refreshLiveTarget(store); // async: reveals the toggle only if a live pane exists
  }
}

// Live delivery drives the TUI that is already running — `/model <id>` sets the model and
// shift+tab cycles the permission mode — so both selections still apply. Only these two
// modes sit off that cycle: they can be set when a session starts, and not after.
const LIVE_OFF_CYCLE = ['bypassPermissions', 'dontAsk'];
function syncOptsForLive(on) {
  const sel = $('agentOpts')?.querySelector('select[data-k="mode"]');
  if (!sel) return;
  for (const el of sel.options) {
    if (!LIVE_OFF_CYCLE.includes(el.value)) continue;
    el.disabled = on;
    el.title = on ? 'Only settable when a session starts — untick "live terminal" to run with this mode.' : '';
  }
  if (on && LIVE_OFF_CYCLE.includes(sel.value)) { // don't leave a mode selected that can't be sent
    sel.value = 'default';
    const store = S.agentOpts.get(S.current);
    if (store) store.mode = 'default';
  }
}
async function openUsage() {
  $('usageBody').innerHTML = '<p class="ihint">fetching usage…</p>';
  $('usageDlg').showModal();
  const r = await fsReq('usage');
  if (r.error) { $('usageBody').innerHTML = `<p class="ihint">${esc(r.error)}</p>`; return; }
  const fmt = (n) => (n ?? 0) >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : (n ?? 0) >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n ?? 0);
  const fmtIn = (iso) => {
    const sec = (new Date(iso) - Date.now()) / 1000;
    if (!iso || sec <= 0) return 'now';
    const h = (sec / 3600) | 0, m = ((sec % 3600) / 60) | 0;
    return h >= 48 ? `${(h / 24) | 0}d ${h % 24}h` : h ? `${h}h ${m}m` : `${m}m`;
  };
  let html = '';
  if (r.account) {
    html += `<p class="usec">Account</p>`
      + stRow('Auth method', esc(r.account.method ?? '—'))
      + stRow('Email', esc(r.account.email ?? '—'))
      + stRow('Organization', esc(r.account.org ?? '—'))
      + stRow('Plan', esc(r.account.plan ?? '—'));
  }
  html += `<p class="usec">Usage</p>`;
  if (r.limits?.length) {
    html += r.limits.map((l) => {
      const pct = Math.round(l.percent ?? 0);
      return `<div class="ubar">
        <div class="ubar-h"><span>${esc(l.label)}</span><b>${pct}%</b></div>
        <div class="umeter"><div class="ufill ${l.severity === 'warning' || pct >= 80 ? 'warn' : ''}" style="width:${Math.min(100, pct)}%"></div></div>
        ${l.resetsAt ? `<div class="ureset">Resets in ${fmtIn(l.resetsAt)}</div>` : ''}</div>`;
    }).join('');
  } else {
    html += `<p class="ihint">${esc(r.limitsError ?? 'no limit data available')}</p>`;
  }
  html += `<p class="usec">This session</p>`
    + stRow('Assistant turns', r.turns ?? 0)
    + stRow('Input tokens', fmt(r.input))
    + stRow('Output tokens', fmt(r.output))
    + stRow('Cache read', fmt(r.cacheRead))
    + stRow('Cache write', fmt(r.cacheWrite))
    + stRow('Models used', Object.entries(r.models ?? {}).map(([m, n]) => `${esc(m)} ×${n}`).join('<br>') || '—')
    + stRow('Transcript size', `${r.sizeKb ?? 0} KB`);
  $('usageBody').innerHTML = html;
}

// agent + folder picker for new sessions
const NEWS = { browsePath: null, agent: 'claude', opts: {} };

// which agent CLIs exist on the machine; default-select the one this device uses most
async function loadAgents() {
  const dev = $('newDevice').value;
  const el = $('agentPick');
  el.innerHTML = '<p class="ihint">detecting agents…</p>';
  const r = await ensureAgentInfo(dev);
  const rows = (r.agents ?? []).filter((a) => AGENTS[a.agent]);
  const usable = rows.filter((a) => !a.broken).map((a) => a.agent);
  const list = usable.length ? usable : ['claude'];
  const uses = {}; // most-used = how many known sessions on this device ran each agent
  for (const s of S.sessions.values()) if (s.deviceId === dev) uses[s.agent] = (uses[s.agent] ?? 0) + 1;
  list.sort((a, b) => (uses[b] ?? 0) - (uses[a] ?? 0) || a.localeCompare(b));
  if (!list.includes(NEWS.agent)) NEWS.agent = list[0];
  const renderSel = () => {
    el.querySelectorAll('.agchip:not(.dis)').forEach((c) => c.classList.toggle('sel', c.dataset.a === NEWS.agent));
    $('agentNote').hidden = NEWS.agent === 'claude';
    agentOptsControls($('agentOptsNew'), NEWS.agent, NEWS.opts, { deviceId: dev });
  };
  const chip = (a, ver, broken) => {
    const d = agentDef(a);
    const mark = d.img ? `<img src="${d.img}" alt="">` : `<span class="amono" style="--ac:${d.color}">${d.glyph}</span>`;
    return `<button type="button" class="agchip ${broken ? 'dis' : ''}" data-a="${esc(a)}" ${broken ? 'disabled' : ''}
      title="${broken ? 'installed but not runnable — reinstall this CLI' : esc(ver ?? '')}">${mark}<span>${esc(d.name)}</span>${
      broken ? '<span class="aguse">broken</span>' : (uses[a] ? `<span class="aguse">${uses[a]}</span>` : '')}</button>`;
  };
  el.innerHTML = list.map((a) => chip(a, rows.find((x) => x.agent === a)?.version, false)).join('')
    + rows.filter((a) => a.broken).map((a) => chip(a.agent, null, true)).join('')
    + (r.error ? `<p class="ihint">${esc(r.error)} — defaulting to Claude Code</p>` : '');
  el.querySelectorAll('.agchip:not(.dis)').forEach((b) => b.addEventListener('click', () => { NEWS.agent = b.dataset.a; NEWS.opts = {}; renderSel(); }));
  renderSel();
}
function pickCwd(p) {
  $('newCwd').value = p;
  $('projList').querySelectorAll('.prow').forEach((b) => b.classList.toggle('sel', b.dataset.p === p));
}
const projRow = (p, name, repo, extraCls = '') =>
  `<button type="button" class="prow ${extraCls}" data-p="${esc(p)}">
    <span class="fico" style="color:#7FA3C8">${SVG_FOLDER}</span>
    <span class="pname">${esc(name)}</span>${repo ? '<span class="ptag">git</span>' : ''}
    <span class="ppath">${esc(shortPath(p))}</span></button>`;
async function loadProjects() {
  const dev = $('newDevice').value;
  const el = $('projList');
  el.innerHTML = '<p class="ihint">loading…</p>';
  const r = await fsReq('projects', {}, dev);
  if (r.error) { el.innerHTML = `<p class="ihint">${esc(r.error)} — type a path above</p>`; return; }
  NEWS.home = r.home;
  const cur = $('newCwd').value.trim();
  el.innerHTML = (r.projects ?? []).map((p) =>
    projRow(p.path, p.path.split('/').pop(), p.repo, cur === p.path ? 'sel' : '')).join('')
    || '<p class="ihint">no known projects yet — browse or type a path</p>';
  el.querySelectorAll('.prow').forEach((b) => b.addEventListener('click', () => pickCwd(b.dataset.p)));
}
async function loadBrowse(p) {
  const dev = $('newDevice').value;
  const el = $('browseList');
  $('browseBox').hidden = false;
  el.innerHTML = '<p class="ihint">loading…</p>';
  const r = await fsReq('browse', { path: p ?? '.' }, dev);
  if (r.error) { el.innerHTML = `<p class="ihint">${esc(r.error)}</p>`; return; }
  NEWS.browsePath = r.path;
  NEWS.browseParent = r.parent;
  $('browsePath').textContent = shortPath(r.path);
  el.innerHTML = (r.entries ?? []).map((e) => projRow(`${r.path}/${e.name}`, e.name, e.repo)).join('')
    || '<p class="ihint">no subfolders</p>';
  // click drills in; “Use this folder” selects the level you're at
  el.querySelectorAll('.prow').forEach((b) => b.addEventListener('click', () => loadBrowse(b.dataset.p)));
}
$('browseBtn')?.addEventListener('click', () => {
  if ($('browseBox').hidden) loadBrowse(NEWS.browsePath ?? '.');
  else $('browseBox').hidden = true;
});
$('browseUp')?.addEventListener('click', () => { if (NEWS.browseParent) loadBrowse(NEWS.browseParent); });
$('browseUse')?.addEventListener('click', () => { if (NEWS.browsePath) pickCwd(NEWS.browsePath); });
$('newDevice')?.addEventListener('change', () => { NEWS.browsePath = null; $('browseBox').hidden = true; loadAgents(); loadProjects(); });

async function openPairing() {
  const pairingToken = b64u.enc(randBytes(16));
  const codeHash = await sha256hex(pairingToken);
  const res = await fetch('/api/pairings', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.clientToken}`, 'x-account-id': cfg.accountId },
    body: JSON.stringify({ codeHash }),
  });
  if (!res.ok) return alert('could not create pairing');
  const code = 'TETHER1.' + b64u.enc(new TextEncoder().encode(JSON.stringify({ a: cfg.accountId, k: cfg.accountSecret, t: pairingToken })));
  // Point people at the published package, and at THIS relay — not a dev checkout and not
  // localhost. A global install (rather than npx) is required: the background service
  // records the script's path, and an npx temp directory disappears after the run.
  const cmd = `npm i -g ${TETHERD_PKG}\ntetherd connect '${code}' --relay ${location.origin}`;
  $('pairCmd').textContent = cmd;
  $('pairCopy').onclick = () => navigator.clipboard.writeText(cmd);
  pairDlg.showModal();
}

// Actionable alerts (approvals, needs-input) must reach you even with the tab focused:
// a desktop notification when possible, always a sound + tab-title badge as a fallback.
function notify(title, body, { urgent = false } = {}) {
  if (urgent && NOTIF_PREF.sound) beep();
  if (!('Notification' in window)) return;
  if (!NOTIF_PREF.banners) return; // the user turned banners off — honour it, whatever the browser allows
  if (Notification.permission === 'granted') {
    // when the tab is focused a banner is noise for routine events, but an urgent
    // one (something is blocked waiting on you) is worth showing regardless
    if (document.visibilityState === 'visible' && !urgent) return;
    // A unique tag per alert, with renotify on. With tag=title the second "Approval needed:
    // Bash" silently REPLACED the first — no sound, no banner — so repeat prompts vanished.
    try {
      new Notification(title, { body: String(body ?? '').slice(0, 180), tag: `${title}#${Date.now()}`, renotify: true });
    } catch {}
  } else if (Notification.permission === 'default') {
    syncNotifButton(); // make the "alerts are off" state visible right now, not after the fact
  }
}

// Reflect the real permission state on the button from the moment the page loads. Before
// this, the button read "Notify" in neutral styling whether alerts were off, blocked or on —
// so someone who never clicked it had no way to know every alert was being dropped.
function syncNotifButton() {
  const b = $('notifBtn');
  if (!b) return;
  const label = b.querySelector('span');
  const supported = 'Notification' in window;
  const p = supported ? Notification.permission : 'unsupported';
  const muted = p === 'granted' && !NOTIF_PREF.banners; // allowed by the browser, turned off by you
  b.classList.toggle('needs', p === 'default');
  b.classList.toggle('denied', p === 'denied' || p === 'unsupported');
  b.classList.toggle('on', p === 'granted' && !muted);
  b.classList.toggle('muted', muted);
  if (label) label.textContent = muted ? 'Alerts off' : { default: 'Enable alerts', denied: 'Alerts blocked', granted: 'Alerts on', unsupported: 'No alerts' }[p];
  b.title = muted ? 'Banners are turned off in Tether. Click to change.' : {
    default: 'Browser notifications are OFF — click to allow them. Until then, every alert is dropped.',
    denied: 'Your browser is blocking notifications for this site. Re-enable them via the lock icon in the address bar.',
    granted: 'Alerts are on. Click for settings and a test alert.',
    unsupported: 'Notifications need a secure origin: use https://, or open the app on localhost / 127.0.0.1.',
  }[p];
}
let audioCtx = null;
function beep() {
  try {
    audioCtx = audioCtx ?? new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.type = 'sine'; o.frequency.value = 880;
    g.gain.setValueAtTime(0.0001, audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.12, audioCtx.currentTime + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.35);
    o.connect(g); g.connect(audioCtx.destination);
    o.start(); o.stop(audioCtx.currentTime + 0.36);
  } catch {}
}

// ---------------------------------------------------------------- boot
function boot() {
  $('setup').hidden = true;
  $('main').hidden = false;
  syncNotifButton(); // show the real alert state immediately, not after the first missed one
  connect();
  setInterval(renderFleet, 30_000); // refresh timeago
}

$('createBtn')?.addEventListener('click', createAccount);
$('signinBtn')?.addEventListener('click', signIn);
// Sign in and Create account share one form. The segmented control sets data-mode on the
// card, CSS shows the matching copy and button, and Enter submits whichever mode is active —
// before this, Enter always meant "sign in", even with Create account in front of you.
const authCard = $('authCard');
function setAuthMode(mode) {
  if (!authCard) return;
  authCard.dataset.mode = mode;
  $('modeSignin')?.setAttribute('aria-selected', String(mode === 'signin'));
  $('modeCreate')?.setAttribute('aria-selected', String(mode === 'create'));
  // tells password managers whether to offer a saved password or generate a new one
  $('setupPass')?.setAttribute('autocomplete', mode === 'create' ? 'new-password' : 'current-password');
  $('setupErr').textContent = '';
}
$('modeSignin')?.addEventListener('click', () => setAuthMode('signin'));
$('modeCreate')?.addEventListener('click', () => setAuthMode('create'));
const submitAuth = () => (authCard?.dataset.mode === 'create' ? createAccount() : signIn());
$('setupPass')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitAuth(); });
$('setupName')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitAuth(); });
$('loginCode')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') loginWithCode(); });
$('attachBtn2')?.addEventListener('click', attachEmailLogin);
$('loginBtn')?.addEventListener('click', loginWithCode);
$('linkBtn')?.addEventListener('click', openLink);
$('logoutBtn')?.addEventListener('click', () => {
  // Logging out is purely local — it clears this browser and calls nothing on the relay.
  // Paired machines authenticate over their own Ed25519 device keys, so they keep syncing
  // and never need re-pairing. Only an account with no email login is actually at risk, so
  // don't show that warning to everyone: it made a safe action look destructive.
  if (!cfg?.email) {
    // Offer the remedy rather than just naming it: this dialog is the first time most people
    // learn the account has no way back in, and the fix is two fields away.
    if (confirm('This account has no email login yet, so logging out would leave no way back in except a one-time code from another signed-in device.\n\nSet an email + password now? Your machines keep running either way.\n\nOK = set it up · Cancel = log out anyway')) {
      openLink(); // the same dialog carries "set an email login for this account"
      return;
    }
    if (!confirm('Log out anyway and forget this account on this browser?\n\nWithout an email login or a link code from another device, the encryption key cannot be recovered.')) return;
  } else if (!confirm(`Log out on this browser?\n\nYour paired machines stay connected and keep syncing — this only clears this browser. Sign back in any time as ${cfg.email}.`)) {
    return;
  }
  localStorage.removeItem('tether');
  location.reload();
});
$('pairBtn')?.addEventListener('click', openPairing);
$('reconnBtn')?.addEventListener('click', () => connect());
$('stPing')?.addEventListener('click', () => { if (statusDev) send({ type: 'device_ping', deviceId: statusDev }); });
$('stDisconnect')?.addEventListener('click', async () => {
  const d = statusDev && S.devices.get(statusDev);
  if (!d) return;
  if (!confirm(`Disconnect "${d.name}"?\n\nThis removes Tether's hooks from every AI agent on that machine and stops its sync service. Existing chat history stays here; reconnect later with: tetherd connect`)) return;
  const btn = $('stDisconnect');
  btn.disabled = true; btn.textContent = 'Disconnecting…';
  const r = await fsReq('disconnect', {}, statusDev);
  btn.disabled = false; btn.textContent = 'Disconnect machine';
  if (r.error) return alert(`Could not disconnect: ${r.error}`);
  alert(`Disconnected.\n\n${(r.results ?? []).join('\n')}`);
  $('statusDlg').close();
});
// Two separate things decide whether you get a banner: the BROWSER's permission (can it show
// one at all) and YOUR preference (do you want them). The button used to handle only the
// first. These are the second — per browser, default on.
const NOTIF_PREF = {
  get banners() { try { return localStorage.getItem('tether.alerts') !== 'off'; } catch { return true; } },
  set banners(v) { try { localStorage.setItem('tether.alerts', v ? 'on' : 'off'); } catch {} },
  get sound() { try { return localStorage.getItem('tether.sound') !== 'off'; } catch { return true; } },
  set sound(v) { try { localStorage.setItem('tether.sound', v ? 'on' : 'off'); } catch {} },
};

function openNotifDlg() {
  const supported = 'Notification' in window;
  const p = supported ? Notification.permission : 'unsupported';
  $('notifStatus').textContent = {
    granted: 'Your browser allows notifications for this site.',
    default: 'Your browser has not been asked yet — turn Banners on to be asked.',
    denied: 'Your browser is BLOCKING notifications for this site. Allow them via the lock icon in the address bar, then reload.',
    unsupported: 'No notification support on this origin. Use https://, or open Tether on localhost / 127.0.0.1.',
  }[p];
  $('notifBanners').checked = NOTIF_PREF.banners && p === 'granted';
  $('notifBanners').disabled = p === 'denied' || p === 'unsupported';
  $('notifSound').checked = NOTIF_PREF.sound;
  $('notifTest').disabled = p !== 'granted';
  $('notifResult').textContent = '';
  $('notifDlg').showModal();
}

$('notifBtn')?.addEventListener('click', openNotifDlg);

$('notifBanners')?.addEventListener('change', async (e) => {
  if (e.target.checked && Notification.permission === 'default') {
    // Turning banners on IS the user gesture the browser needs for the permission prompt.
    const r = await Notification.requestPermission();
    if (r !== 'granted') e.target.checked = false;
  }
  NOTIF_PREF.banners = e.target.checked;
  syncNotifButton();
  openNotifDlg(); // re-render status/checkbox from the real state
});
$('notifSound')?.addEventListener('change', (e) => { NOTIF_PREF.sound = e.target.checked; syncNotifButton(); });

// The test answers "does a banner actually appear?" without guesswork: the Notification
// object tells us whether the browser displayed it. Beep + shown = working. Beep + not shown
// within 2.5s = the browser was allowed to try but macOS swallowed it (Notification settings
// for the browser app, or a Focus mode). That distinction is invisible any other way.
$('notifTest')?.addEventListener('click', () => {
  const out = $('notifResult');
  out.textContent = 'sending…';
  if (NOTIF_PREF.sound) beep();
  let settled = false;
  const done = (msg) => { if (!settled) { settled = true; out.textContent = msg; } };
  try {
    const n = new Notification('Tether test alert', { body: 'If you can read this, banners work end to end.', tag: `test#${Date.now()}`, renotify: true });
    n.onshow = () => done('✓ Banner shown by the browser.');
    n.onerror = () => done('✗ The browser reported an error showing it.');
    n.onclick = () => { window.focus(); n.close(); };
    setTimeout(() => done('Sent, but the browser never reported it as shown — macOS is blocking notifications for this browser, or a Focus mode is on. Check System Settings → Notifications.'), 2500);
  } catch (e) { done(`✗ ${e.message}`); }
});

// Browsers only allow the permission request from a user gesture. Rather than wait for a
// click on the one button, ask on the FIRST click anywhere in the app while it is still
// undecided — once per page load. Anyone who says no is never asked again by this path.
if ('Notification' in window && Notification.permission === 'default') {
  document.addEventListener('click', async function askOnce() {
    document.removeEventListener('click', askOnce);
    try { await Notification.requestPermission(); } catch {}
    syncNotifButton();
  }, { once: true });
}
$('newBtn')?.addEventListener('click', () => {
  $('newDevice').innerHTML = [...S.devices.values()].map((d) => `<option value="${esc(d.id)}" ${d.online ? '' : 'disabled'}>${esc(d.name)}${d.online ? '' : ' (offline)'}</option>`).join('');
  NEWS.browsePath = null;
  $('browseBox').hidden = true;
  newDlg.showModal();
  loadAgents();
  loadProjects();
});
$('newGo')?.addEventListener('click', (e) => { e.preventDefault(); newSession(); });

// follow-the-latest: ONLY a deliberate upward scroll detaches (programmatic pins and
// streaming re-renders always move down, so they can never break tracking); reaching
// the bottom re-attaches. A safety loop keeps the view glued while following even when
// content grows without firing a scroll event (image loads, expanding tool output).
let pinGuard = 0, lastTop = 0;
function pinToLatest(smooth = false) {
  const el = $('transcript');
  pinGuard = Date.now() + (smooth ? 1200 : 300);
  if (smooth) {
    el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  } else {
    el.style.scrollBehavior = 'auto';
    el.scrollTop = el.scrollHeight;
    el.style.scrollBehavior = '';
  }
}
function setFollow(on) {
  if (S.follow === on) return;
  S.follow = on;
  const j = $('jumpLatest');
  if (j) j.hidden = on;
}
$('transcript')?.addEventListener('scroll', () => {
  const el = $('transcript');
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  const goingUp = el.scrollTop < lastTop - 1;
  lastTop = el.scrollTop;
  if (atBottom) setFollow(true);
  else if (goingUp && Date.now() > pinGuard) setFollow(false);
}, { passive: true });
setInterval(() => {
  if (!S.follow || !S.current || Date.now() < pinGuard) return;
  const el = $('transcript');
  if (el.scrollHeight - el.scrollTop - el.clientHeight >= 2) pinToLatest();
}, 600);

// Native scrollbars are hidden everywhere (style.css). Instead one overlay thumb per axis is drawn
// over whichever element the *user* is scrolling and fades out once they stop, so nothing is
// visible while the page is still. Programmatic scrolls — the transcript pinning itself to a
// streaming reply — never reveal them; they only keep an already-visible thumb accurate. Scroll
// events don't bubble, so everything is caught in the capture phase.
const SB_LINGER_MS = 900, SB_MIN = 24, SB_GAP = 2, SB_SIZE = 6;
const sbThumbs = {
  y: Object.assign(document.createElement('div'), { className: 'sb-thumb sb-y' }),
  x: Object.assign(document.createElement('div'), { className: 'sb-thumb sb-x' }),
};
document.body.append(sbThumbs.y, sbThumbs.x);
let sbTarget = null, sbHideTimer = 0, sbDrag = null, userScrollUntil = 0;
const isRoot = (el) => el === document.documentElement;
const sbMetrics = (el, axis) => (axis === 'y'
  ? { view: isRoot(el) ? window.innerHeight : el.clientHeight, total: el.scrollHeight, pos: el.scrollTop }
  : { view: isRoot(el) ? window.innerWidth : el.clientWidth, total: el.scrollWidth, pos: el.scrollLeft });
// Position both thumbs for `el`; returns which axes actually overflow.
function sbPlace(el) {
  const rect = isRoot(el)
    ? { top: 0, left: 0, right: window.innerWidth, bottom: window.innerHeight }
    : el.getBoundingClientRect();
  const shown = { y: false, x: false };
  for (const axis of ['y', 'x']) {
    const t = sbThumbs[axis], { view, total, pos } = sbMetrics(el, axis);
    if (view <= 0 || total <= view + 1) continue;
    shown[axis] = true;
    const track = view - SB_GAP * 2, len = Math.max(SB_MIN, Math.round(track * view / total));
    const off = SB_GAP + (track - len) * (pos / (total - view));
    if (axis === 'y') {
      t.style.height = `${len}px`; t.style.top = `${rect.top + off}px`; t.style.left = `${rect.right - SB_GAP - SB_SIZE}px`;
    } else {
      t.style.width = `${len}px`; t.style.left = `${rect.left + off}px`; t.style.top = `${rect.bottom - SB_GAP - SB_SIZE}px`;
    }
  }
  return shown;
}
const sbHide = () => { sbThumbs.y.classList.remove('on'); sbThumbs.x.classList.remove('on'); };
function sbShow(el) {
  const shown = sbPlace(el);
  if (!shown.y && !shown.x) return;
  sbTarget = el;
  sbThumbs.y.classList.toggle('on', shown.y);
  sbThumbs.x.classList.toggle('on', shown.x);
  clearTimeout(sbHideTimer);
  sbHideTimer = setTimeout(() => { if (!sbDrag) sbHide(); }, SB_LINGER_MS);
}
const noteUserScroll = (ms = 200) => { userScrollUntil = Math.max(userScrollUntil, Date.now() + ms); };
const passiveCapture = { capture: true, passive: true };
window.addEventListener('wheel', () => noteUserScroll(), passiveCapture);
window.addEventListener('touchmove', () => noteUserScroll(), passiveCapture);
window.addEventListener('touchend', () => noteUserScroll(1500), passiveCapture); // momentum after lift
window.addEventListener('keydown', (e) => {
  if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PageUp', 'PageDown', 'Home', 'End', ' '].includes(e.key)) noteUserScroll();
}, passiveCapture);
document.addEventListener('scroll', (e) => {
  const el = e.target === document ? document.documentElement : e.target;
  if (!(el instanceof Element)) return;
  if (sbDrag?.el === el || Date.now() <= userScrollUntil) sbShow(el);
  else if (sbTarget === el && (sbThumbs.y.classList.contains('on') || sbThumbs.x.classList.contains('on'))) sbPlace(el);
}, passiveCapture);
window.addEventListener('resize', sbHide);
// The thumbs can be dragged like real scrollbars.
for (const axis of ['y', 'x']) {
  const t = sbThumbs[axis];
  t.addEventListener('pointerdown', (e) => {
    if (!sbTarget) return;
    const { pos } = sbMetrics(sbTarget, axis);
    sbDrag = { el: sbTarget, axis, start: axis === 'y' ? e.clientY : e.clientX, pos, behavior: sbTarget.style.scrollBehavior };
    sbTarget.style.scrollBehavior = 'auto'; // a drag must track the pointer, not glide after it
    t.classList.add('drag');
    t.setPointerCapture(e.pointerId);
    clearTimeout(sbHideTimer);
    e.preventDefault();
  });
  t.addEventListener('pointermove', (e) => {
    if (!sbDrag || sbDrag.axis !== axis) return;
    const { view, total } = sbMetrics(sbDrag.el, axis);
    const len = parseFloat(axis === 'y' ? t.style.height : t.style.width), track = view - SB_GAP * 2 - len;
    if (track <= 0) return;
    const delta = ((axis === 'y' ? e.clientY : e.clientX) - sbDrag.start) * (total - view) / track;
    if (axis === 'y') sbDrag.el.scrollTop = sbDrag.pos + delta; else sbDrag.el.scrollLeft = sbDrag.pos + delta;
  });
  const end = () => {
    if (!sbDrag || sbDrag.axis !== axis) return;
    sbDrag.el.style.scrollBehavior = sbDrag.behavior;
    sbDrag = null;
    t.classList.remove('drag');
    sbHideTimer = setTimeout(sbHide, SB_LINGER_MS);
  };
  t.addEventListener('pointerup', end);
  t.addEventListener('pointercancel', end);
}

// resizable session list — drag the divider; width survives reloads, double-click resets
(() => {
  const rz = $('fleetResize');
  if (!rz) return;
  const clamp = (px) => Math.min(560, Math.max(220, px));
  const apply = (px) => document.documentElement.style.setProperty('--fleetw', `${px}px`);
  let w = 0;
  try { w = parseInt(localStorage.getItem('tether.fleetw'), 10) || 0; } catch {}
  if (w) apply(clamp(w));
  rz.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    rz.setPointerCapture(e.pointerId);
    rz.classList.add('dragging');
    const left = $('fleetWrap').getBoundingClientRect().left;
    const move = (ev) => { w = clamp(Math.round(ev.clientX - left)); apply(w); };
    const up = () => {
      rz.classList.remove('dragging');
      rz.removeEventListener('pointermove', move);
      rz.removeEventListener('pointerup', up);
      rz.removeEventListener('pointercancel', up);
      try { localStorage.setItem('tether.fleetw', String(w)); } catch {}
    };
    rz.addEventListener('pointermove', move);
    rz.addEventListener('pointerup', up);
    rz.addEventListener('pointercancel', up);
  });
  rz.addEventListener('dblclick', () => {
    apply(296);
    try { localStorage.removeItem('tether.fleetw'); } catch {}
  });
})();
$('composer')?.addEventListener('submit', (e) => { e.preventDefault(); sendPrompt(); });
$('attachBtn')?.addEventListener('click', () => $('attachFile').click());
$('attachFile')?.addEventListener('change', async (e) => { for (const f of e.target.files) await addImage(f); e.target.value = ''; });
$('promptText')?.addEventListener('paste', (e) => {
  const files = [...(e.clipboardData?.items ?? [])].filter((it) => it.kind === 'file' && it.type.startsWith('image/')).map((it) => it.getAsFile());
  if (files.length) { e.preventDefault(); files.forEach(addImage); }
});
$('composer')?.addEventListener('dragover', (e) => { if ([...e.dataTransfer.types].includes('Files')) { e.preventDefault(); $('composer').classList.add('dragover'); } });
$('composer')?.addEventListener('dragleave', () => $('composer').classList.remove('dragover'));
$('composer')?.addEventListener('drop', (e) => {
  e.preventDefault(); $('composer').classList.remove('dragover');
  [...e.dataTransfer.files].forEach(addImage);
});
// A one-row box hides everything above the last line while you write. Grow it with the text
// up to a ceiling, then let it scroll.
const AUTOSIZE_MAX = 200;
function autosize(el) {
  if (!el) return;
  el.style.height = 'auto';
  el.style.height = `${Math.min(el.scrollHeight, AUTOSIZE_MAX)}px`;
}
// Enter sends, shift+Enter is a newline — but only where there is a real keyboard. On a touch
// device shift+Enter is impractical, so Enter stays a newline there and the send button sends.
const ENTER_SENDS = window.matchMedia('(pointer: fine)').matches;
$('promptText')?.addEventListener('input', (e) => autosize(e.target));
$('newText')?.addEventListener('input', (e) => autosize(e.target));
$('promptText')?.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' || e.isComposing) return; // never break IME composition
  if (e.metaKey || e.ctrlKey || (ENTER_SENDS && !e.shiftKey)) { e.preventDefault(); sendPrompt(); }
});

window.addEventListener('unhandledrejection', (e) => {
  const el = $('setupErr');
  if (el && !$('setup').hidden) el.textContent = `Error: ${e.reason?.message ?? e.reason}`;
});

// Back gesture / browser back: return to the list instead of unloading the app.
addEventListener('popstate', () => document.body.classList.remove('on-pane'));

if (cfg?.accountId) boot();
else $('setup').hidden = false;
