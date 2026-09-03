#!/usr/bin/env node
// Tether relay: WebSocket gateway + pairing REST + ciphertext store + serves the app.
// It can route and push but never read a transcript (plan §3.2, §6).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { openDb } from './db.mjs';
import { verifyNonce, sha256hex, randHex, randB64u } from '../daemon/crypto.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.join(HERE, '..', 'app');
const DB_PATH = process.env.TETHER_DB ?? path.join(os.homedir(), '.tether', 'relay.sqlite');
const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? '127.0.0.1';

const db = openDb(DB_PATH);
const log = (m) => console.log(`${new Date().toISOString()} ${m}`);
const now = () => Date.now();

// live connections
const daemons = new Map();  // deviceId -> ws
const deviceSyncing = new Map(); // deviceId -> bool (true while backfilling)
const deviceHealth = new Map(); // deviceId -> {healthCt, at} — opaque e2e blob, kept for fleet snapshots
const pendingFs = new Map();    // reqId -> {ws, at} — which client asked; payloads stay opaque
const loginTries = new Map();   // email -> {n, at} — throttle brute-force logins
const clients = new Set();  // ws (ws.meta = {accountId, name, subs:Set<"dev/sid">})

const q = {
  accountByToken: db.prepare('SELECT * FROM accounts WHERE id = ? AND token_hash = ?'),
  insertAccount: db.prepare('INSERT INTO accounts(id, name, token_hash, created_at) VALUES (?,?,?,?)'),
  accountById: db.prepare('SELECT * FROM accounts WHERE id = ?'),
  insertPairing: db.prepare('INSERT INTO pairings(id, account_id, code_hash, expires_at) VALUES (?,?,?,?)'),
  insertClient: db.prepare('INSERT INTO clients(id, account_id, name, token_hash, created_at, last_seen) VALUES (?,?,?,?,?,?)'),
  clientByToken: db.prepare('SELECT * FROM clients WHERE account_id = ? AND token_hash = ?'),
  touchClient: db.prepare('UPDATE clients SET last_seen = ? WHERE id = ?'),
  accountByEmail: db.prepare('SELECT * FROM accounts WHERE email = ?'),
  setAccountLogin: db.prepare('UPDATE accounts SET email = ?, pass_salt = ?, auth_hash = ?, key_ct = ? WHERE id = ?'),
  insertAccountFull: db.prepare('INSERT INTO accounts(id, name, token_hash, created_at, email, pass_salt, auth_hash, key_ct) VALUES (?,?,?,?,?,?,?,?)'),
  insertClientLink: db.prepare('INSERT INTO client_links(id, account_id, code_hash, expires_at) VALUES (?,?,?,?)'),
  findClientLink: db.prepare('SELECT * FROM client_links WHERE account_id = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?'),
  useClientLink: db.prepare('UPDATE client_links SET used_at = ? WHERE id = ?'),
  findPairing: db.prepare('SELECT * FROM pairings WHERE account_id = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?'),
  usePairing: db.prepare('UPDATE pairings SET used_at = ? WHERE id = ?'),
  insertDevice: db.prepare('INSERT INTO devices(id, account_id, name, platform, pubkey, paired_at, last_seen) VALUES (?,?,?,?,?,?,?)'),
  deviceById: db.prepare('SELECT * FROM devices WHERE id = ?'),
  devicesByAccount: db.prepare('SELECT * FROM devices WHERE account_id = ?'),
  touchDevice: db.prepare('UPDATE devices SET last_seen = ? WHERE id = ?'),
  upsertSession: db.prepare(`INSERT INTO sessions(device_id, session_id, agent, state, meta_ct, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?)
    ON CONFLICT(device_id, session_id) DO UPDATE SET agent=excluded.agent, state=excluded.state, meta_ct=excluded.meta_ct, updated_at=excluded.updated_at`),
  setSessionState: db.prepare('UPDATE sessions SET state = ?, updated_at = ? WHERE device_id = ? AND session_id = ?'),
  setSessionNote: db.prepare('UPDATE sessions SET note_ct = ? WHERE device_id = ? AND session_id = ?'),
  sessionsByAccount: db.prepare(`SELECT s.* FROM sessions s JOIN devices d ON d.id = s.device_id
    WHERE d.account_id = ? ORDER BY s.updated_at DESC LIMIT 200`),
  insertEvent: db.prepare('INSERT OR IGNORE INTO events(device_id, session_id, seq, ts, ct) VALUES (?,?,?,?,?)'),
  maxSeqBySession: db.prepare('SELECT session_id, MAX(seq) AS m FROM events WHERE device_id = ? GROUP BY session_id'),
  lastEvents: db.prepare('SELECT seq, ts, ct FROM events WHERE device_id = ? AND session_id = ? ORDER BY seq DESC LIMIT ?'),
  eventsBefore: db.prepare('SELECT seq, ts, ct FROM events WHERE device_id = ? AND session_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?'),
  deleteEvents: db.prepare('DELETE FROM events WHERE device_id = ? AND session_id = ?'),
  insertApproval: db.prepare('INSERT INTO approvals(id, device_id, session_id, request_ct, status, deadline, created_at) VALUES (?,?,?,?,?,?,?)'),
  decideApproval: db.prepare("UPDATE approvals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'"),
  expireApproval: db.prepare("UPDATE approvals SET status = 'expired' WHERE id = ? AND status = 'pending'"),
  pendingForDevice: db.prepare("SELECT id FROM approvals WHERE device_id = ? AND status = 'pending'"),
  approvalById: db.prepare('SELECT * FROM approvals WHERE id = ?'),
  pendingApprovals: db.prepare(`SELECT a.* FROM approvals a JOIN devices d ON d.id = a.device_id
    WHERE d.account_id = ? AND a.status = 'pending' AND a.deadline > ? ORDER BY a.created_at`),
  insertPrompt: db.prepare('INSERT INTO prompts(id, device_id, session_id, body_ct, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)'),
  updatePrompt: db.prepare('UPDATE prompts SET status = ?, detail = ?, updated_at = ? WHERE id = ?'),
  promptById: db.prepare('SELECT * FROM prompts WHERE id = ?'),
  queuedPrompts: db.prepare("SELECT * FROM prompts WHERE device_id = ? AND status = 'queued' ORDER BY created_at"),
  recentPrompts: db.prepare(`SELECT p.* FROM prompts p JOIN devices d ON d.id = p.device_id
    WHERE d.account_id = ? ORDER BY p.created_at DESC LIMIT 20`),
};

// ------------------------------------------------------------------ helpers
const send = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };
// accepts the original registration token or any linked client's token
function authAccount(accountId, token) {
  const h = sha256hex(token ?? '');
  const acc = q.accountByToken.get(accountId, h);
  if (acc) return { account: acc, client: null };
  const cl = q.clientByToken.get(accountId, h);
  if (cl) {
    q.touchClient.run(now(), cl.id);
    return { account: q.accountById.get(accountId), client: cl };
  }
  return null;
}
const accountOfDevice = (deviceId) => q.deviceById.get(deviceId)?.account_id ?? null;

// Daemons need to know whether anyone is actually watching: with no client connected,
// a PreToolUse gate must not stall the local terminal waiting for a remote decision.
function clientCount(accountId) {
  let n = 0;
  for (const ws of clients) if (ws.meta?.accountId === accountId) n++;
  return n;
}
function notifyDaemonsOfClients(accountId) {
  const watchers = clientCount(accountId);
  for (const [deviceId, dws] of daemons) {
    if (q.deviceById.get(deviceId)?.account_id === accountId) send(dws, { type: 'clients_present', watchers });
  }
}

function broadcast(accountId, obj, { onlySubscribedTo = null } = {}) {
  for (const ws of clients) {
    if (ws.meta?.accountId !== accountId) continue;
    if (onlySubscribedTo && !ws.meta.subs.has(onlySubscribedTo)) continue;
    send(ws, obj);
  }
}

function fleetSnapshot(accountId) {
  const online = new Set(daemons.keys());
  const devices = q.devicesByAccount.all(accountId).map((d) => ({
    id: d.id, name: d.name, platform: d.platform, lastSeen: d.last_seen,
    online: online.has(d.id), syncing: online.has(d.id) && deviceSyncing.get(d.id) === true,
    healthCt: deviceHealth.get(d.id)?.healthCt ?? null, healthAt: deviceHealth.get(d.id)?.at ?? null,
  }));
  // A session the daemon last touched long ago is not still "running" — a daemon restart
  // or crash can strand a live-looking state forever. Report what we can actually justify.
  const STALE_MS = 10 * 60_000;
  const sessions = q.sessionsByAccount.all(accountId).map((s) => {
    const stale = s.updated_at && (now() - s.updated_at) > STALE_MS;
    // 'waiting_input' is legitimately long-lived — a session can sit asking for hours,
    // and that is precisely what the user needs to see. Only states that imply ongoing
    // work (or a short deadline) can go stale.
    const live = s.state === 'running' || s.state === 'waiting_approval';
    return {
      deviceId: s.device_id, sessionId: s.session_id, agent: s.agent,
      state: stale && live ? 'idle' : s.state,
      metaCt: s.meta_ct, updatedAt: s.updated_at,
      noteCt: s.state === 'waiting_input' ? s.note_ct : null,
    };
  });
  const approvals = q.pendingApprovals.all(accountId, now()).map((a) => ({
    approvalId: a.id, deviceId: a.device_id, sessionId: a.session_id,
    requestCt: a.request_ct, deadline: a.deadline,
  }));
  const prompts = q.recentPrompts.all(accountId).map((p) => ({
    promptId: p.id, deviceId: p.device_id, sessionId: p.session_id, status: p.status, detail: p.detail,
  }));
  return { type: 'fleet', devices, sessions, approvals, prompts };
}

// ------------------------------------------------------------------ daemon messages
function onDaemonMessage(ws, m) {
  const deviceId = ws.meta.deviceId;
  const accountId = ws.meta.accountId;
  switch (m.type) {
    case 'session_upsert': {
      const t = now();
      q.upsertSession.run(deviceId, m.sessionId, m.agent ?? 'claude', m.state ?? 'idle', m.metaCt ?? null, t, t);
      broadcast(accountId, { type: 'session_upsert', deviceId, sessionId: m.sessionId, agent: m.agent, state: m.state, metaCt: m.metaCt, updatedAt: t });
      break;
    }
    case 'events_append': {
      if (!Array.isArray(m.events) || !m.events.length) break;
      let upTo = 0;
      for (const ev of m.events) {
        q.insertEvent.run(deviceId, m.sessionId, ev.seq, ev.ts ?? null, ev.ct);
        upTo = Math.max(upTo, ev.seq);
      }
      send(ws, { type: 'ack', sessionId: m.sessionId, upTo });
      broadcast(accountId, { type: 'events', deviceId, sessionId: m.sessionId, events: m.events },
        { onlySubscribedTo: `${deviceId}/${m.sessionId}` });
      break;
    }
    case 'state_change': {
      q.setSessionState.run(m.state, now(), deviceId, m.sessionId);
      // keep the open question with the session (and clear it once unblocked) so a client
      // that connects later still sees what the agent is asking
      q.setSessionNote.run(m.state === 'waiting_input' ? (m.noteCt ?? null) : null, deviceId, m.sessionId);
      broadcast(accountId, { type: 'state_change', deviceId, sessionId: m.sessionId, state: m.state, noteCt: m.noteCt });
      break;
    }
    case 'session_reset': {
      q.deleteEvents.run(deviceId, m.sessionId);
      broadcast(accountId, { type: 'session_reset', deviceId, sessionId: m.sessionId });
      break;
    }
    case 'approval_open': {
      q.insertApproval.run(m.approvalId, deviceId, m.sessionId, m.requestCt, 'pending', m.deadline, now());
      broadcast(accountId, { type: 'approval_open', approvalId: m.approvalId, deviceId, sessionId: m.sessionId, requestCt: m.requestCt, deadline: m.deadline });
      break;
    }
    case 'approval_update': {
      // The daemon is telling us a held prompt ended without a decision from the UI:
      //   expired          — nobody answered before the deadline
      //   resolved_locally — the session moved on (answered at the machine, or cancelled)
      //   approved_locally — the tool ran, so it was approved at the machine or by auto mode
      // All three retire the card; only the label differs. Anything else is ignored.
      const st = m.status;
      if (st === 'expired') {
        q.expireApproval.run(m.approvalId);
        broadcast(accountId, { type: 'approval_resolved', approvalId: m.approvalId, status: 'expired' });
      } else if (st === 'resolved_locally' || st === 'approved_locally') {
        q.decideApproval.run(st, now(), 'machine', m.approvalId);
        broadcast(accountId, { type: 'approval_resolved', approvalId: m.approvalId, status: st, decidedBy: 'machine' });
      }
      break;
    }
    case 'prompt_status': {
      q.updatePrompt.run(m.status, m.detail ?? null, now(), m.promptId);
      broadcast(accountId, { type: 'prompt_status', promptId: m.promptId, status: m.status, detail: m.detail });
      break;
    }
    case 'device_sync': {
      const syncing = m.state === 'syncing';
      deviceSyncing.set(deviceId, syncing);
      broadcast(accountId, { type: 'device_sync', deviceId, syncing });
      break;
    }
    case 'daemon_status': {
      const t = now();
      deviceHealth.set(deviceId, { healthCt: m.healthCt, at: t });
      q.touchDevice.run(t, deviceId);
      broadcast(accountId, { type: 'device_health', deviceId, healthCt: m.healthCt, at: t });
      break;
    }
    case 'fs_result': {
      const p = pendingFs.get(m.reqId);
      pendingFs.delete(m.reqId);
      if (p) send(p.ws, { type: 'fs_result', reqId: m.reqId, resultCt: m.resultCt });
      break;
    }
  }
}

// ------------------------------------------------------------------ client messages
function onClientMessage(ws, m) {
  const accountId = ws.meta.accountId;
  switch (m.type) {
    case 'subscribe': {
      const key = `${m.deviceId}/${m.sessionId}`;
      ws.meta.subs.add(key);
      const events = q.lastEvents.all(m.deviceId, m.sessionId, 200).reverse();
      send(ws, { type: 'events', deviceId: m.deviceId, sessionId: m.sessionId, initial: true, events });
      break;
    }
    case 'unsubscribe': ws.meta.subs.delete(`${m.deviceId}/${m.sessionId}`); break;
    case 'load_earlier': {
      const events = q.eventsBefore.all(m.deviceId, m.sessionId, m.beforeSeq, 200).reverse();
      send(ws, { type: 'events', deviceId: m.deviceId, sessionId: m.sessionId, earlier: true, events });
      break;
    }
    case 'approve': {
      const a = q.approvalById.get(m.approvalId);
      if (!a || accountOfDevice(a.device_id) !== accountId) return send(ws, { type: 'error', message: 'unknown approval' });
      const decision = m.decision === 'allow' ? 'allow' : 'deny';
      const status = decision === 'allow' ? 'approved' : 'denied';
      // Atomic: the WHERE status='pending' clause means only ONE concurrent decision
      // flips the row. If we didn't change a row, another device already decided —
      // tell only this client the real outcome and do NOT re-broadcast or re-notify the daemon.
      const won = q.decideApproval.run(status, now(), ws.meta.name ?? 'client', m.approvalId).changes === 1;
      if (!won) {
        const settled = q.approvalById.get(m.approvalId);
        return send(ws, { type: 'approval_resolved', approvalId: m.approvalId, status: settled?.status ?? 'expired', decidedBy: settled?.decided_by ?? null, lostRace: true });
      }
      const dws = daemons.get(a.device_id);
      // answersCt carries the reply to an AskUserQuestion. Routed opaquely: it is sealed
      // with the approval's own key, so the relay moves it without being able to read it.
      if (dws) send(dws, { type: 'approval_result', approvalId: m.approvalId, decision,
                           decidedBy: ws.meta.name ?? 'client', answersCt: m.answersCt ?? null });
      broadcast(accountId, { type: 'approval_resolved', approvalId: m.approvalId, status, decidedBy: ws.meta.name ?? 'client' });
      break;
    }
    case 'prompt': {
      const dev = q.deviceById.get(m.deviceId);
      if (!dev || dev.account_id !== accountId) return send(ws, { type: 'error', message: 'unknown device' });
      const t = now();
      q.insertPrompt.run(m.promptId, m.deviceId, m.sessionId ?? null, m.bodyCt, 'queued', t, t);
      const dws = daemons.get(m.deviceId);
      if (dws) {
        send(dws, { type: 'prompt_execute', promptId: m.promptId, sessionId: m.sessionId ?? null, bodyCt: m.bodyCt });
        q.updatePrompt.run('delivered', null, now(), m.promptId);
        broadcast(accountId, { type: 'prompt_status', promptId: m.promptId, status: 'delivered' });
      } else {
        broadcast(accountId, { type: 'prompt_status', promptId: m.promptId, status: 'queued', detail: 'device offline; will deliver when it reconnects' });
      }
      break;
    }
    case 'refresh': send(ws, fleetSnapshot(accountId)); break;
    case 'fs': { // workspace inspector request — routed opaque, answered by the daemon
      const dev = q.deviceById.get(m.deviceId);
      if (!dev || dev.account_id !== accountId) return send(ws, { type: 'error', message: 'unknown device' });
      const dws = daemons.get(m.deviceId);
      if (!dws) return send(ws, { type: 'fs_result', reqId: m.reqId, error: 'device offline' });
      pendingFs.set(m.reqId, { ws, at: now() });
      send(dws, { type: 'fs_request', reqId: m.reqId, reqCt: m.reqCt });
      break;
    }
    // a client asking "is this device really alive, right now?" — answer with current
    // presence immediately and nudge the daemon for a fresh health report
    case 'device_ping': {
      const dev = q.deviceById.get(m.deviceId);
      if (!dev || dev.account_id !== accountId) return send(ws, { type: 'error', message: 'unknown device' });
      const dws = daemons.get(m.deviceId);
      send(ws, { type: 'device_presence', deviceId: m.deviceId, online: !!dws, syncing: !!dws && deviceSyncing.get(m.deviceId) === true, lastSeen: dev.last_seen });
      if (dws) send(dws, { type: 'status_request' });
      break;
    }
  }
}

// ------------------------------------------------------------------ WS auth
const wss = new WebSocketServer({ noServer: true });
wss.on('connection', (ws) => {
  const nonce = randB64u(24);
  ws.meta = null;
  send(ws, { type: 'challenge', nonce });
  const authTimer = setTimeout(() => { if (!ws.meta) ws.close(); }, 10_000);

  ws.on('message', (data) => {
    let m; try { m = JSON.parse(data); } catch { return; }
    if (m.type === 'pong') {
      ws.lastPong = now();
      if (ws.meta?.role === 'daemon') q.touchDevice.run(now(), ws.meta.deviceId);
      return;
    }
    try {
    if (!ws.meta) {
      if (m.type !== 'auth') return ws.close();
      if (m.role === 'daemon') {
        const dev = q.deviceById.get(m.deviceId);
        if (!dev || !verifyNonce(dev.pubkey, nonce, m.sig)) { log(`daemon auth failed: ${m.deviceId}`); return ws.close(); }
        ws.meta = { role: 'daemon', deviceId: dev.id, accountId: dev.account_id };
        ws.lastPong = now();
        clearTimeout(authTimer);
        daemons.get(dev.id)?.close();
        daemons.set(dev.id, ws);
        deviceSyncing.set(dev.id, true);
        q.touchDevice.run(now(), dev.id);
        const cursors = {};
        for (const r of q.maxSeqBySession.all(dev.id)) cursors[r.session_id] = r.m;
        send(ws, { type: 'authed', cursors });
        // A daemon that just connected holds no gates: whatever it was holding died with the
        // old process, and the hooks behind those cards have already exited silently. Left
        // alone, the cards would sit in the UI looking live until their deadline. Retire them.
        for (const { id } of q.pendingForDevice.all(dev.id)) {
          q.expireApproval.run(id);
          broadcast(dev.account_id, { type: 'approval_resolved', approvalId: id, status: 'expired' });
          log(`approval ${id} expired: its daemon reconnected without it`);
        }
        send(ws, { type: 'clients_present', watchers: clientCount(dev.account_id) });
        broadcast(dev.account_id, { type: 'device_presence', deviceId: dev.id, online: true, syncing: true, lastSeen: now() });
        for (const p of q.queuedPrompts.all(dev.id)) {
          send(ws, { type: 'prompt_execute', promptId: p.id, sessionId: p.session_id, bodyCt: p.body_ct });
          q.updatePrompt.run('delivered', null, now(), p.id);
        }
        log(`daemon connected: ${dev.id} (${dev.name})`);
      } else if (m.role === 'client') {
        const auth = authAccount(m.accountId, m.clientToken);
        if (!auth) { log('client auth failed'); return ws.close(); }
        ws.meta = { role: 'client', accountId: auth.account.id, name: m.name ?? auth.client?.name ?? auth.account.name ?? 'client', subs: new Set() };
        ws.lastPong = now();
        clearTimeout(authTimer);
        clients.add(ws);
        send(ws, { type: 'authed' });
        send(ws, fleetSnapshot(ws.meta.accountId));
        notifyDaemonsOfClients(ws.meta.accountId);
        log(`client connected: ${ws.meta.name}`);
      } else ws.close();
      return;
    }
      if (ws.meta.role === 'daemon') onDaemonMessage(ws, m);
      else onClientMessage(ws, m);
    } catch (e) { log(`message error (${m.type}): ${e.message}`); send(ws, { type: 'error', message: e.message }); }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (ws.meta?.role === 'daemon' && daemons.get(ws.meta.deviceId) === ws) {
      daemons.delete(ws.meta.deviceId);
      deviceSyncing.delete(ws.meta.deviceId);
      q.touchDevice.run(now(), ws.meta.deviceId);
      broadcast(ws.meta.accountId, { type: 'device_presence', deviceId: ws.meta.deviceId, online: false, syncing: false, lastSeen: now() });
      log(`daemon disconnected: ${ws.meta.deviceId}`);
    }
    if (clients.delete(ws) && ws.meta?.accountId) notifyDaemonsOfClients(ws.meta.accountId);
  });
});

// keepalive + liveness: a socket that hasn't answered pings for ~95s is dead (laptop slept,
// network dropped without FIN) — terminate it so presence flips to offline instead of lying
setInterval(() => {
  for (const [rid, p] of pendingFs) if (now() - p.at > 60_000) pendingFs.delete(rid);
  for (const ws of [...daemons.values(), ...clients]) {
    if (ws.lastPong && now() - ws.lastPong > 95_000) {
      log(`terminating unresponsive ${ws.meta?.role ?? '?'} socket${ws.meta?.deviceId ? ` (${ws.meta.deviceId})` : ''}`);
      try { ws.terminate(); } catch {}
      continue;
    }
    send(ws, { type: 'ping' });
  }
}, 30_000).unref();

// ------------------------------------------------------------------ REST + static
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webp': 'image/webp', '.webmanifest': 'application/manifest+json' };

function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 1_000_000) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch { reject(new Error('bad json')); } });
  });
}
const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname === '/api/health') return json(res, 200, { ok: true });

    if (req.method === 'POST' && url.pathname === '/api/register') {
      const { accountId, name, email, passSalt, authHash, keyCt } = await readBody(req);
      if (!/^[0-9a-f]{16,64}$/.test(accountId ?? '')) return json(res, 400, { error: 'bad accountId' });
      if (q.accountById.get(accountId)) return json(res, 409, { error: 'account exists' });
      const em = String(email ?? '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return json(res, 400, { error: 'invalid email' });
      if (!passSalt || !authHash || !keyCt) return json(res, 400, { error: 'missing credentials' });
      if (q.accountByEmail.get(em)) return json(res, 409, { error: 'an account with that email already exists' });
      const token = randB64u(32);
      // authHash arrives already password-derived in the browser; hash it once more at rest
      q.insertAccountFull.run(accountId, String(name ?? 'me').slice(0, 64), sha256hex(token), now(),
        em, String(passSalt).slice(0, 128), sha256hex(String(authHash)), String(keyCt).slice(0, 2048));
      log(`account registered: ${accountId} (${em})`);
      return json(res, 200, { clientToken: token });
    }

    // email/password login: salt first (client derives keys), then verify
    if (req.method === 'POST' && url.pathname === '/api/login-salt') {
      const { email } = await readBody(req);
      const acc = q.accountByEmail.get(String(email ?? '').trim().toLowerCase());
      if (!acc?.pass_salt) return json(res, 404, { error: 'no account with that email' });
      return json(res, 200, { passSalt: acc.pass_salt });
    }
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { email, authHash, name } = await readBody(req);
      const em = String(email ?? '').trim().toLowerCase();
      const tries = loginTries.get(em) ?? { n: 0, at: 0 };
      if (tries.n >= 10 && now() - tries.at < 15 * 60_000) return json(res, 429, { error: 'too many attempts — try again later' });
      const acc = q.accountByEmail.get(em);
      if (!acc || sha256hex(String(authHash ?? '')) !== acc.auth_hash) {
        loginTries.set(em, { n: tries.n + 1, at: now() });
        return json(res, 401, { error: 'wrong email or password' });
      }
      loginTries.delete(em);
      const token = randB64u(32);
      q.insertClient.run(randHex(8), acc.id, String(name ?? 'client').slice(0, 64), sha256hex(token), now(), now());
      log(`email login: ${em} -> account ${acc.id}`);
      return json(res, 200, { accountId: acc.id, clientToken: token, keyCt: acc.key_ct, name: acc.name });
    }
    // attach email/password login to an already-authenticated account (legacy accounts)
    if (req.method === 'POST' && url.pathname === '/api/account/email') {
      const accountId = req.headers['x-account-id'];
      const token = (req.headers.authorization ?? '').replace('Bearer ', '');
      if (!authAccount(accountId, token)) return json(res, 401, { error: 'unauthorized' });
      const { email, passSalt, authHash, keyCt } = await readBody(req);
      const em = String(email ?? '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return json(res, 400, { error: 'invalid email' });
      if (!passSalt || !authHash || !keyCt) return json(res, 400, { error: 'missing credentials' });
      const taken = q.accountByEmail.get(em);
      if (taken && taken.id !== accountId) return json(res, 409, { error: 'that email is used by another account' });
      q.setAccountLogin.run(em, String(passSalt).slice(0, 128), sha256hex(String(authHash)), String(keyCt).slice(0, 2048), accountId);
      log(`email login attached to account ${accountId} (${em})`);
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/pairings') {
      const accountId = req.headers['x-account-id'];
      const token = (req.headers.authorization ?? '').replace('Bearer ', '');
      if (!authAccount(accountId, token)) return json(res, 401, { error: 'unauthorized' });
      const { codeHash } = await readBody(req);
      if (!/^[0-9a-f]{64}$/.test(codeHash ?? '')) return json(res, 400, { error: 'bad codeHash' });
      q.insertPairing.run(randHex(8), accountId, codeHash, now() + 10 * 60_000);
      return json(res, 200, { ok: true, expiresInSec: 600 });
    }

    // create a one-time login link (from a logged-in client)
    if (req.method === 'POST' && url.pathname === '/api/client-links') {
      const accountId = req.headers['x-account-id'];
      const token = (req.headers.authorization ?? '').replace('Bearer ', '');
      if (!authAccount(accountId, token)) return json(res, 401, { error: 'unauthorized' });
      const { codeHash } = await readBody(req);
      if (!/^[0-9a-f]{64}$/.test(codeHash ?? '')) return json(res, 400, { error: 'bad codeHash' });
      q.insertClientLink.run(randHex(8), accountId, codeHash, now() + 10 * 60_000);
      return json(res, 200, { ok: true, expiresInSec: 600 });
    }

    // redeem a login link -> this browser gets its own client token
    if (req.method === 'POST' && url.pathname === '/api/client-link/redeem') {
      const { accountId, linkToken, name } = await readBody(req);
      const link = q.findClientLink.get(accountId, sha256hex(linkToken ?? ''), now());
      if (!link) return json(res, 403, { error: 'invalid or expired login code' });
      q.useClientLink.run(now(), link.id);
      const clientToken = randB64u(32);
      q.insertClient.run(randHex(8), accountId, String(name ?? 'client').slice(0, 64), sha256hex(clientToken), now(), now());
      log(`client linked: "${name}" for account ${accountId}`);
      // tell the new browser whether this account has an email login, so it knows whether
      // logging out here is recoverable (the email itself is already the account's own)
      return json(res, 200, { clientToken, email: q.accountById.get(accountId)?.email ?? null });
    }

    if (req.method === 'POST' && url.pathname === '/api/pair') {
      const { accountId, pairingToken, pubkey, name, platform } = await readBody(req);
      const p = q.findPairing.get(accountId, sha256hex(pairingToken ?? ''), now());
      if (!p) return json(res, 403, { error: 'invalid or expired pairing code' });
      q.usePairing.run(now(), p.id);
      const deviceId = randHex(8);
      q.insertDevice.run(deviceId, accountId, String(name ?? 'device').slice(0, 64), String(platform ?? '?').slice(0, 16), pubkey, now(), now());
      log(`device paired: ${deviceId} (${name}) for account ${accountId}`);
      return json(res, 200, { deviceId });
    }

    // static app
    let p = url.pathname === '/' ? '/index.html' : url.pathname;
    p = path.normalize(p).replace(/^(\.\.[\/\\])+/, '');
    const file = path.join(APP_DIR, p);
    if (!file.startsWith(APP_DIR)) { res.writeHead(403); return res.end(); }
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
      return fs.createReadStream(file).pipe(res);
    }
    res.writeHead(404); res.end('not found');
  } catch (e) { json(res, 400, { error: e.message }); }
});

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws') { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

server.listen(PORT, HOST, () => log(`tether relay on http://${HOST}:${PORT} (db: ${DB_PATH})`));
