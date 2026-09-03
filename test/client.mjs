#!/usr/bin/env node
// Headless Tether client: speaks the exact same protocol as the web app.
// Used to verify the system end-to-end without a browser.
// Commands:
//   register <name>            create account, save creds to ~/.tether/testclient.json
//   pair-code                  create a pairing and print the tetherd command
//   listen [--auto-approve] [--quiet]   stream fleet + decrypted events/approvals
//   approve <approvalId> <allow|deny>
//   prompt <deviceId> <sessionId> <text...>
//   new-session <deviceId> <cwd> <text...>
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import * as C from '../daemon/crypto.mjs';

const RELAY = process.env.RELAY ?? 'http://127.0.0.1:8787';
// Overridable so a test run can point at a second account without clobbering the saved one.
const CREDS = process.env.TETHER_TEST_CREDS ?? path.join(os.homedir(), '.tether', 'testclient.json');
const cmd = process.argv[2];
const load = () => JSON.parse(fs.readFileSync(CREDS, 'utf8'));
const flag = (f) => process.argv.includes(f);

if (cmd === 'register') {
  const name = process.argv[3] ?? 'test-client';
  const accountId = C.randHex(16);
  const accountSecret = C.randB64u(32);
  const res = await fetch(`${RELAY}/api/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountId, name }) });
  if (!res.ok) { console.error('register failed:', res.status, await res.text()); process.exit(1); }
  const { clientToken } = await res.json();
  fs.mkdirSync(path.dirname(CREDS), { recursive: true });
  fs.writeFileSync(CREDS, JSON.stringify({ relay: RELAY, accountId, accountSecret, clientToken, name }, null, 2), { mode: 0o600 });
  console.log(`registered account ${accountId} -> ${CREDS}`);
} else if (cmd === 'pair-code') {
  const c = load();
  const pairingToken = C.randB64u(16);
  const res = await fetch(`${c.relay}/api/pairings`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${c.clientToken}`, 'x-account-id': c.accountId },
    body: JSON.stringify({ codeHash: C.sha256hex(pairingToken) }),
  });
  if (!res.ok) { console.error('pairing failed:', res.status, await res.text()); process.exit(1); }
  const code = C.makePairingCode(c.accountId, c.accountSecret, pairingToken);
  console.log(code);
  console.error(`\nrun on the machine:\n  node ~/tether/daemon/tetherd.mjs pair '${code}' --relay ${c.relay}`);
} else if (cmd === 'listen') {
  const c = load();
  const quiet = flag('--quiet');
  const ws = new WebSocket(c.relay.replace(/^http/, 'ws') + '/ws');
  const send = (o) => ws.send(JSON.stringify(o));
  const dec = (scope, ct) => { try { return C.decryptJSON(C.deriveKey(c.accountSecret, scope), ct); } catch (e) { return { decryptError: e.message }; } };
  const subs = new Set();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.type === 'challenge') return send({ type: 'auth', role: 'client', accountId: c.accountId, clientToken: c.clientToken, name: c.name });
    if (m.type === 'ping') return send({ type: 'pong' });
    if (m.type === 'fleet') {
      console.log(`FLEET devices=${m.devices.length} sessions=${m.sessions.length} approvals=${m.approvals.length}`);
      for (const d of m.devices) console.log(`  device ${d.id} "${d.name}" ${d.online ? 'ONLINE' : 'offline'}`);
      for (const s of m.sessions.slice(0, 15)) {
        const meta = dec(`session:${s.sessionId}`, s.metaCt);
        console.log(`  session ${s.deviceId}/${s.sessionId.slice(0, 8)} [${s.state}] "${meta.title ?? ''}" cwd=${meta.cwd ?? '?'}`);
        if (!subs.has(s.sessionId)) { subs.add(s.sessionId); send({ type: 'subscribe', deviceId: s.deviceId, sessionId: s.sessionId }); }
      }
      for (const a of m.approvals) printApproval(a);
    } else if (m.type === 'session_upsert') {
      const meta = dec(`session:${m.sessionId}`, m.metaCt);
      console.log(`UPSERT ${m.sessionId.slice(0, 8)} [${m.state}] "${meta.title ?? ''}" cwd=${meta.cwd ?? '?'}`);
      if (!subs.has(m.sessionId)) { subs.add(m.sessionId); send({ type: 'subscribe', deviceId: m.deviceId, sessionId: m.sessionId }); }
    } else if (m.type === 'events') {
      for (const e of m.events) {
        const ev = dec(`session:${m.sessionId}`, e.ct);
        const txt = (ev.text ?? '').replace(/\s+/g, ' ').slice(0, quiet ? 60 : 110);
        console.log(`EV ${m.sessionId.slice(0, 8)}#${e.seq} ${ev.kind}${ev.tool ? ':' + ev.tool : ''} ${txt}`);
      }
    } else if (m.type === 'state_change') {
      console.log(`STATE ${m.sessionId.slice(0, 8)} -> ${m.state}${m.noteCt ? ' note=' + JSON.stringify(dec(`session:${m.sessionId}`, m.noteCt)) : ''}`);
    } else if (m.type === 'approval_open') {
      printApproval(m);
      if (flag('--auto-approve')) { console.log(`AUTO-APPROVING ${m.approvalId}`); send({ type: 'approve', approvalId: m.approvalId, decision: 'allow' }); }
    } else if (m.type === 'approval_resolved') {
      console.log(`APPROVAL ${m.approvalId} -> ${m.status}${m.decidedBy ? ' by ' + m.decidedBy : ''}`);
    } else if (m.type === 'prompt_status') {
      console.log(`PROMPT ${m.promptId} -> ${m.status}${m.detail ? ' (' + m.detail + ')' : ''}`);
    } else if (m.type === 'device_presence') {
      console.log(`PRESENCE ${m.deviceId} ${m.online ? 'ONLINE' : 'offline'}`);
    }
  };
  function printApproval(a) {
    const req = dec(`approval:${a.approvalId}`, a.requestCt);
    console.log(`APPROVAL-REQUEST id=${a.approvalId} session=${a.sessionId.slice(0, 8)} tool=${req.toolName} input=${JSON.stringify(req.toolInput).slice(0, 140)} deadline=${new Date(a.deadline).toISOString()}`);
    console.log(`  decide with: node test/client.mjs approve ${a.approvalId} allow|deny`);
  }
  ws.onclose = () => { console.log('connection closed'); process.exit(0); };
} else if (cmd === 'approve') {
  const c = load();
  const [id, decision] = [process.argv[3], process.argv[4] ?? 'allow'];
  await oneShot(c, { type: 'approve', approvalId: id, decision });
  console.log(`sent ${decision} for ${id}`);
} else if (cmd === 'answer') {
  // Reply to an AskUserQuestion the way the web UI does: only the answers travel, sealed
  // with the approval's own key, and the daemon puts them back together with the questions.
  //   client.mjs answer <approvalId> '{"Which one?":"Option A"}'
  const c = load();
  const id = process.argv[3];
  const answers = JSON.parse(process.argv[4] ?? '{}');
  const answersCt = C.encryptJSON(C.deriveKey(c.accountSecret, `approval:${id}`), { answers });
  await oneShot(c, { type: 'approve', approvalId: id, decision: 'allow', answersCt });
  console.log(`answered ${id}: ${JSON.stringify(answers)}`);
} else if (cmd === 'prompt') {
  const c = load();
  const [deviceId, sessionId] = [process.argv[3], process.argv[4]];
  const text = process.argv.slice(5).join(' ');
  const promptId = C.randHex(8);
  const bodyCt = C.encryptJSON(C.deriveKey(c.accountSecret, `prompt:${promptId}`), { text });
  await oneShot(c, { type: 'prompt', promptId, deviceId, sessionId, bodyCt });
  console.log(`prompt ${promptId} sent to ${deviceId}/${sessionId.slice(0, 8)}`);
} else if (cmd === 'new-session') {
  const c = load();
  const [deviceId, cwd] = [process.argv[3], process.argv[4]];
  const text = process.argv.slice(5).join(' ');
  const promptId = C.randHex(8);
  const bodyCt = C.encryptJSON(C.deriveKey(c.accountSecret, `prompt:${promptId}`), { text, cwd });
  await oneShot(c, { type: 'prompt', promptId, deviceId, bodyCt });
  console.log(`new-session prompt ${promptId} sent to ${deviceId} in ${cwd}`);
} else {
  console.log('usage: client.mjs register|pair-code|listen|approve|answer|prompt|new-session ...');
  process.exit(1);
}

function oneShot(c, msg) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(c.relay.replace(/^http/, 'ws') + '/ws');
    const t = setTimeout(() => reject(new Error('timeout')), 8000);
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.type === 'challenge') ws.send(JSON.stringify({ type: 'auth', role: 'client', accountId: c.accountId, clientToken: c.clientToken, name: c.name }));
      else if (m.type === 'authed') { ws.send(JSON.stringify(msg)); setTimeout(() => { clearTimeout(t); ws.close(); resolve(); }, 300); }
    };
    ws.onerror = (e) => { clearTimeout(t); reject(new Error('ws error')); };
  });
}
