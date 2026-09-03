// Local HTTP server on a unix socket. Claude Code hooks (via hook-exec.mjs) POST here.
// PreToolUse blocks until a remote decision arrives or the deadline passes; on deadline
// it answers "no decision" and the CLI's normal permission flow takes over (plan §5).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randHex } from './crypto.mjs';

// Windows has no unix-domain sockets; Node exposes the same API over a named pipe.
export const SOCK_PATH = process.platform === 'win32'
  ? '\\\\.\\pipe\\tether-hook'
  : path.join(os.homedir(), '.tether', 'hook.sock');

export class HookBridge {
  /**
   * @param {object} handlers {
   *   onApprovalOpen(approval) -> void   // {id, sessionId, toolName, toolInput, cwd, deadline}
   *   onApprovalSettled(id, outcome)     // 'expired' | 'allow' | 'deny'
   *   onStop(sessionId)
   *   onNotification(sessionId, message)
   *   onPromptSubmit(sessionId)
   * }
   */
  constructor(handlers, { approvalTimeoutMs = 25_000 } = {}, log = () => {}) {
    this.h = handlers;
    this.approvalTimeoutMs = approvalTimeoutMs;
    this.log = log;
    this.pending = new Map(); // approvalId -> {resolve, timer, sessionId}
    this.pendingTool = new Map(); // sessionId -> last tool call seen by PreToolUse
  }

  start() {
    if (process.platform !== 'win32') {
      fs.mkdirSync(path.dirname(SOCK_PATH), { recursive: true });
      try { fs.unlinkSync(SOCK_PATH); } catch {}
    }
    this.server = http.createServer((req, res) => this.route(req, res));
    this.server.listen(SOCK_PATH, () => {
      try { fs.chmodSync(SOCK_PATH, 0o600); } catch {}
      this.log(`hook bridge on ${SOCK_PATH}`);
    });
  }

  stop() { this.server?.close(); try { fs.unlinkSync(SOCK_PATH); } catch {} }

  route(req, res) {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 2_000_000) req.destroy(); });
    req.on('end', () => {
      let payload = {};
      try { payload = JSON.parse(body || '{}'); } catch {}
      const event = (req.url || '').replace('/hook/', '');
      const sid = payload.session_id ?? null;
      const reply = (obj) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
      try {
        switch (event) {
          case 'PreToolUse': return this.preToolUse(sid, payload, reply);
          case 'Stop': this.h.onStop?.(sid); return reply({});
          case 'Notification': this.h.onNotification?.(sid, payload.message ?? '', this.pendingTool.get(sid) ?? null); return reply({});
          case 'UserPromptSubmit': this.h.onPromptSubmit?.(sid); return reply({});
          default: return reply({});
        }
      } catch (e) { this.log(`hook route error: ${e.message}`); return reply({}); }
    });
  }

  // Remember the tool call that is about to be evaluated. We deliberately DO NOT hold the
  // hook: holding suppresses Claude's own permission prompt (measured: the TUI just shows
  // "Forming…" until the hook returns), so gating both delays work and invents approvals
  // for calls the agent would have allowed silently. Instead we let the CLI decide, and
  // mirror the prompt only if the CLI actually raises one (Notification hook).
  recordPending(sessionId, payload) {
    this.pendingTool.set(sessionId, {
      toolName: payload.tool_name ?? '?', toolInput: payload.tool_input ?? {},
      cwd: payload.cwd ?? null, permissionMode: payload.permission_mode ?? null,
      toolUseId: payload.tool_use_id ?? null, at: Date.now(),
    });
  }

  preToolUse(sessionId, payload, reply) {
    this.recordPending(sessionId, payload);
    return reply({}); // never gate — the CLI decides, and we mirror only what it asks
  }

  // decision: 'allow' | 'deny' | null (no decision -> local fallback)
  settle(id, decision, by = 'remote') {
    const p = this.pending.get(id);
    if (!p) return false;
    this.pending.delete(id);
    clearTimeout(p.timer);
    p.resolve({ decision, decidedBy: decision ? by : null });
    this.h.onApprovalSettled?.(id, decision ?? 'expired');
    this.log(`approval ${id} settled: ${decision ?? 'expired (local fallback)'}`);
    return true;
  }

  hasPendingFor(sessionId) {
    for (const p of this.pending.values()) if (p.sessionId === sessionId) return true;
    return false;
  }
}
