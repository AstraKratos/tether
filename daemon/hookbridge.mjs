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
  : path.join(process.env.TETHER_HOME || path.join(os.homedir(), '.tether'), 'hook.sock');

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
      const url = req.url || '';
      const event = url.replace('/hook/', '');
      const sid = payload.session_id ?? null;
      const reply = (obj) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
      try {
        // Not a hook: permission-mcp.mjs, wired in as --permission-prompt-tool. Unlike the
        // hooks above this one is SUPPOSED to block — the CLI is waiting on a decision it
        // could not make itself, and holds the turn until the answer comes back.
        if (url === '/permission') return this.permissionRequest(sid, payload, reply, res);
        switch (event) {
          // A session is blocked on at most one prompt at a time, so any later lifecycle
          // event from it means that prompt was resolved somewhere we could not see —
          // answered at the machine, approved by auto mode, denied, or cancelled. The CLI
          // does not kill our held hook in those cases; it just stops listening. So each of
          // these events also releases our stale gates for the session and clears the card.
          case 'PreToolUse':
            this.resolveStaleGates(sid, 'a new tool call started', payload.tool_use_id ?? null);
            this.recordPending(sid, payload); return reply({}); // observe only
          case 'PostToolUse':
            this.resolveGateFor(sid, payload.tool_use_id ?? null, 'approved_locally'); // the tool ran
            this.resolveStaleGates(sid, 'a tool call completed');
            return reply({});
          case 'PermissionRequest': return this.permissionGate(sid, payload, reply, res);
          case 'Stop': this.resolveStaleGates(sid, 'the turn ended'); this.h.onStop?.(sid); return reply({});
          case 'Notification': this.h.onNotification?.(sid, payload.message ?? '', this.pendingTool.get(sid) ?? null); return reply({});
          case 'UserPromptSubmit': this.resolveStaleGates(sid, 'a new prompt was sent'); this.h.onPromptSubmit?.(sid); return reply({});
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

  /**
   * PermissionRequest: the CLI has ALREADY decided a human must answer this call. The agent
   * is stopped regardless of what we do here — so holding adds no interference, only a
   * second place to answer from. That is the one channel that reaches a session with no
   * terminal (IDE-hosted, plain shell), where a prompt can otherwise only be answered at
   * the machine. Nothing here predicts or guesses: we never see a call the CLI would have
   * approved on its own.
   */
  permissionGate(sessionId, payload, reply, res) {
    this.recordPending(sessionId, payload);
    if (!this.h.canHold?.()) return reply({}); // nobody watching, or switched off: local prompt as usual

    const id = randHex(8);
    const deadline = Date.now() + this.approvalTimeoutMs;
    const entry = { resolve: reply, sessionId, kind: 'gate', toolInput: payload.tool_input ?? {}, toolUseId: payload.tool_use_id ?? null };
    entry.timer = setTimeout(() => {
      // Nobody answered. Reply with NO decision so the CLI's own flow runs untouched — a
      // timeout must never become an approval, or Tether would be overriding real rules.
      if (this.pending.delete(id)) {
        this.log(`gate ${id} expired; handing back to the local permission flow`);
        this.h.onApprovalSettled?.(id, 'expired');
        try { reply({}); } catch {}
      }
    }, this.approvalTimeoutMs);
    this.pending.set(id, entry);
    res?.on('close', () => {
      if (this.pending.delete(id)) {
        clearTimeout(entry.timer);
        this.log(`gate ${id} abandoned (the turn ended before it was answered)`);
        this.h.onApprovalSettled?.(id, 'expired');
      }
    });
    this.log(`gating ${payload.tool_name ?? '?'} as ${id} for session ${sessionId ?? '?'}`);
    this.h.onApprovalOpen?.({
      id, sessionId, deadline,
      toolName: payload.tool_name ?? '?', toolInput: payload.tool_input ?? {},
      cwd: payload.cwd ?? null, permissionMode: payload.permission_mode ?? null,
    });
    return undefined; // held; `reply` is called by settle() or by the timer above
  }

  /**
   * A `claude -p` run has reached a call the CLI could not decide on its own. There is no
   * terminal to prompt, so this is the last word: mirror it to the web UI and wait.
   *
   * No timeout by design. The CLI holds the turn for as long as the callback takes, and a
   * deadline here would silently deny work the moment someone put their phone down. The
   * caller can still give up; if the socket closes we drop the entry and stop tracking it.
   */
  permissionRequest(sessionId, payload, reply, res) {
    const id = randHex(8);
    const req = {
      id, sessionId,
      toolName: payload.tool_name ?? '?',
      toolInput: payload.input ?? {},
      toolUseId: payload.tool_use_id ?? null,
      // AskUserQuestion is a question, not a permission check: the UI renders its choices
      // and the answer travels back inside updatedInput.
      kind: (payload.tool_name === 'AskUserQuestion') ? 'question' : 'permission',
      cwd: payload.cwd ?? null,
    };
    this.pending.set(id, { resolve: reply, sessionId, kind: req.kind, toolInput: req.toolInput });
    // The run can be interrupted or killed while we hold. Without this the entry would sit
    // in `pending` forever and the card would stay live in the UI for a call that is gone.
    res?.on('close', () => {
      if (this.pending.delete(id)) {
        this.log(`permission ${id} abandoned (the run ended before it was answered)`);
        this.h.onApprovalSettled?.(id, 'expired');
      }
    });
    this.log(`permission request ${id}: ${req.toolName} (${req.kind}) for session ${sessionId ?? '?'}`);
    this.h.onPermissionRequest?.(req);
    return undefined; // held: `reply` is called later, by settlePermission
  }

  /**
   * Answer a held permission request. `result` is the shape Claude Code expects back:
   *   { behavior: 'allow', updatedInput? }  |  { behavior: 'deny', message? }
   * Returns false when the id is unknown (already answered, or the run gave up).
   */
  settlePermission(id, result, by = 'remote') {
    const p = this.pending.get(id);
    if (!p) return false;
    this.pending.delete(id);
    clearTimeout(p.timer);
    // An answered question comes back as `answers` alone; Claude Code wants the original
    // questions echoed alongside them, and we are the side still holding those.
    const answered = result?.answers
      ? { questions: p.toolInput?.questions ?? [], answers: result.answers }
      : null;
    const out = result?.behavior === 'allow'
      ? { behavior: 'allow', updatedInput: result.updatedInput ?? answered ?? p.toolInput }
      : { behavior: 'deny', message: result?.message || `Denied from Tether${by ? ` (${by})` : ''}` };
    p.resolve(out);
    this.h.onApprovalSettled?.(id, out.behavior === 'allow' ? 'allow' : 'deny');
    this.log(`permission ${id} settled: ${out.behavior} by ${by}`);
    return true;
  }

  /**
   * Release a held gate without a decision. hook-exec receives {} and exits silently, the CLI
   * (which already moved on) is untouched, and the relay is told so the card disappears.
   */
  releaseGate(id, p, outcome, why) {
    this.pending.delete(id);
    clearTimeout(p.timer);
    try { p.resolve({}); } catch {}
    this.h.onApprovalSettled?.(id, outcome);
    this.log(`gate ${id} ${outcome} (${why})`);
  }

  /** The tool with this tool_use_id ran, so its prompt was approved — at the machine or by auto mode. */
  resolveGateFor(sessionId, toolUseId, outcome) {
    if (!toolUseId) return;
    for (const [id, p] of this.pending) {
      if (p.kind === 'gate' && p.sessionId === sessionId && p.toolUseId === toolUseId) {
        return this.releaseGate(id, p, outcome, `tool ${toolUseId.slice(0, 12)} completed`);
      }
    }
  }

  /** Every gate still held for this session is stale once the session has moved on. */
  resolveStaleGates(sessionId, why, exceptToolUseId = null) {
    if (!sessionId) return;
    for (const [id, p] of [...this.pending]) {
      if (p.kind !== 'gate' || p.sessionId !== sessionId) continue;
      if (exceptToolUseId && p.toolUseId === exceptToolUseId) continue;
      this.releaseGate(id, p, 'resolved_locally', why);
    }
  }

  // decision: 'allow' | 'deny' | null (no decision -> local fallback)
  settle(id, decision, by = 'remote') {
    const p = this.pending.get(id);
    if (!p) return false;
    // A gated hook wants { decision } back; the MCP prompt tool wants { behavior }.
    if (p.kind === 'permission' || p.kind === 'question') {
      return this.settlePermission(id, { behavior: decision === 'allow' ? 'allow' : 'deny' }, by);
    }
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
