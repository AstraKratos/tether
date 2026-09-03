// WebSocket client to the relay. Auth: relay sends a nonce, we sign with the device key.
// Reconnects with backoff; on auth the relay returns per-session cursors so the session
// manager can resend anything the relay missed (at-least-once, idempotent appends).
import { signNonce } from './crypto.mjs';

export class Transport {
  constructor({ relayUrl, deviceId, privKey }, { onAuthed, onMessage, onDown }, log = () => {}) {
    this.wsUrl = relayUrl.replace(/^http/, 'ws').replace(/\/$/, '') + '/ws';
    this.deviceId = deviceId;
    this.privKey = privKey;
    this.onAuthed = onAuthed;
    this.onMessage = onMessage;
    this.onDown = onDown;
    this.log = log;
    this.ready = false;
    this.backoff = 1000;
    this.closed = false;
  }

  isReady() { return this.ready; }
  start() { this.connect(); }
  stop() { this.closed = true; try { this.ws?.close(); } catch {} }

  connect() {
    if (this.closed) return;
    try { this.ws = new WebSocket(this.wsUrl); } catch (e) { return this.retry(e.message); }
    // Node's WebSocket fires only `error` (no `close`) on a refused connection,
    // so retry from whichever fires first — exactly once per attempt.
    let settled = false;
    const settle = (why) => {
      if (settled) return;
      settled = true;
      const was = this.ready;
      this.ready = false;
      if (was) this.onDown?.();
      this.retry(why);
    };
    this.ws.onopen = () => this.log(`ws connected: ${this.wsUrl}`);
    this.ws.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.type === 'challenge') {
        this.send({ type: 'auth', role: 'daemon', deviceId: this.deviceId, sig: signNonce(this.privKey, m.nonce) }, true);
      } else if (m.type === 'authed') {
        this.ready = true;
        this.backoff = 1000;
        this.log('authenticated with relay');
        this.onAuthed?.(m.cursors ?? {});
      } else if (m.type === 'ping') {
        this.send({ type: 'pong' }, true);
      } else {
        this.onMessage?.(m);
      }
    };
    this.ws.onclose = () => settle('closed');
    this.ws.onerror = () => settle('error');
  }

  retry(why) {
    if (this.closed) return;
    this.log(`ws down (${why}); retrying in ${this.backoff}ms`);
    setTimeout(() => this.connect(), this.backoff);
    this.backoff = Math.min(this.backoff * 2, 30_000);
  }

  send(obj, evenUnauthed = false) {
    if (!evenUnauthed && !this.ready) return false;
    try {
      if (this.ws?.readyState === WebSocket.OPEN) { this.ws.send(JSON.stringify(obj)); return true; }
    } catch {}
    return false;
  }
}
