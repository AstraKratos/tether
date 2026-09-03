// Tether crypto: account-key E2E envelope + device identity.
// AES-256-GCM with per-scope keys derived via HKDF-SHA256 from the account secret.
// The relay never sees the account secret or any derived key.
import crypto from 'node:crypto';

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64u = (s) => Buffer.from(s, 'base64url');
export const sha256hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
export const randB64u = (n) => b64u(crypto.randomBytes(n));
export const randHex = (n) => crypto.randomBytes(n).toString('hex');

// scope examples: "session:<sessionId>", "prompt:<promptId>", "approval:<approvalId>"
export function deriveKey(accountSecretB64u, scope) {
  const ikm = fromB64u(accountSecretB64u);
  return Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.from('tether-v1'), Buffer.from(scope), 32));
}

export function encryptJSON(key, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj))), c.final(), c.getAuthTag()]);
  return b64u(Buffer.concat([iv, ct]));
}

export function decryptJSON(key, blob) {
  const buf = fromB64u(blob);
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString());
}

// --- device identity (Ed25519) ---
export function genDeviceKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
}
export function signNonce(privB64, nonce) {
  const key = crypto.createPrivateKey({ key: Buffer.from(privB64, 'base64'), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(nonce), key).toString('base64');
}
export function verifyNonce(pubB64, nonce, sigB64) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(pubB64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(nonce), key, Buffer.from(sigB64, 'base64'));
  } catch { return false; }
}

// --- pairing code: TETHER1.<b64u(json)> ---
// Carries the account secret to the new machine via the user (typed/pasted), never via the relay.
export function makePairingCode(accountId, accountSecretB64u, pairingToken) {
  return 'TETHER1.' + b64u(JSON.stringify({ a: accountId, k: accountSecretB64u, t: pairingToken }));
}
export function parsePairingCode(code) {
  code = code.trim();
  if (!code.startsWith('TETHER1.')) throw new Error('not a Tether pairing code');
  const o = JSON.parse(fromB64u(code.slice('TETHER1.'.length)).toString());
  if (!o.a || !o.k || !o.t) throw new Error('malformed pairing code');
  return o;
}
