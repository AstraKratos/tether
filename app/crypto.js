// Browser mirror of daemon/crypto.mjs envelope: HKDF-SHA256 -> AES-256-GCM.
// Node writes iv || ciphertext || tag; WebCrypto treats ciphertext||tag as one buffer,
// so the formats are wire-compatible.
export const b64u = {
  enc(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  },
  dec(str) {
    const bin = atob(str.replaceAll('-', '+').replaceAll('_', '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  },
};
const te = new TextEncoder();
const td = new TextDecoder();

export async function sha256hex(str) {
  const d = await crypto.subtle.digest('SHA-256', te.encode(str));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export function randBytes(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
export const randHex = (n) => [...randBytes(n)].map((b) => b.toString(16).padStart(2, '0')).join('');

const keyCache = new Map();
export async function deriveKey(accountSecretB64u, scope) {
  if (keyCache.has(scope)) return keyCache.get(scope);
  const ikm = await crypto.subtle.importKey('raw', b64u.dec(accountSecretB64u), 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('tether-v1'), info: te.encode(scope) },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  keyCache.set(scope, key);
  return key;
}
export async function encryptJSON(key, obj) {
  const iv = randBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj))));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return b64u.enc(out);
}
export async function decryptJSON(key, blob) {
  const buf = b64u.dec(blob);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  return JSON.parse(td.decode(pt));
}

// Email/password login. One PBKDF2 run yields two independent halves:
//   authHash — sent to the relay as the login credential (relay hashes it again at rest);
//   wrapKey  — NEVER sent; it seals/unseals the account's e2e key (key_ct on the relay).
// So the relay can verify who you are, but can never derive your encryption key.
export async function passKeys(email, password, saltB64u) {
  const base = await crypto.subtle.importKey('raw', te.encode(`${email.trim().toLowerCase()}:${password}`), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64u.dec(saltB64u), iterations: 310_000 }, base, 512));
  const wrapKey = await crypto.subtle.importKey('raw', bits.slice(32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { authHash: b64u.enc(bits.slice(0, 32)), wrapKey };
}
export async function wrapSecret(wrapKey, secretB64u) {
  const iv = randBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, te.encode(secretB64u)));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return b64u.enc(out);
}
export async function unwrapSecret(wrapKey, blob) {
  const buf = b64u.dec(blob);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, wrapKey, buf.slice(12));
  return td.decode(pt);
}
