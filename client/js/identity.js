// identity.js — DMTAP identity (spec §1). Uses REAL Web Crypto.
//
// What is real: Ed25519 keypair generation + signing (where the browser supports it),
// SHA-256 hashing. What is a stand-in: SHA-256 substitutes for BLAKE3 content-addressing
// (browsers have no BLAKE3), and the recovery phrase word list is a small demo list, not the
// full SLIP-0039/BIP39 list. All clearly marked. Persistence is localStorage (a real node
// would hold keys in an OS keystore).
//
// This module also computes the identity's key-name (spec §3.9.1, see keyname.js) once at
// creation/load time and attaches it as `.keyName` — the top rung of the naming ladder,
// always present regardless of which onboarding tier / handle / domain the user also has.

import { deriveKeyName } from './keyname.js';

const LS_KEY = 'dmtap.identity.v1';

// A small demo wordlist (real impl uses the full SLIP-0039 list — spec §1.4).
const WORDS = ('acid apex atlas basin blade cedar cobalt comet coral delta ember fable flint ' +
  'garnet glide harbor helix ionic ivory jasper karma linen lunar maple mesa nova onyx opal ' +
  'petal quartz raven relay river sable slate spark tidal umbra vertex willow xenon yarrow zephyr')
  .split(' ');

let _identity = null;

// True Ed25519 support varies by browser; fall back to ECDSA P-256 if needed, and mark which.
async function genSigningKey() {
  try {
    return { kp: await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']), alg: 'Ed25519' };
  } catch {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { kp, alg: 'ECDSA-P256 (Ed25519 unsupported here)' };
  }
}

export async function sha256(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(d);
}

export function toB64u(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64u(s) {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
export function hex(bytes, max) {
  let s = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return max ? s.slice(0, max) : s;
}

export async function createIdentity(name, tier) {
  const { kp, alg } = await genSigningKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)
    .catch(async () => new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))));
  const ik = toB64u(raw);
  const fingerprint = hex(await sha256(raw), 16);
  const keyName = await deriveKeyName(raw); // spec §3.9.1 — deterministic, from the key itself
  // recovery phrase — 12 demo words (mock; real = SLIP-0039)
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  const phrase = [...rnd].map(b => WORDS[b % WORDS.length]);

  _identity = {
    name, tier, ik, alg, fingerprint, phrase, keyName, handle: null,
    created: Date.now(),
    _kp: kp,
  };
  const pk8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  localStorage.setItem(LS_KEY, JSON.stringify({
    name, tier, ik, alg, fingerprint, phrase, keyName, handle: null, created: _identity.created,
    pk8: toB64u(pk8), pub: toB64u(raw),
  }));
  return _identity;
}

export async function loadIdentity() {
  const j = localStorage.getItem(LS_KEY);
  if (!j) return null;
  const s = JSON.parse(j);
  const alg = s.alg.startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  try {
    const priv = await crypto.subtle.importKey('pkcs8', fromB64u(s.pk8), alg, true, ['sign']);
    _identity = { ...s, _kp: { privateKey: priv } };
  } catch {
    _identity = { ...s, _kp: null };
  }
  // Older saved identities (pre-key-name) won't have `.keyName` — derive it on load so every
  // identity gets one, still deterministically from the same public key bytes.
  if (!_identity.keyName) _identity.keyName = await deriveKeyName(fromB64u(s.pub || s.ik));
  return _identity;
}

export function currentIdentity() { return _identity; }
export function logout() { localStorage.removeItem(LS_KEY); _identity = null; }

// Claim (or clear) the optional @handle rung of the naming ladder (spec §3.9.2). The
// directory lookup/anti-squat check lives in mesh-sim.js (it's simulated); this just persists
// the result onto the identity, same pattern as everything else in this module.
export function setHandle(handle) {
  if (!_identity) return;
  _identity.handle = handle || null;
  const s = JSON.parse(localStorage.getItem(LS_KEY) || '{}');
  s.handle = _identity.handle;
  localStorage.setItem(LS_KEY, JSON.stringify(s));
}

// Sign bytes with the identity's device/root key (spec §2.4 payload signature).
export async function sign(bytes) {
  const id = _identity;
  if (!id?._kp?.privateKey) return new Uint8Array(0);
  const alg = id.alg.startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' };
  const sig = await crypto.subtle.sign(alg, id._kp.privateKey, bytes);
  return new Uint8Array(sig);
}

// The naming ladder in priority order (spec §3.9): a claimed handle beats a domain address
// beats the raw key-name fallback — but the key-name always exists underneath, tier or not.
export function displayAddress(id) {
  if (!id) return '';
  if (id.handle) return '@' + id.handle;
  if (id.tier === 'A') return id.name || id.keyName?.full || ('key:' + id.fingerprint.slice(0, 8));
  return id.name;
}

export { WORDS };
