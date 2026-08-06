// identity.js — DMTAP identity (spec §1). Uses REAL Web Crypto.
//
// ADDRESSING MODEL (spec §3.9, finalized): the identity is the KEYPAIR. What people see and
// give out is a PRIMARY address `name@domain` (e.g. you@envoir.org). An identity MAY hold many
// addresses at once — aliases, a kept legacy address, an optional @handle — all resolving to
// the same key (§3.9.4). The key is verified out-of-band via a SAFETY NUMBER (safety.js), not
// used as an address.
//
// Real: Ed25519 keypair generation + signing (ECDSA-P256 fallback, labeled), SHA-256 hashing,
// deterministic safety-number derivation. Stand-in: SHA-256 substitutes for BLAKE3 content-
// addressing; the recovery phrase uses a small demo word list (real = SLIP-0039). Persistence
// is localStorage (a real node holds keys in an OS keystore).
//
// JSDoc typedefs below are this module's own single source of truth (replacing what used to be
// a hand-written sidecar identity.d.ts — deleted, see client/tsconfig.json's header comment for
// why a colocated same-named .d.ts shadows its .js for module resolution once checkJs is on).

/** One address on an identity. kind ∈ primary | alias | legacy | handle | namechain. */
/**
 * @typedef {Object} Alias
 * @property {string} address
 * @property {string} kind
 */

/**
 * @typedef {Object} Identity
 * @property {string} name
 * @property {string} primary
 * @property {string} displayName
 * @property {string} givenName
 * @property {string} familyName
 * @property {string | null} avatarUrl
 * @property {boolean} gravatarEnabled
 * @property {Alias[]} addresses
 * @property {string} alg
 * @property {string} ik base64url-encoded raw public key
 * @property {string} fingerprint
 * @property {string} keyName
 * @property {string[]} phrase
 * @property {unknown} safety
 * @property {number} created
 * @property {{ privateKey?: CryptoKey, publicKey?: CryptoKey } | null} [_kp]
 * @property {number} [hue]
 * @property {string} [_avatarSrc]
 */

import { deriveSafety, deriveKeyName } from './safety.js';
import { resolveIdentityAvatar } from './avatar.js';

const LS_KEY = 'envoir.identity.v2';

const WORDS = ('acid apex atlas basin blade cedar cobalt comet coral delta ember fable flint ' +
  'garnet glide harbor helix ionic ivory jasper karma linen lunar maple mesa nova onyx opal ' +
  'petal quartz raven relay river sable slate spark tidal umbra vertex willow xenon yarrow zephyr')
  .split(' ');

/** @type {Identity | null} */
let _identity = null;

/** @returns {Promise<{ kp: CryptoKeyPair, alg: string }>} */
async function genSigningKey() {
  try {
    return { kp: /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])), alg: 'Ed25519' };
  } catch {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { kp, alg: 'ECDSA-P256 (Ed25519 unsupported here)' };
  }
}

/** @param {BufferSource} bytes @returns {Promise<Uint8Array>} */
export async function sha256(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(d);
}
/** @param {Uint8Array} bytes @returns {string} */
export function toB64u(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
/** @param {string} s @returns {Uint8Array<ArrayBuffer>} */
export function fromB64u(s) {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
/** @param {Uint8Array} bytes @param {number} [max] @returns {string} */
export function hex(bytes, max) {
  const s = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return max ? s.slice(0, max) : s;
}

// An alias record. kind ∈ primary | alias | legacy | handle. All resolve to the same key.
/** @param {string} address @param {string} kind @param {Record<string, unknown>} [extra] @returns {Alias} */
function alias(address, kind, extra = {}) {
  return { address, kind, ...extra };
}

/** @returns {void} */
function persist() {
  if (!_identity) return;
  const s = localStorage.getItem(LS_KEY);
  const base = s ? JSON.parse(s) : {};
  localStorage.setItem(LS_KEY, JSON.stringify({
    ...base,
    name: _identity.name, primary: _identity.primary, addresses: _identity.addresses,
    alg: _identity.alg, ik: _identity.ik, fingerprint: _identity.fingerprint, keyName: _identity.keyName,
    phrase: _identity.phrase, safety: _identity.safety, created: _identity.created,
    displayName: _identity.displayName, givenName: _identity.givenName, familyName: _identity.familyName,
    avatarUrl: _identity.avatarUrl, gravatarEnabled: _identity.gravatarEnabled,
  }));
}

/** @param {string} primary @param {string} [displayName] @returns {Promise<Identity>} */
export async function createIdentity(primary, displayName) {
  const { kp, alg } = await genSigningKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)
    .catch(async () => new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))));
  const ik = toB64u(raw);
  const fingerprint = hex(await sha256(raw), 16);
  const safety = await deriveSafety(raw);
  const keyName = await deriveKeyName(raw);
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  const phrase = [...rnd].map(b => WORDS[b % WORDS.length]);

  _identity = {
    name: primary, primary, displayName: displayName || primary.split('@')[0],
    givenName: '', familyName: '', avatarUrl: null, gravatarEnabled: false,
    addresses: [alias(primary, 'primary')],
    alg, ik, fingerprint, keyName, phrase, safety, created: Date.now(),
    _kp: kp,
  };
  const pk8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const s = { pk8: toB64u(pk8), pub: toB64u(raw) };
  localStorage.setItem(LS_KEY, JSON.stringify(s));
  persist();
  await refreshAvatar(_identity, raw);
  return _identity;
}

/** @returns {Promise<Identity | null>} */
export async function loadIdentity() {
  const j = localStorage.getItem(LS_KEY);
  if (!j) return null;
  const s = JSON.parse(j);
  if (!s.ik) return null;
  /** @type {EcKeyImportParams | Algorithm} */
  const alg = (s.alg || '').startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  /** @type {{ privateKey?: CryptoKey } | null} */
  let kp = null;
  try {
    const priv = await crypto.subtle.importKey('pkcs8', fromB64u(s.pk8), alg, true, ['sign']);
    kp = { privateKey: priv };
  } catch { /* key unavailable — signing disabled, UI still works */ }
  /** @type {Identity} */
  const id = { ...s, _kp: kp };
  // loadIdentity() runs exactly once at app boot (see client/js/app.js) — no concurrent call
  // can reassign `id`/`_identity` while these awaits are in flight.
  if (!id.safety) id.safety = await deriveSafety(fromB64u(s.pub || s.ik));
  if (!id.keyName) id.keyName = await deriveKeyName(fromB64u(s.pub || s.ik));
  if (!id.addresses) id.addresses = [alias(id.primary || id.name, 'primary')];
  if (id.givenName == null) id.givenName = '';
  if (id.familyName == null) id.familyName = '';
  if (id.avatarUrl == null) id.avatarUrl = null;
  if (id.gravatarEnabled == null) id.gravatarEnabled = false;
  await refreshAvatar(id, fromB64u(s.pub || s.ik));
  _identity = id;
  return _identity;
}

// Re-derive the effective avatar (the ladder in avatar.js) after load/create or a profile
// edit, and cache it on the identity as a transient field. `rawKeyBytes` may be omitted if
// already known to be unchanged — it's re-derived from the stored public key in that case.
/** @param {Identity | null} [id] @param {Uint8Array} [rawKeyBytes] @returns {Promise<unknown>} */
export async function refreshAvatar(id = _identity, rawKeyBytes) {
  if (!id) return null;
  const raw = rawKeyBytes || fromB64u(id.ik);
  return resolveIdentityAvatar(id, raw);
}

// Self-asserted profile fields (spec framing: the KEY is the identity; name + photo are only
// pointers to it, exactly like the address — see identity.js header comment). Persists and
// re-resolves the avatar ladder; callers should re-render + refresh chrome afterward.
/**
 * @param {Partial<Pick<Identity, 'givenName' | 'familyName' | 'displayName' | 'avatarUrl' | 'gravatarEnabled'>>} [fields]
 * @returns {Promise<Identity | null>}
 */
export async function setProfile(fields = {}) {
  if (!_identity) return _identity;
  // Explicit per-field assignment (rather than a generic `for (k of allowed) obj[k] = fields[k]`
  // loop) so each write stays checked against its own property type — a heterogeneous indexed
  // loop like that can't be soundly typed (the value type is a union across all five fields,
  // not the specific field being written).
  if (fields.givenName !== undefined) _identity.givenName = fields.givenName;
  if (fields.familyName !== undefined) _identity.familyName = fields.familyName;
  if (fields.displayName !== undefined) _identity.displayName = fields.displayName;
  if (fields.avatarUrl !== undefined) _identity.avatarUrl = fields.avatarUrl;
  if (fields.gravatarEnabled !== undefined) _identity.gravatarEnabled = fields.gravatarEnabled;
  persist();
  await refreshAvatar(_identity);
  return _identity;
}

// A lightweight "person" shape for the self-identity, so the SAME avatar()/name rendering used
// for contacts/senders also renders "you" consistently (rail, compose From, mail/chat "me").
/** @returns {{ name: string, hue: number, address: string, trust: string, avatarUrl?: string | null, _avatarSrc?: string | null }} */
export function selfPerson() {
  const id = _identity;
  if (!id) return { name: 'You', hue: 220, address: 'you', trust: 'verified' };
  return {
    name: displayName(id), address: id.primary || 'you', hue: id.hue ?? 220, trust: 'verified',
    avatarUrl: id.avatarUrl || null, _avatarSrc: id._avatarSrc || null,
  };
}

/** @returns {Identity | null} */
export function currentIdentity() { return _identity; }
/** @returns {void} */
export function logout() { localStorage.removeItem(LS_KEY); _identity = null; }

// Characters that are never legitimate in an address/handle but ARE HTML-meaningful. A handful
// of UI surfaces (toasts) render an address's raw text without re-escaping it at the call site —
// esc() at those sinks is the other half of this defense (belt-and-braces); this is the source-side
// half, so a stored address can never carry markup in the first place. Whitespace is excluded too
// (email locals/domains never contain it).
const UNSAFE_ADDR_RE = /[<>"'`\s]/;

// A bare name@domain shape (no whitespace, no HTML-dangerous characters). Exported so its rule is
// independently unit-testable without needing a live identity (client/test/*.test.mjs — DOM-free).
/** @param {string} a @returns {boolean} */
export function isDnsShapedAddress(a) {
  return /^[^@]+@[^@]+\.[^@]+$/.test(a) && !UNSAFE_ADDR_RE.test(a);
}

// Strip HTML-dangerous characters from free-typed address input (onboarding's "your own domain"
// field has no other character filter before the string becomes the identity's PRIMARY address).
/** @param {string | null | undefined} s @returns {string} */
export function sanitizeAddressInput(s) {
  return (s || '').replace(/[<>"'`]/g, '');
}

/** @typedef {{ ok: true } | { ok: false, reason: string }} AliasResult */

// --- Aliases (spec §3.9.4): one identity, many name@domain addresses, all → same key. ---
// Also accepts the `name-chain` resolver form (§3.12.4/§3.12.5, e.g. `alice.eth`/`alice.sol`) —
// bare, no "@", the everyday ENS/SNS-style spelling — auto-classified to kind 'namechain' so the
// naming-ladder UI (identity view, §3.13.2) can show its bidirectional on-chain binding honestly.
/** @param {string} address @param {string} [kind] @returns {AliasResult} */
export function addAlias(address, kind = 'alias') {
  if (!_identity) return { ok: false, reason: 'No identity.' };
  const a = (address || '').trim().toLowerCase();
  if (!a) return { ok: false, reason: 'Enter an address.' };
  const isHandle = a.startsWith('@') && !UNSAFE_ADDR_RE.test(a);
  const isNameChain = !isHandle && !a.includes('@') && /\.(eth|sol)$/.test(a) && !UNSAFE_ADDR_RE.test(a);
  const isDnsShaped = isDnsShapedAddress(a);
  if (!isHandle && !isNameChain && !isDnsShaped) return { ok: false, reason: 'Use name@domain, alice.eth/.sol, or @handle.' };
  if (_identity.addresses.some(x => x.address === a)) return { ok: false, reason: 'Already an address on this identity.' };
  const finalKind = isHandle ? 'handle' : isNameChain ? 'namechain' : kind;
  _identity.addresses.push(alias(a, finalKind));
  persist();
  return { ok: true };
}
/** @param {string} address @returns {void} */
export function removeAlias(address) {
  if (!_identity) return;
  const a = _identity.addresses.find(x => x.address === address);
  if (!a || a.kind === 'primary') return; // can't remove the primary
  _identity.addresses = _identity.addresses.filter(x => x.address !== address);
  persist();
}
/** @param {string} address @returns {void} */
export function makePrimary(address) {
  if (!_identity) return;
  const target = _identity.addresses.find(x => x.address === address);
  if (!target || target.kind === 'handle') return;
  _identity.addresses.forEach(x => { if (x.kind === 'primary') x.kind = 'alias'; });
  target.kind = 'primary';
  _identity.primary = _identity.name = address;
  persist();
}

// Sign bytes with the identity's device/root key (spec §2.4 payload signature).
/** @param {BufferSource} bytes @returns {Promise<Uint8Array>} */
export async function sign(bytes) {
  const id = _identity;
  if (!id?._kp?.privateKey) return new Uint8Array(0);
  const alg = id.alg.startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' };
  return new Uint8Array(await crypto.subtle.sign(alg, id._kp.privateKey, bytes));
}

// The address people see and give out (spec §3.9): the PRIMARY name@domain.
/** @param {Identity | null} [id] @returns {string} */
export function displayAddress(id) {
  id = id || _identity;
  return id ? id.primary || id.name || '' : '';
}
// Composes GIVEN + FAMILY name, unless a single explicit "display name" override is set (spec
// framing, §3.9): these are self-asserted profile fields — a pointer to you, like the address —
// never the identity itself. The address is a pointer to the key; the name is a pointer to you.
/** @param {Identity | null} [id] @returns {string} */
export function displayName(id) {
  id = id || _identity;
  if (!id) return '';
  if (id.displayName) return id.displayName;
  const composed = [id.givenName, id.familyName].filter(Boolean).join(' ').trim();
  if (composed) return composed;
  return (id.primary || id.name || '').split('@')[0];
}

// A stable, KEY-DERIVED legacy/gateway fallback address — the client's simplified presentation
// of the spec §7.10 gateway alias. The spec's "Encoded" form (§7.10.2) packs `localpart +
// nativedomain` so it is a pure, near-stateless function of the pair — but that needs a native
// *domain*, which a Tier A key-only identity (§3.8) doesn't have. Deriving instead from the
// identity's own fingerprint keeps the same self-describing, near-stateless property (no
// per-gateway registration, no state table) while working for every identity, domain or not: the
// result is the SAME at every dmtap1-compatible gateway. It is still, honestly, a *separate,
// rotatable* pointer (§7.10.4) — burn or regenerate it and every other name on the key is
// unaffected.
/** @param {Identity | null} [id] @param {string} [gatewayDomain] @returns {string} */
export function gatewayAlias(id = _identity, gatewayDomain = 'gw.envoir.org') {
  if (!id?.fingerprint) return '';
  return `dmtap1-${id.fingerprint.slice(0, 12)}@${gatewayDomain}`;
}

// Split a plus-addressed local part (spec §3.9.4): you+tag@domain → { base, tag }.
/** @param {string} address @returns {{ base: string, tag: string | null }} */
export function parsePlus(address) {
  const [local, domain] = (address || '').split('@');
  const plus = local.indexOf('+');
  if (plus < 0) return { base: address, tag: null };
  return { base: local.slice(0, plus) + (domain ? '@' + domain : ''), tag: local.slice(plus + 1) };
}

export { WORDS };
