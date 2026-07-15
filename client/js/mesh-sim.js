// mesh-sim.js — a SIMULATED DMTAP mesh + mixnet.
//
// IMPORTANT: there are no real peers. This module fakes discovery, mixnet hops, delivery
// latency, and a few contacts so the UI can demonstrate the protocol end to end. A real
// client would replace this with a libp2p connection to the user's node (spec §4). Every
// place the UI shows network activity, it is this simulation.
//
// It also fakes the @handle directory (spec §3.9.2) and seeds calendar/contact demo data
// (spec §8.4) — see below. Both are clearly marked simulated at their point of use.

export const CONTACTS = [
  { name: 'ada@gw.dmtap.example', key: 'K7f2ada9c1', tier: 'B', pinned: true, verified: true, avatar: 'A' },
  { name: 'linus@kernel.dev',    key: 'K3b8linus4', tier: 'C', pinned: true, verified: false, avatar: 'L' },
  { name: 'grace@navy.mil',      key: 'K9c1grace7', tier: 'C', pinned: true, verified: true, avatar: 'G' },
  { name: 'satoshi',             key: 'Kd4esat0sh', tier: 'A', pinned: false, verified: false, avatar: 'S' },
  { name: 'carol@gmail.com',     key: null,         tier: 'legacy', pinned: false, verified: false, avatar: 'C', legacy: true },
];

// Mixnet hop labels for the private-tier visualization (spec §4.4).
const MIX_PATH = ['entry-mix', 'mix-α', 'mix-β', 'exit-mix'];

// "Send" a MOTE: returns a delivery plan describing the path + latency, and invokes
// onHop(index) callbacks so the UI can animate. Private tier = mixnet (slow); fast = direct.
export function planDelivery(mote, contact) {
  const legacy = contact?.legacy;
  if (legacy) {
    return { path: ['your node', 'gateway', 'SMTP', 'gmail.com'], latencyMs: 1400, kind: 'legacy' };
  }
  if (mote.tier === 'fast') {
    return { path: ['your node', 'direct (IPv6)', 'their node'], latencyMs: 300, kind: 'direct' };
  }
  return { path: ['your node', ...MIX_PATH, 'their node'], latencyMs: 2600, kind: 'mixnet' };
}

export async function animatePath(plan, onHop) {
  const step = plan.latencyMs / plan.path.length;
  for (let i = 0; i < plan.path.length; i++) {
    onHop(i, plan.path[i]);
    await new Promise(r => setTimeout(r, Math.min(step, 500)));
  }
}

// Seed mailbox (received MOTEs, already "decrypted" for display).
export function seedMail() {
  const now = Date.now();
  return [
    { id: 'm1', from: 'ada@gw.dmtap.example', avatar: 'A', subject: 'Welcome to DMTAP',
      time: now - 3600e3, tier: 'private', verified: true,
      body: "Hey — you're on the sovereign network now.\n\nYour key is your identity; this address is just a pointer to it. No provider can read this — it was sealed to your key and routed through the mixnet, so not even the network saw that I wrote to you.\n\nTry composing a reply and watch the MOTE inspector.\n\n— Ada" },
    { id: 'm2', from: 'grace@navy.mil', avatar: 'G', subject: 'Re: compiler bug', verified: true,
      time: now - 7200e3, tier: 'private',
      body: "Reproduced. The fix is to always check the return value.\n\nAlso: I verified your safety number out-of-band, so this thread is upgraded from TOFU-pinned to verified." },
    { id: 'm3', from: 'carol@gmail.com', avatar: 'C', subject: 'lunch?', legacy: true,
      time: now - 9000e3, tier: 'legacy',
      body: "hey are you free thursday?\n\n(this one came in from the legacy world via the gateway — it's authenticated but not end-to-end encrypted before the gateway, so it's marked legacy-origin.)" },
    { id: 'm4', from: 'linus@kernel.dev', avatar: 'L', subject: 'patch series v3',
      time: now - 86400e3, tier: 'private',
      body: "Applied. One nit inline. This whole thread is metadata-private — an observer can't tell we correspond." },
  ];
}

export function seedChats() {
  const now = Date.now();
  return [
    { id: 'c1', with: 'ada@gw.dmtap.example', avatar: 'A', msgs: [
      { me: false, t: now - 300e3, body: 'chat and mail are the same MOTE underneath 👀' },
      { me: false, t: now - 240e3, body: 'this one just uses the fast tier since we\'re both online' },
      { me: true,  t: now - 120e3, body: 'so one identity, one substrate — mail, chat, files' },
      { me: false, t: now - 60e3,  body: 'exactly. kind=chat instead of kind=mail. that\'s the whole difference.' },
    ]},
    { id: 'c2', with: 'satoshi', avatar: 'S', msgs: [
      { me: false, t: now - 8000e3, body: 'no domain needed. i\'m tier A — key-only identity.' },
    ]},
  ];
}

export function seedFiles() {
  return [
    { name: 'whitepaper.pdf', size: 2_400_000, cid: 'b3:9f2c…a71e', icon: '📄', from: 'ada@gw.dmtap.example' },
    { name: 'design-v2.png',  size: 840_000,   cid: 'b3:1a4b…c93d', icon: '🖼️', from: 'linus@kernel.dev' },
    { name: 'backups.tar.gz', size: 5_100_000_000, cid: 'b3:77e0…12ff', icon: '📦', from: 'you' },
  ];
}

export function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}

// ---------------- Simulated handle directory (spec §3.9.2) ----------------
// A real handle directory assigns @handles first-come-first-served with an anti-squat cost,
// and publishes handle→key bindings to a key-transparency log so it's auditable, not
// trusted. There is no such directory here — just an in-memory registry seeded with a few
// "already taken" handles so claiming one demonstrates a lookup + collision, not a rubber
// stamp that always says yes.
const TAKEN_HANDLES = new Set(['ada', 'linus', 'grace', 'satoshi', 'admin', 'root', 'support', 'envoir']);

export function normalizeHandle(h) {
  return (h || '').trim().toLowerCase().replace(/^@/, '').replace(/\.{2,}/g, '.');
}

export function checkHandle(h) {
  const n = normalizeHandle(h);
  if (!n) return { ok: false, reason: 'Enter a handle.' };
  if (!/^[a-z0-9][a-z0-9.-]{1,19}$/.test(n)) return { ok: false, reason: '3-20 chars, letters/digits/./- , must start alphanumeric.' };
  if (TAKEN_HANDLES.has(n)) return { ok: false, reason: '@' + n + ' is already taken.' };
  return { ok: true, normalized: n };
}

// "Claim" a handle: checks the (simulated) directory, then reserves it and returns a fake
// key-transparency log entry — a stand-in for the signed tree head + inclusion proof a real
// directory would publish (spec §3.5) so the assignment is auditable.
export async function claimHandle(h) {
  const chk = checkHandle(h);
  if (!chk.ok) return chk;
  TAKEN_HANDLES.add(chk.normalized);
  const { sha256, hex } = await import('./identity.js');
  const leaf = await sha256(new TextEncoder().encode(chk.normalized + ':' + Date.now() + ':' + Math.random()));
  return { ok: true, handle: chk.normalized, kt: 'kt:' + hex(leaf, 12) + '…' };
}

// ---------------- Calendar & contacts seed data (spec §8.4) ----------------
// Same substrate as mail/chat: additional MOTE kinds (calendar, contact) stored on the node,
// end-to-end encrypted, synced across the device cluster — not a separate CalDAV/CardDAV
// service. These are seed/demo entries only.
export function seedCalendar() {
  const now = Date.now(), day = 86400e3;
  return [
    { id: 'ev1', title: 'Mesh working group sync', start: now + 2 * 3600e3, end: now + 3 * 3600e3, with: 'ada@gw.dmtap.example' },
    { id: 'ev2', title: 'Design review — MOTE v2 framing', start: now + day + 5 * 3600e3, end: now + day + 6 * 3600e3, with: 'linus@kernel.dev' },
    { id: 'ev3', title: "Grace's flight lands", start: now + 2 * day + 1.5 * 3600e3, end: now + 2 * day + 2 * 3600e3, with: 'grace@navy.mil' },
  ];
}

export function seedAddressBook() {
  return [
    { name: 'Ada', handle: 'ada@gw.dmtap.example', email: 'ada@gw.dmtap.example', phone: '+1 555 0182', note: 'DMTAP core', avatar: 'A' },
    { name: 'Linus', handle: 'linus@kernel.dev', email: 'linus@kernel.dev', phone: null, note: 'kernel maintainer', avatar: 'L' },
    { name: 'Grace', handle: 'grace@navy.mil', email: 'grace@navy.mil', phone: '+1 555 0143', note: 'verified contact', avatar: 'G' },
  ];
}
