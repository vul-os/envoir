// mote.js — build a MOTE, the DMTAP message object (spec §2).
//
// Three nested layers (spec §2.1): outer (mixnet / sealed sender), envelope (signed,
// content-addressed), payload (E2E-encrypted). Here the payload signature is REAL (Web
// Crypto); "encryption" and the outer onion are represented structurally (the demo has no
// real recipient key exchange / mixnet). The content-address id is SHA-256 (stand-in for
// BLAKE3, spec §2.2). This mirrors the spec so the object shape is honest even though the
// network is simulated.

import { sha256, sign, toB64u, hex, currentIdentity } from './identity.js';

export const KIND = { mail: 0x00, chat: 0x01, calendar: 0x02, contact: 0x03, file_offer: 0x05 };
export const TIER = { private: 'private', fast: 'fast' };

const enc = new TextEncoder();

// Build a MOTE for the given content. Returns a structured object with the three layers
// exposed for inspection/visualization.
export async function buildMote({ to, kind, subject, body, tier, attach }) {
  const id = currentIdentity();
  const ts = Date.now();

  // --- Payload (would be sealed with MLS/HPKE to the recipient; here shown structurally) ---
  const payload = {
    from: id.ik,               // revealed only to recipient (sealed sender, §2.2)
    headers: { subject: subject || null, mime: 'text/plain', thread: null, cc: [] },
    body: body || '',
    refs: [],
    attach: attach || [],
    expires: null,
  };
  const payloadBytes = enc.encode(JSON.stringify(payload));
  const sig = await sign(payloadBytes);           // REAL signature over the payload
  payload.sig = toB64u(sig);

  // "ciphertext": in a real client this is HPKE/MLS sealed. Demo: mark as sealed, keep bytes.
  const ciphertext = payloadBytes;                 // (not actually encrypted in the demo)
  const contentId = 'b3:' + hex(await sha256(ciphertext), 32); // §2.2 (SHA-256 stand-in)

  // --- Envelope (signed, per-recipient, content-addressed, §2.2) ---
  const envelope = {
    v: 0, suite: 0x01,
    id: contentId,
    to,                        // recipient key/name (blinded in real §6)
    ts, kind,
    sealed: true,
    sig_present: sig.length > 0,
  };

  // --- Outer (mixnet / sealed sender wrapper, §2.1/§6) ---
  const outer = {
    tier,
    onion: tier === 'private',  // wrapped in Sphinx onion layers if private
    padded: true,               // size-padded to a bucket (§6.3)
    sender_visible: false,      // sealed sender — no clear-text sender (§6.2)
  };

  return { outer, envelope, payload, contentId, ts, kind, tier, sigLen: sig.length };
}

export function kindName(k) {
  return Object.entries(KIND).find(([, v]) => v === k)?.[0] || 'unknown';
}
