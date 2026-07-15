// ui.js — rendering helpers and view builders. Pure DOM, no framework.

import { fmtBytes } from './mesh-sim.js';

export const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
export const esc = (s) => (s || '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
export const timeAgo = (t) => {
  const s = (Date.now() - t) / 1000;
  if (s < 60) return 'now';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
};

export function toast(msg, ms = 2600) {
  const t = document.getElementById('toast');
  t.innerHTML = msg; t.classList.remove('hidden');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.add('hidden'), ms);
}

// ---- MOTE inspector (the three-layer visualization, spec §2.1) ----
export function showInspector(mote, plan) {
  const insp = document.getElementById('inspector');
  const hops = plan.path.map((h, i) => `<span class="hop" data-h="${i}">${esc(h)}</span>`)
    .join('<span class="arrow">→</span>');
  const tierBadge = mote.tier === 'private'
    ? '<span class="badge priv">● private · mixnet</span>'
    : (plan.kind === 'legacy' ? '<span class="badge warn">● legacy · gateway</span>' : '<span class="badge fast">● fast · direct</span>');

  insp.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
      <h3>MOTE inspector</h3>
      <button class="btn ghost" id="insp-close">✕</button>
    </div>
    <div class="sub">The message object, spec §2 — three nested layers. ${tierBadge}</div>

    <div class="layer outer">
      <div class="layer-h">◇ OUTER — mixnet / sealed sender</div>
      <div class="kv"><span class="k">tier</span><span class="v">${mote.tier}</span></div>
      <div class="kv"><span class="k">onion</span><span class="v">${mote.outer.onion ? 'Sphinx, constant-length' : 'direct'}</span></div>
      <div class="kv"><span class="k">sender</span><span class="v">hidden (sealed)</span></div>
      <div class="kv"><span class="k">padded</span><span class="v">yes → size bucket</span></div>
      <div class="lock">The network sees only this layer: ciphertext to an opaque destination.</div>
    </div>

    <div class="layer env">
      <div class="layer-h">▢ ENVELOPE — signed, content-addressed</div>
      <div class="kv"><span class="k">id</span><span class="v">${esc(mote.envelope.id)}</span></div>
      <div class="kv"><span class="k">to</span><span class="v">${esc(mote.envelope.to)}</span></div>
      <div class="kv"><span class="k">kind</span><span class="v">0x${mote.kind.toString(16).padStart(2, '0')}</span></div>
      <div class="kv"><span class="k">suite</span><span class="v">0x01 (Ed25519/X25519/ChaCha20)</span></div>
      <div class="kv"><span class="k">ts</span><span class="v">${mote.ts}</span></div>
      <div class="lock">id = BLAKE3(ciphertext) — content-addressed (SHA-256 stand-in in this demo).</div>
    </div>

    <div class="layer pay">
      <div class="layer-h">▣ PAYLOAD — end-to-end encrypted</div>
      <div class="kv"><span class="k">from</span><span class="v">${esc(mote.payload.from.slice(0, 24))}…</span></div>
      <div class="kv"><span class="k">signature</span><span class="v">${mote.sigLen ? '✓ real Ed25519, ' + mote.sigLen + ' bytes' : '(unsigned — key unavailable)'}</span></div>
      <div class="kv"><span class="k">subject</span><span class="v">${esc(mote.payload.headers.subject || '—')}</span></div>
      <div class="kv"><span class="k">body</span><span class="v">${esc((mote.payload.body || '').slice(0, 40))}…</span></div>
      <div class="lock">Only the recipient can decrypt this. Sender identity + signature live inside.</div>
    </div>

    <div style="margin-top:16px"><b style="font-size:12px">Delivery path</b></div>
    <div class="path">${hops}</div>
  `;
  insp.classList.remove('hidden');
  insp.querySelector('#insp-close').onclick = () => insp.classList.add('hidden');
  return insp;
}
export function litHop(i) {
  const insp = document.getElementById('inspector');
  insp?.querySelectorAll('.hop').forEach((h, j) => h.classList.toggle('lit', j <= i));
}
export function hideInspector() { document.getElementById('inspector').classList.add('hidden'); }

// ---- Network diagram (roles: node / relay / mixnet / gateway) ----
export function networkSVG() {
  return `<svg viewBox="0 0 640 260" xmlns="http://www.w3.org/2000/svg" fill="none" stroke-width="1.6" font-family="var(--mono)">
    <style>text{font:11px var(--mono);fill:var(--text-dim)} .n{fill:var(--bg-3);stroke:var(--line-2)} .lbl{fill:var(--text)} .e{stroke:var(--line-2)}</style>
    <line class="e" x1="90" y1="130" x2="250" y2="70"/><line class="e" x1="90" y1="130" x2="250" y2="190"/>
    <line class="e" x1="250" y1="70" x2="410" y2="70"/><line class="e" x1="250" y1="190" x2="410" y2="190"/>
    <line class="e" x1="410" y1="70" x2="550" y2="130"/><line class="e" x1="410" y1="190" x2="550" y2="130"/>
    <line class="e" x1="410" y1="70" x2="410" y2="190" stroke-dasharray="3 3"/>
    <circle class="n" cx="90" cy="130" r="30"/><text class="lbl" x="90" y="130" text-anchor="middle">you</text><text x="90" y="178" text-anchor="middle">your node</text>
    <circle class="n" cx="250" cy="70" r="26"/><text x="250" y="72" text-anchor="middle">relay</text>
    <rect class="n" x="216" y="164" width="68" height="52" rx="10"/><text x="250" y="194" text-anchor="middle">mixnet</text>
    <circle class="n" cx="410" cy="70" r="26"/><text x="410" y="72" text-anchor="middle">peer</text>
    <rect class="n" x="376" y="164" width="68" height="52" rx="10"/><text x="410" y="188" text-anchor="middle">gateway</text><text x="410" y="204" text-anchor="middle" font-size="9">→ SMTP</text>
    <circle class="n" cx="550" cy="130" r="30"/><text class="lbl" x="550" y="130" text-anchor="middle">them</text><text x="550" y="178" text-anchor="middle">their node</text>
  </svg>`;
}

// ---- Key-name pills (spec §3.9.1) — 8 derived words + a distinct checksum word ----
export function keyNamePills(keyName) {
  if (!keyName) return '';
  const words = keyName.words.map((w, i) => `<span data-i="${i + 1}">${esc(w)}</span>`).join('');
  return `<div class="phrase keyname">${words}<span class="checksum" data-i="✓">${esc(keyName.checksum)}</span></div>`;
}

export { fmtBytes };
