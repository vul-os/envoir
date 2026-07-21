// views/billing.js — the domain's onboarding tier + usage view. Reads the same TIERS vocabulary
// the operator's dmtap-seam uses (key_only / gateway_domain / vanity_domain) and shows what this
// domain actually draws on operator infrastructure for — which is deliberately narrow: hosted
// storage, legacy-bridge sends/receives, and relay bytes ONLY, and only while the Gateway policy
// screen says this domain draws on operator infrastructure for them. Native DMTAP mail, mixnet
// routing, the KT log and directory resolution are never metered, at any tier.
//
// This view shows USAGE, not a price. Envoir computes no invoice and integrates no payment
// processor — an operator who wants to charge for hosting attaches their own billing system at
// the `dmtap-seam` boundary (see crates/dmtap-seam's `BillingSink`); this console has no opinion
// on what, if anything, that costs.

import { state, effectiveMeters, logEvent } from '../store.js';
import { bus } from '../bus.js';
import { esc, icon, toast, fmtBytes, fmtNum } from '../ui.js';

const TIERS = {
  key_only: { label: 'Key-only', blurb: 'Name→key resolution only — no hosted domain, no gateway.' },
  gateway_domain: { label: 'Gateway domain', blurb: 'name@ under a shared operator domain, legacy bridge available.' },
  vanity_domain: { label: 'Vanity domain', blurb: 'This domain, fully managed — vanity DNS + directory hosting.' },
};

export function render(root) {
  root.className = 'view scroll-view';
  const d = state.domain;
  const p = d.policy;
  const tier = TIERS[d.billing.tier] || TIERS.gateway_domain;
  const m = effectiveMeters();

  const lines = [
    { icon: 'database', label: 'Hosted storage', used: fmtBytes(m.storage_bytes), free: p.selfHost === 'self-hosted', freeNote: 'self-hosted' },
    { icon: 'gateway', label: 'Legacy-bridge sends', used: fmtNum(m.gateway_sends), free: !p.legacyBridge, freeNote: 'bridge disabled' },
    { icon: 'mail', label: 'Legacy-bridge receives', used: fmtNum(m.inbound_legacy), free: !p.legacyBridge, freeNote: 'bridge disabled' },
    { icon: 'relay', label: 'Relay bytes', used: fmtBytes(m.relay_bytes), free: false, freeNote: '' },
  ];

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Usage &amp; quotas <span class="pill accent sm">dmtap-seam</span></h1>
        <p class="page-sub">What <span class="mono">@${esc(d.name)}</span> actually draws on operator infrastructure for — the same narrow set of <b>operations</b> the operator's seam meters, never a protocol capability (spec §12.3). Gateway policy decides what's metered here.</p>
      </div>
    </header>

    <div class="banner good inviolable">${icon('shield')} <span><b>Privacy is never metered.</b> Native DMTAP mail, mixnet routing, the KT log and directory resolution are <b>always free</b> — at every tier, for every domain. There is deliberately no quota for encryption, metadata privacy, or key access.</span></div>

    <section class="card">
      <div class="card-h"><h2>${icon('billing')} Onboarding tier</h2></div>
      <p class="card-sub">Choose the tier that matches how <span class="mono">@${esc(d.name)}</span> is provisioned (spec §3.8). Changing tier does not touch any member's key. Envoir has no price for any of these — if this operator charges for hosting, that arrangement lives entirely outside this console (see <span class="mono">dmtap-seam::BillingSink</span>).</p>
      <div class="model-select">
        ${Object.entries(TIERS).map(([id, t]) => `
          <button class="model-opt ${d.billing.tier === id ? 'sel' : ''}" data-tier="${id}">
            <div class="model-opt-h">${icon('billing')} ${esc(t.label)}</div>
            <p>${esc(t.blurb)}</p>
          </button>`).join('')}
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('database')} This period's usage</h2></div>
      <p class="card-sub">Gateway-metered line items — zeroed the moment the corresponding policy in <b>Gateway &amp; relay policy</b> says this domain isn't drawing on operator infrastructure for it. Counts only; Envoir renders no cost or invoice.</p>
      <div class="bill-lines" id="bill-lines"></div>
      <button class="btn ghost sm bill-adjust" id="goto-gateway">${icon('gateway')} Adjust in Gateway &amp; relay policy →</button>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('scale')} Always free</h2></div>
      <p class="card-sub">These are never metered, at any tier, for any domain — the sovereignty guarantee is not a paid feature.</p>
      <div class="always-free">
        <div class="af-item">${icon('send')} <div><b>Native DMTAP mail</b><small>direct P2P delivery, spec §4</small></div></div>
        <div class="af-item">${icon('directory')} <div><b>Mixnet routing</b><small>metadata-hiding transit, spec §4.4</small></div></div>
        <div class="af-item">${icon('kt')} <div><b>Key Transparency</b><small>log reads &amp; appends, spec §3.5</small></div></div>
        <div class="af-item">${icon('search')} <div><b>Directory resolution</b><small>name→key lookups, spec §3.10</small></div></div>
      </div>
    </section>
  </div>`;

  const linesWrap = root.querySelector('#bill-lines');
  linesWrap.innerHTML = lines.map(l => `
    <div class="bill-line">
      <span class="bl-ic">${icon(l.icon)}</span>
      <div class="bl-main"><b>${esc(l.label)}</b><small class="mono">${esc(l.used)}</small></div>
      ${l.free
        ? `<span class="pill good sm">${icon('check')} ${esc(l.freeNote)}</span>`
        : `<span class="pill dim sm">metered</span>`}
    </div>`).join('');

  root.querySelector('#goto-gateway').onclick = () => bus.setView('gateway');

  root.querySelectorAll('[data-tier]').forEach(b => b.onclick = async () => {
    const id = b.dataset.tier;
    if (d.billing.tier === id) return;
    d.billing.tier = id;
    await logEvent('domain', `Onboarding tier → ${TIERS[id].label}`);
    toast(`${icon('check')} Tier → ${TIERS[id].label}`);
    bus.rerender();
  });
}
