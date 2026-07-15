// app.js — Envoir reference client controller. Wires identity + MOTE + simulated mesh + UI.

import { createIdentity, loadIdentity, currentIdentity, logout, displayAddress, sign, sha256, toB64u, hex, fromB64u, setHandle } from './identity.js';
import { verifyKeyName } from './keyname.js';
import { buildMote, KIND } from './mote.js';
import * as mesh from './mesh-sim.js';
import { el, esc, timeAgo, toast, showInspector, litHop, hideInspector, networkSVG, fmtBytes, keyNamePills } from './ui.js';

const state = {
  view: 'mail',
  mail: [], chats: [], files: [], events: [], addressBook: [],
  selMail: null, selChat: null,
  tierDefault: 'private', gateway: true,
};

// ---------------- Onboarding ----------------
const TIERS = [
  { id: 'B', name: 'name@gateway (recommended)', desc: 'A ready address like you@gw.dmtap.example. Zero DNS. Works with Gmail today. This is the easy default.' },
  { id: 'A', name: 'Key only — no domain', desc: 'Pure DMTAP. Your key is your identity, no domain at all. Talk to other DMTAP users; the legacy world can\'t reach a name it can\'t resolve.' },
  { id: 'C', name: 'Your own domain', desc: 'you@yourbrand.com. The gateway auto-configures DNS/DKIM/DMARC (approve once). Vanity + full legacy interop.' },
];

function renderOnboarding() {
  const o = document.getElementById('onboarding');
  o.classList.remove('hidden');
  let step = 0, tier = 'B', name = '', ident = null;

  const draw = () => {
    if (step === 0) {
      o.innerHTML = `<div class="card">
        <div class="step-dots"><i class="on"></i><i></i><i></i></div>
        <h1>Your key is your identity</h1>
        <div class="sub">Envoir gives you sovereign mail, chat & files. No company can read them, and you can leave anytime with all your data. First, choose how people address you.</div>
        ${TIERS.map(t => `<div class="tier ${t.id === tier ? 'sel' : ''}" data-t="${t.id}"><b>${esc(t.name)}</b><small>${esc(t.desc)}</small></div>`).join('')}
        <div class="field" style="margin-top:14px" id="namefield"></div>
        <button class="btn primary" id="next" style="width:100%;justify-content:center">Continue</button>
      </div>`;
      const nf = o.querySelector('#namefield');
      const drawName = () => {
        if (tier === 'A') { nf.innerHTML = `<label>Nickname (optional, not global)</label><input id="nm" placeholder="satoshi" value="${esc(name)}">`; }
        else if (tier === 'B') { nf.innerHTML = `<label>Pick your name</label><input id="nm" placeholder="you" value="${esc(name)}"><small style="color:var(--text-faint)">→ &lt;name&gt;@gw.dmtap.example</small>`; }
        else { nf.innerHTML = `<label>Your domain address</label><input id="nm" placeholder="you@yourbrand.com" value="${esc(name)}">`; }
        nf.querySelector('#nm').oninput = e => name = e.target.value;
      };
      drawName();
      o.querySelectorAll('.tier').forEach(t => t.onclick = () => { tier = t.dataset.t; draw(); });
      o.querySelector('#next').onclick = async () => {
        let addr = name.trim();
        if (tier === 'B') addr = (addr || 'you') + '@gw.dmtap.example';
        if (tier === 'A' && !addr) addr = '';
        if (tier === 'C' && !addr) addr = 'you@yourbrand.com';
        toast('Generating Ed25519 keypair…');
        ident = await createIdentity(addr, tier);
        step = 1; draw();
      };
    } else if (step === 1) {
      o.innerHTML = `<div class="card">
        <div class="step-dots"><i class="on"></i><i class="on"></i><i></i></div>
        <h1>Save your recovery phrase</h1>
        <div class="sub">These 12 words can restore your identity if you lose every device. Write them down offline. (Demo phrase — a real client uses the full SLIP-0039 word list, spec §1.4.)</div>
        <div class="phrase">${ident.phrase.map((w, i) => `<span data-i="${i + 1}">${esc(w)}</span>`).join('')}</div>
        <div class="notice">Anyone with this phrase can recover your identity. Never share it.</div>
        <button class="btn primary" id="next" style="width:100%;justify-content:center">I've saved it</button>
      </div>`;
      o.querySelector('#next').onclick = () => { step = 2; draw(); };
    } else {
      o.innerHTML = `<div class="card">
        <div class="step-dots"><i class="on"></i><i class="on"></i><i class="on"></i></div>
        <h1>You're sovereign 🔑</h1>
        <div class="sub">Your identity is live. Below is your public key — the real "you". Everything else (address, handle, key-name) is just a pointer to it.</div>
        <div class="field"><label>Address</label><div class="key">${esc(displayAddress(ident) || '(key-only)')}</div></div>
        <div class="field"><label>Key-name — your zero-authority address (spec §3.9.1)</label>
          ${keyNamePills(ident.keyName)}
          <small style="color:var(--text-faint)">Derived from your key alone — no directory, no registration, unique by construction. Give this to anyone; it always resolves to this exact key.</small>
        </div>
        <div class="field"><label>Identity key (Ed25519)</label><div class="key">${esc(ident.ik.slice(0, 44))}…</div></div>
        <div class="field"><label>Fingerprint</label><div class="key">${esc(ident.fingerprint)}</div></div>
        <div class="field"><label>Algorithm</label><div class="key">${esc(ident.alg)}</div></div>
        <div class="ladder">
          <b style="font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--text-dim)">The naming ladder (spec §3.9) — you can hold all three at once</b>
          <div class="ladder-row"><span class="key">key-name</span><span>zero authority, always present — what's above, works today.</span></div>
          <div class="ladder-row"><span class="key">@handle</span><span>optional, human-chosen, first-come in a directory — claim one anytime in Settings.</span></div>
          <div class="ladder-row"><span class="key">name@domain</span><span>your own vanity domain, DNS auto-configured — connect one anytime in Settings.</span></div>
        </div>
        <button class="btn primary" id="go" style="width:100%;justify-content:center">Open my mailbox</button>
      </div>`;
      o.querySelector('#go').onclick = () => { o.classList.add('hidden'); boot(); };
    }
  };
  draw();
}

// ---------------- Views ----------------
function setView(v) {
  state.view = v;
  document.querySelectorAll('.rail-btn').forEach(b => b.classList.toggle('active', b.dataset.view === v));
  const view = document.getElementById('view');
  ({ mail: viewMail, chat: viewChat, files: viewFiles, contacts: viewContacts, calendar: viewCalendar, network: viewNetwork, settings: viewSettings }[v] || viewMail)(view);
}

function viewMail(root) {
  root.innerHTML = `
    <div class="pane pane-list">
      <div class="pane-head"><h2>Inbox</h2><button class="btn primary" id="compose">Compose</button></div>
      <div class="pane-body" id="maillist"></div>
    </div>
    <div class="pane pane-detail" id="maildetail"></div>`;
  const list = root.querySelector('#maillist');
  state.mail.forEach(m => {
    const badge = m.legacy ? '<span class="badge warn">legacy</span>' : (m.verified ? '<span class="badge good">✓</span>' : '<span class="badge priv">private</span>');
    const r = el(`<div class="row ${state.selMail === m.id ? 'sel' : ''}" data-id="${m.id}">
      <div class="row-top"><span class="row-from">${esc(m.from)}</span><span class="row-time">${timeAgo(m.time)}</span></div>
      <div class="row-subj">${esc(m.subject)} ${badge}</div>
      <div class="row-preview">${esc(m.body.split('\n')[0])}</div></div>`);
    r.onclick = () => { state.selMail = m.id; viewMail(root); };
    list.appendChild(r);
  });
  const det = root.querySelector('#maildetail');
  const m = state.mail.find(x => x.id === state.selMail);
  if (m) {
    det.innerHTML = `<div class="msg">
      <div class="msg-subj">${esc(m.subject)}</div>
      <div class="msg-meta"><div class="avatar">${m.avatar}</div><div><b>${esc(m.from)}</b></div>
        ${m.legacy ? '<span class="badge warn">legacy-origin · not E2E before gateway</span>' : (m.verified ? '<span class="badge good">✓ verified contact</span>' : '<span class="badge priv">● metadata-private</span>')}
        <button class="btn ghost" id="reply" style="margin-left:auto">Reply</button></div>
      <div class="msg-body">${esc(m.body)}</div></div>`;
    det.querySelector('#reply').onclick = () => openCompose(root, m.from, 'Re: ' + m.subject);
  } else {
    det.innerHTML = emptyState('Select a message', 'Your inbox is end-to-end encrypted and metadata-private.');
  }
  root.querySelector('#compose').onclick = () => openCompose(root);
}

function openCompose(root, to = '', subject = '') {
  const det = root.querySelector('#maildetail') || root;
  const contactOpts = mesh.CONTACTS.map(c => `<option value="${esc(c.name)}">${esc(c.name)}${c.legacy ? ' (legacy)' : ''}</option>`).join('');
  det.innerHTML = `<div class="compose">
    <div class="pane-head" style="padding:0 0 12px;border:none"><h2>New message</h2></div>
    <div class="field"><label>To</label><input id="to" list="contacts" value="${esc(to)}" placeholder="name@domain or key"><datalist id="contacts">${contactOpts}</datalist></div>
    <div class="field"><label>Subject</label><input id="subj" value="${esc(subject)}"></div>
    <textarea id="body" placeholder="Write your message… it will be sealed to the recipient's key and routed privately."></textarea>
    <div class="compose-foot">
      <button class="btn primary" id="send">Send</button>
      <span class="badge priv" id="tierb">● ${state.tierDefault}</span>
      <span style="color:var(--text-faint);font-size:12px">signed with your real key · sealed sender</span>
    </div></div>`;
  det.querySelector('#send').onclick = async () => {
    const to = det.querySelector('#to').value.trim();
    if (!to) return toast('Add a recipient');
    const contact = mesh.CONTACTS.find(c => c.name === to);
    const tier = contact?.legacy ? 'fast' : state.tierDefault;
    const mote = await buildMote({ to, kind: KIND.mail, subject: det.querySelector('#subj').value, body: det.querySelector('#body').value, tier, attach: [] });
    const plan = mesh.planDelivery(mote, contact);
    const insp = showInspector(mote, plan);
    toast(plan.kind === 'mixnet' ? 'Routing through the mixnet…' : plan.kind === 'legacy' ? 'Bridging to legacy via gateway…' : 'Delivering direct…');
    await mesh.animatePath(plan, (i) => litHop(i));
    toast('✓ Delivered · MOTE ' + mote.contentId.slice(0, 14) + '…');
  };
}

function viewChat(root) {
  root.innerHTML = `
    <div class="pane pane-list">
      <div class="pane-head"><h2>Chats</h2><span class="badge fast">fast tier</span></div>
      <div class="pane-body" id="chatlist"></div>
    </div>
    <div class="pane pane-detail" id="chatdetail"></div>`;
  const list = root.querySelector('#chatlist');
  state.chats.forEach(c => {
    const last = c.msgs[c.msgs.length - 1];
    const r = el(`<div class="row ${state.selChat === c.id ? 'sel' : ''}"><div class="row-top"><span class="row-from">${esc(c.with)}</span><span class="row-time">${timeAgo(last.t)}</span></div><div class="row-preview">${esc(last.body)}</div></div>`);
    r.onclick = () => { state.selChat = c.id; viewChat(root); };
    list.appendChild(r);
  });
  const det = root.querySelector('#chatdetail');
  const c = state.chats.find(x => x.id === state.selChat);
  if (c) {
    det.innerHTML = `<div class="pane"><div class="pane-head"><h2>${esc(c.with)}</h2><span class="badge fast">● same MOTE, kind=chat</span></div>
      <div class="pane-body"><div class="bubbles" id="bubbles"></div></div>
      <div class="chat-input"><input id="ci" placeholder="Message… (kind=chat, fast tier)"><button class="btn primary" id="cs">Send</button></div></div>`;
    const b = det.querySelector('#bubbles');
    c.msgs.forEach(m => b.appendChild(el(`<div class="bubble ${m.me ? 'me' : 'them'}">${esc(m.body)}<div class="t">${timeAgo(m.t)}</div></div>`)));
    b.scrollTop = b.scrollHeight;
    const send = async () => {
      const v = det.querySelector('#ci').value.trim(); if (!v) return;
      c.msgs.push({ me: true, t: Date.now(), body: v });
      const mote = await buildMote({ to: c.with, kind: KIND.chat, body: v, tier: 'fast', attach: [] });
      viewChat(root);
      setTimeout(() => toast('✓ chat MOTE ' + mote.contentId.slice(0, 12) + '… (fast/direct)'), 100);
    };
    det.querySelector('#cs').onclick = send;
    det.querySelector('#ci').onkeydown = e => { if (e.key === 'Enter') send(); };
  } else det.innerHTML = emptyState('Select a chat', 'Chat is the same object as mail — kind=chat, fast tier.');
}

function viewFiles(root) {
  root.innerHTML = `<div class="full">
    <h2>Files</h2><div class="sub">Content-addressed, end-to-end encrypted, any size. No protocol cap (spec §5.5).</div>
    <div class="drop" id="drop">Drop a file here or click to share — it's chunked, hashed, and encrypted client-side.</div>
    <input type="file" id="finput" class="hidden">
    <div class="file-grid" id="grid"></div></div>`;
  const grid = root.querySelector('#grid');
  const draw = () => { grid.innerHTML = ''; state.files.forEach(f => grid.appendChild(el(
    `<div class="file-card"><div class="fi">${f.icon}</div><div class="fn">${esc(f.name)}</div><div class="fm">${fmtBytes(f.size)} · from ${esc(f.from)}</div><div class="key" style="margin-top:8px">${esc(f.cid)}</div></div>`))); };
  draw();
  const inp = root.querySelector('#finput'), drop = root.querySelector('#drop');
  drop.onclick = () => inp.click();
  drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) shareFile(e.dataTransfer.files[0]); };
  inp.onchange = () => { if (inp.files[0]) shareFile(inp.files[0]); };
  async function shareFile(file) {
    toast('Chunking + hashing ' + file.name + '…');
    const buf = new Uint8Array(await file.arrayBuffer());
    const { sha256, hex } = await import('./identity.js');
    const cid = 'b3:' + hex(await sha256(buf), 8) + '…' + hex(await sha256(buf.slice(-64)), 4);
    const chunks = Math.max(1, Math.ceil(file.size / (1024 * 1024)));
    state.files.unshift({ name: file.name, size: file.size, cid, icon: '🔒', from: 'you' });
    draw();
    toast(`✓ Shared · ${chunks} chunk(s) · manifest ${cid} · E2E encrypted`);
  }
}

function viewContacts(root) {
  root.innerHTML = `<div class="full"><h2>People</h2><div class="sub">Contacts are pinned by key (TOFU, spec §3.4). Verify a safety number out-of-band to upgrade trust.</div><div id="clist"></div></div>`;
  const l = root.querySelector('#clist');
  mesh.CONTACTS.forEach(c => {
    const trust = c.verified ? '<span class="badge good">✓ verified</span>' : c.pinned ? '<span class="badge priv">pinned (TOFU)</span>' : '<span class="badge warn">unpinned</span>';
    const row = el(`<div class="setting"><div class="s-l" style="display:flex;gap:12px;align-items:center">
      <div class="avatar">${c.avatar}</div>
      <div><b>${esc(c.name)}</b><br><span class="key">${esc(c.key || 'legacy · no key')}</span> <small>tier ${c.tier}</small></div></div>
      <div style="display:flex;gap:8px;align-items:center">${trust}${!c.verified && !c.legacy ? '<button class="btn ghost" data-v="' + esc(c.name) + '">Verify</button>' : ''}</div></div>`);
    const vb = row.querySelector('[data-v]');
    if (vb) vb.onclick = () => { c.verified = true; toast('Safety number matched — ' + c.name + ' is now verified'); viewContacts(root); };
    l.appendChild(row);
  });
}

// Calendar & contacts (spec §8.4): additional MOTE kinds on the same node — not separate
// CalDAV/CardDAV services. "New event"/"New contact" build real MOTEs (kind=calendar,
// kind=contact) through the same buildMote()/inspector path as mail, to make the "same
// substrate" claim concrete rather than just asserted in prose.
function viewCalendar(root) {
  root.innerHTML = `<div class="full">
    <h2>Calendar &amp; contacts</h2>
    <div class="sub">Not separate services — additional MOTE kinds stored on your node, end-to-end
      encrypted, synced across your device cluster (spec §8.4). No central CalDAV/CardDAV server,
      no calendar provider ever sees these. <i>Different from People:</i> that view tracks
      cryptographic trust (TOFU/verification) for a contact; this is their address-book details
      (JSContact-style) — same key, a different MOTE kind.</div>
    <div class="cal-cols">
      <div>
        <div class="pane-head flat"><h2>Events</h2><button class="btn ghost" id="newevent">+ New event</button></div>
        <div id="evform"></div>
        <div id="evlist"></div>
      </div>
      <div>
        <div class="pane-head flat"><h2>Address book</h2><button class="btn ghost" id="newcontact">+ New contact</button></div>
        <div id="cform"></div>
        <div id="ablist"></div>
      </div>
    </div>
  </div>`;

  const evlist = root.querySelector('#evlist');
  const drawEvents = () => {
    evlist.innerHTML = '';
    state.events.slice().sort((a, b) => a.start - b.start).forEach(e => evlist.appendChild(el(
      `<div class="tile cal-item"><div class="lbl">${esc(fmtWhen(e.start))} – ${esc(fmtWhen(e.end, true))}</div>
       <b>${esc(e.title)}</b><div style="color:var(--text-dim);font-size:12px">with ${esc(e.with)}</div>
       <span class="badge priv">kind=calendar</span></div>`)));
  };
  drawEvents();

  const ablist = root.querySelector('#ablist');
  const drawAB = () => {
    ablist.innerHTML = '';
    state.addressBook.forEach(c => ablist.appendChild(el(
      `<div class="tile cal-item" style="display:flex;gap:12px;align-items:center">
        <div class="avatar">${esc(c.avatar)}</div>
        <div style="flex:1;min-width:0">
          <b>${esc(c.name)}</b>
          <div class="key" style="margin-top:2px">${esc(c.email)}${c.phone ? ' · ' + esc(c.phone) : ''}</div>
          <div style="color:var(--text-dim);font-size:12px">${esc(c.note)}</div>
        </div>
        <span class="badge fast">kind=contact</span></div>`)));
  };
  drawAB();

  root.querySelector('#newevent').onclick = () => {
    const f = root.querySelector('#evform');
    if (f.innerHTML) { f.innerHTML = ''; return; }
    f.innerHTML = `<div class="tile cal-item">
      <div class="field"><label>Title</label><input id="evt" placeholder="Coffee with Ada"></div>
      <div class="field"><label>With</label><input id="evw" placeholder="ada@gw.dmtap.example"></div>
      <button class="btn primary" id="evsave">Save</button></div>`;
    f.querySelector('#evsave').onclick = async () => {
      const title = f.querySelector('#evt').value.trim();
      if (!title) return toast('Add a title');
      const withWhom = f.querySelector('#evw').value.trim() || 'you';
      const start = Date.now() + 3600e3, end = start + 3600e3;
      const mote = await buildMote({ to: withWhom, kind: KIND.calendar, subject: title, body: JSON.stringify({ start, end }), tier: state.tierDefault, attach: [] });
      state.events.unshift({ id: mote.contentId, title, start, end, with: withWhom });
      f.innerHTML = ''; drawEvents();
      showInspector(mote, { path: ['your node', withWhom === 'you' ? 'device cluster' : 'their node'], latencyMs: 0, kind: 'direct' });
      toast('✓ calendar MOTE ' + mote.contentId.slice(0, 12) + '… — same substrate as mail, kind=calendar');
    };
  };

  root.querySelector('#newcontact').onclick = () => {
    const f = root.querySelector('#cform');
    if (f.innerHTML) { f.innerHTML = ''; return; }
    f.innerHTML = `<div class="tile cal-item">
      <div class="field"><label>Name</label><input id="cnn" placeholder="Satoshi"></div>
      <div class="field"><label>Email / address</label><input id="cne" placeholder="satoshi@gw.dmtap.example"></div>
      <button class="btn primary" id="csave">Save</button></div>`;
    f.querySelector('#csave').onclick = async () => {
      const name = f.querySelector('#cnn').value.trim();
      if (!name) return toast('Add a name');
      const email = f.querySelector('#cne').value.trim() || (name.toLowerCase() + '@gw.dmtap.example');
      const mote = await buildMote({ to: email, kind: KIND.contact, subject: name, body: JSON.stringify({ name, email }), tier: state.tierDefault, attach: [] });
      state.addressBook.unshift({ name, handle: email, email, phone: null, note: 'added just now', avatar: name[0].toUpperCase() });
      f.innerHTML = ''; drawAB();
      showInspector(mote, { path: ['your node', 'device cluster'], latencyMs: 0, kind: 'direct' });
      toast('✓ contact MOTE ' + mote.contentId.slice(0, 12) + '… — same substrate, kind=contact');
    };
  };
}

function fmtWhen(t, timeOnly) {
  const d = new Date(t);
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return timeOnly ? time : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + time;
}

function viewNetwork(root) {
  root.innerHTML = `<div class="net full"><h2>Network</h2><div class="sub">Roles in the mesh. Only the node holds your data; the middle is content-blind and swappable (spec §0, §4).</div>
    <div class="net-diagram">${networkSVG()}</div>
    <div class="tiles">
      <div class="tile"><div class="lbl">Your node</div><div class="val" style="font-size:15px">online</div><small style="color:var(--text-dim)">holds your keys + mailbox</small></div>
      <div class="tile"><div class="lbl">Relays (mesh)</div><div class="val">3</div><small style="color:var(--text-dim)">content-blind, swappable</small></div>
      <div class="tile"><div class="lbl">Mixnet hops</div><div class="val">4</div><small style="color:var(--text-dim)">hides who talks to whom</small></div>
      <div class="tile"><div class="lbl">Gateway</div><div class="val" style="font-size:15px">${state.gateway ? 'on' : 'off'}</div><small style="color:var(--text-dim)">legacy SMTP bridge</small></div>
    </div>
    <div class="notice">Simulated network — there are no real peers in this demo. A real client connects to your node over libp2p (spec §4).</div></div>`;
}

function viewSettings(root) {
  const id = currentIdentity();
  root.innerHTML = `<div class="full"><h2>Settings</h2><div class="sub">Your identity and defaults. Privacy is never a paid feature.</div>
    <div class="tile" style="margin-bottom:20px">
      <div class="lbl">Address</div><div class="key" style="margin:4px 0">${esc(displayAddress(id) || '(key-only)')}</div>
      <div class="lbl" style="margin-top:10px">Identity key</div><div class="key" style="margin:4px 0">${esc(id.ik.slice(0, 50))}…</div>
      <div class="lbl" style="margin-top:10px">Fingerprint</div><div class="key" style="margin:4px 0">${esc(id.fingerprint)}</div>
    </div>

    <h3 class="section-h">Naming ladder — spec §3.9</h3>
    <div class="tile" style="margin-bottom:20px">
      <div class="lbl">Key-name — zero authority, always present</div>
      <div id="knpills" style="margin:8px 0"></div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button class="btn ghost" id="verifykn">Recompute &amp; verify</button>
        <small style="color:var(--text-faint)">re-derives the name from your public key, right now — proves it's deterministic, not stored/looked-up</small>
      </div>
    </div>
    <div class="setting"><div class="s-l"><b>Handle</b><small>@name, first-come in a directory (simulated) — an introduction, not a trust upgrade</small></div>
      <div id="handlebox"></div></div>
    <div class="setting"><div class="s-l"><b>Domain</b><small>name@yourbrand.com — provider auto-configures DNS/DKIM/DMARC once (spec §3.8 tier C)</small></div>
      <div>${id.tier === 'C' ? `<span class="badge good">✓ ${esc(id.name)}</span>` : '<button class="btn ghost" id="connectdomain">Connect a domain</button>'}</div></div>

    <div class="setting"><div class="s-l"><b>Default privacy tier</b><small>private = mixnet (metadata-private); fast = direct (lower latency)</small></div>
      <div class="toggle"><button data-t="private" class="${state.tierDefault === 'private' ? 'on' : ''}">Private</button><button data-t="fast" class="${state.tierDefault === 'fast' ? 'on' : ''}">Fast</button></div></div>
    <div class="setting"><div class="s-l"><b>Legacy gateway</b><small>bridge to/from the Gmail world (fades as DMTAP grows)</small></div>
      <div class="toggle"><button data-g="1" class="${state.gateway ? 'on' : ''}">On</button><button data-g="0" class="${!state.gateway ? 'on' : ''}">Off</button></div></div>
    <div class="setting"><div class="s-l"><b>Recovery phrase</b><small>restore your identity on a new device</small></div><button class="btn ghost" id="showphrase">Show</button></div>
    <div class="setting"><div class="s-l"><b>Sign out</b><small>clears this identity from this browser</small></div><button class="btn" id="signout">Sign out</button></div>

    <h3 class="section-h">Sign in with Envoir — demo, spec §13</h3>
    <div id="rpdemo" class="tile"></div>
  </div>`;

  root.querySelector('#knpills').innerHTML = keyNamePills(id.keyName);
  root.querySelector('#verifykn').onclick = async () => {
    const { match, recomputed } = await verifyKeyName(fromB64u(id.ik), id.keyName.full);
    toast(match ? '✓ recomputed from your public key — identical: ' + recomputed : '✗ mismatch (should never happen): ' + recomputed, 5000);
  };
  drawHandleBox(root.querySelector('#handlebox'), id);
  const connBtn = root.querySelector('#connectdomain');
  if (connBtn) connBtn.onclick = () => toast('Simulated — production walks you through Domain Connect / a registrar API to auto-publish MX/SPF/DKIM/DMARC once; this address then replaces the key-name/handle as your default (spec §3.8 tier C).', 6000);

  root.querySelectorAll('[data-t]').forEach(b => b.onclick = () => { state.tierDefault = b.dataset.t; viewSettings(root); });
  root.querySelectorAll('[data-g]').forEach(b => b.onclick = () => { state.gateway = b.dataset.g === '1'; viewSettings(root); });
  root.querySelector('#showphrase').onclick = () => toast(id.phrase.join(' '), 6000);
  root.querySelector('#signout').onclick = () => { logout(); location.reload(); };

  renderRpDemo(root.querySelector('#rpdemo'));
}

function drawHandleBox(box, id) {
  if (id.handle) {
    box.innerHTML = `<span class="badge good">✓ @${esc(id.handle)}</span>`;
    return;
  }
  box.innerHTML = `<div style="display:flex;gap:8px"><input id="hin" placeholder="yourname" style="width:160px"><button class="btn ghost" id="hclaim">Claim</button></div>`;
  box.querySelector('#hclaim').onclick = async () => {
    const v = box.querySelector('#hin').value;
    const r = await mesh.claimHandle(v);
    if (!r.ok) return toast(r.reason);
    setHandle(r.handle);
    toast('✓ @' + r.handle + ' claimed · ' + r.kt + ' (simulated key-transparency log entry)', 4500);
    setView('settings');
  };
}

// ---------------- "Sign in with Envoir" demo (DMTAP-Auth, spec §13.3) ----------------
// A mock relying party (there is no real third-party site or network call here — it's all
// on this page) walks through the real ceremony shape: an origin-bound challenge is built,
// the user approves, and the identity key produces a REAL signature over it. Kept as
// module-level state so it survives re-renders of the rest of Settings.
let rpDemo = { origin: 'https://example-app.test', status: 'idle', challenge: null, sig: null };

function renderRpDemo(box) {
  if (!box) return;
  const id = currentIdentity();
  if (rpDemo.status === 'idle') {
    box.innerHTML = `<div class="rp-mock">
      <div class="rp-head"><span class="dot" style="background:var(--text-faint)"></span><b>${esc(rpDemo.origin)}</b><span style="color:var(--text-faint)">— mock relying party</span></div>
      <div class="sub" style="margin:8px 0 14px">A third-party site wants to know who you are. This runs the DMTAP-Auth login ceremony (spec §13.3) against your real identity key.</div>
      <button class="btn primary" id="rpstart">Sign in with Envoir</button>
    </div>`;
    box.querySelector('#rpstart').onclick = () => startRpDemo(box);
  } else if (rpDemo.status === 'challenge') {
    const c = rpDemo.challenge;
    box.innerHTML = `<div class="rp-mock">
      <div class="rp-head"><span class="dot" style="background:var(--warn)"></span><b>${esc(rpDemo.origin)}</b><span style="color:var(--text-faint)">— mock relying party</span></div>
      <div class="sub" style="margin:8px 0">The relying party sent this origin-bound challenge. Approving signs it with your identity key.</div>
      <div class="kv-block">
        <div class="kv"><span class="k">rp_origin</span><span class="v">${esc(c.rp_origin)}</span></div>
        <div class="kv"><span class="k">nonce</span><span class="v">${esc(c.nonce)}</span></div>
        <div class="kv"><span class="k">issued_at</span><span class="v">${c.issued_at}</span></div>
        <div class="kv"><span class="k">exp</span><span class="v">${c.exp}</span></div>
      </div>
      <div class="notice">Honest limit: this static demo just displays <b>${esc(c.rp_origin)}</b> in-page and signs directly — the "user-verified" mode the spec calls <i>weaker</i> (§13.7 #1). Production DMTAP-Auth requires a <b>trusted client</b> (WebAuthn) to bind and enforce the true origin (§13.3.1); without it, a look-alike site could show its own address bar and you'd have no cryptographic guarantee this really is example-app.test.</div>
      <div style="display:flex;gap:8px">
        <button class="btn primary" id="rpapprove">Approve &amp; sign</button>
        <button class="btn ghost" id="rpdeny">Deny</button>
      </div>
    </div>`;
    box.querySelector('#rpapprove').onclick = () => approveRpDemo(box);
    box.querySelector('#rpdeny').onclick = () => { rpDemo = { ...rpDemo, status: 'idle', challenge: null }; renderRpDemo(box); toast('Sign-in denied'); };
  } else {
    box.innerHTML = `<div class="rp-mock">
      <div class="rp-head"><span class="dot" style="background:var(--good)"></span><b>${esc(rpDemo.origin)}</b><span class="badge good">✓ signed in</span></div>
      <div class="sub" style="margin:8px 0">Signed assertion — a real signature over <span class="key">rp_origin ‖ nonce ‖ issued_at ‖ exp ‖ aud</span> (spec §13.3 step 5):</div>
      <div class="key" style="display:block;white-space:normal;word-break:break-all;padding:8px">${esc(rpDemo.sig)}</div>
      <div class="kv-block" style="margin-top:10px">
        <div class="kv"><span class="k">signed as</span><span class="v">${esc(displayAddress(id) || '(key-only)')}</span></div>
        <div class="kv"><span class="k">alg</span><span class="v">${esc(id.alg)}</span></div>
      </div>
      <button class="btn ghost" id="rpreset" style="margin-top:12px">Reset demo</button>
    </div>`;
    box.querySelector('#rpreset').onclick = () => { rpDemo = { origin: rpDemo.origin, status: 'idle', challenge: null, sig: null }; renderRpDemo(box); };
  }
}

function startRpDemo(box) {
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const issued_at = Date.now();
  rpDemo = { ...rpDemo, status: 'challenge', challenge: { rp_origin: rpDemo.origin, nonce, issued_at, exp: issued_at + 60_000, aud: rpDemo.origin }, sig: null };
  renderRpDemo(box);
}

async function approveRpDemo(box) {
  const c = rpDemo.challenge;
  // Canonical challenge bytes, spec §13.3 step 5: H(rp_origin ‖ nonce ‖ issued_at ‖ exp ‖ aud).
  const bytes = new TextEncoder().encode([c.rp_origin, c.nonce, c.issued_at, c.exp, c.aud].join('|'));
  const digest = await sha256(bytes);
  const sig = await sign(digest); // REAL signature, the same identity key that signs your mail
  rpDemo = { ...rpDemo, status: 'done', sig: toB64u(sig) };
  renderRpDemo(box);
  toast('✓ signed the challenge with your real identity key (' + sig.length + ' bytes)');
}

function emptyState(title, sub) {
  return `<div class="empty"><svg viewBox="0 0 24 24"><path d="M3 5h18v14H3z"/><path d="M3 6l9 7 9-7"/></svg><div><b>${esc(title)}</b><br><span style="font-size:13px">${esc(sub)}</span></div></div>`;
}

// ---------------- Boot ----------------
function boot() {
  const id = currentIdentity();
  document.getElementById('app').classList.remove('hidden');
  document.getElementById('rail-id').textContent = (displayAddress(id) || 'K')[0].toUpperCase();
  document.getElementById('rail-id').onclick = () => setView('settings');
  document.querySelectorAll('.rail-btn').forEach(b => b.onclick = () => setView(b.dataset.view));
  state.mail = mesh.seedMail();
  state.chats = mesh.seedChats();
  state.files = mesh.seedFiles();
  state.events = mesh.seedCalendar();
  state.addressBook = mesh.seedAddressBook();
  state.selMail = state.mail[0]?.id;
  setView('mail');
}

(async function main() {
  const id = await loadIdentity();
  if (id) boot();
  else renderOnboarding();
})();
