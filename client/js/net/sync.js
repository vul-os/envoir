// net/sync.js — the bridge between the real JMAP client (net/jmap.js) and the app's in-memory
// store (store.js). It pulls live mail from the user's node and MAPS it onto the exact
// `state.mail` thread/message shape the views already consume, so the UI layer (js/views/*) is
// UNCHANGED — the README's promise. It also owns the honest REAL-vs-SIMULATION mode switch:
//
//   • configured node + reachable  → REAL mode: state.mail is live JMAP data, pill says "live node"
//   • not configured / unreachable → SIMULATION stays (seed.js), pill says "simulated network"
//
// JMAP → UI mapping (RFC 8621 ↔ this client's model):
//   Mailbox (role/name) → folder      Thread (threadId)      → thread
//   keyword $seen        → read        keyword $flagged       → starred
//   keyword $draft       → drafts      other keywords         → labels
//   Email from/to/subject/receivedAt/bodyValues → message fields

import { state, resolveNodeConfig, setNetStatus, uid } from '../store.js';
import { FOLDERS, LABELS } from '../seed.js';
import { currentIdentity } from '../identity.js';
import { JmapClient } from './jmap.js';

// The Email properties we need for the thread/message shape (keeps the payload lean).
const EMAIL_PROPS = [
  'id', 'blobId', 'threadId', 'mailboxIds', 'keywords', 'size',
  'receivedAt', 'subject', 'from', 'to', 'cc', 'preview', 'hasAttachment',
  'bodyValues', 'textBody',
];

// System JMAP keywords (RFC 8621 §4.1.1) that are NOT user labels.
const SYSTEM_KEYWORDS = new Set(['$seen', '$flagged', '$answered', '$draft', '$deleted', '$forwarded']);

// Map a JMAP mailbox (its role, else its name) onto one of the client's fixed FOLDERS ids.
const FOLDER_IDS = new Set(FOLDERS.map((f) => f.id));
function mailboxToFolder(mb) {
  const role = (mb && mb.role ? String(mb.role) : '').toLowerCase();
  const byRole = { inbox: 'inbox', sent: 'sent', drafts: 'drafts', archive: 'archive', junk: 'spam', spam: 'spam', trash: 'trash' };
  if (byRole[role]) return byRole[role];
  const name = (mb && mb.name ? String(mb.name) : '').toLowerCase();
  if (FOLDER_IDS.has(name)) return name;
  if (name === 'junk') return 'spam';
  // Unknown mailbox: keep the mail reachable rather than hiding it.
  return 'inbox';
}

// The set of addresses that are "me" (so a sent message renders as You, matching seed convention).
function ownAddresses(accountId) {
  const set = new Set();
  if (accountId) set.add(accountId.toLowerCase());
  const id = currentIdentity();
  if (id) {
    if (id.primary) set.add(String(id.primary).toLowerCase());
    if (id.name) set.add(String(id.name).toLowerCase());
    for (const a of id.addresses || []) if (a && a.address) set.add(String(a.address).toLowerCase());
  }
  return set;
}

function addrString(a) {
  if (!a) return '';
  if (a.email) return a.email;
  if (a.name) return a.name;
  return '';
}

function bodyText(email) {
  const bv = email.bodyValues || {};
  // Prefer the part referenced by textBody[0].partId, else any bodyValue, else the preview.
  const partId = Array.isArray(email.textBody) && email.textBody[0] ? email.textBody[0].partId : null;
  const chosen = (partId && bv[partId]) || Object.values(bv)[0] || null;
  if (chosen && typeof chosen.value === 'string') return chosen.value;
  return email.preview || '';
}

// Map one JMAP Email → the client's message object, given the mailbox→folder lookup + own addrs.
function emailToMsg(email, mine) {
  const from = Array.isArray(email.from) && email.from[0] ? addrString(email.from[0]) : '';
  const isMe = from && mine.has(from.toLowerCase());
  const to = Array.isArray(email.to) ? email.to.map(addrString).filter(Boolean) : [];
  const time = Date.parse(email.receivedAt || '') || Date.now();
  const msg = {
    id: email.id || uid('m'),
    from: isMe ? 'you' : (from || 'unknown'),
    to,
    time,
    tier: 'private',       // JMAP carries no DMTAP tier; default to the private/mixnet framing.
    body: bodyText(email),
  };
  if (isMe) msg.me = true;
  if (email.hasAttachment) msg.attach = [{ name: 'attachment', size: email.size || 0 }];
  return msg;
}

// Fold a flat list of JMAP Emails into the client's thread objects (grouped by JMAP threadId).
function emailsToThreads(emails, mailboxById, mine) {
  const byThread = new Map();
  for (const email of emails) {
    if (!email) continue;
    const tid = email.threadId || ('T' + (email.id || uid('t')));
    let t = byThread.get(tid);
    if (!t) {
      t = { id: tid, subject: '', labels: [], folder: 'inbox', read: true, starred: false,
        snoozeUntil: null, tier: 'private', verified: false, legacy: false, _emails: [] };
      byThread.set(tid, t);
    }
    t._emails.push(email);
  }

  const threads = [];
  for (const t of byThread.values()) {
    // Order the thread's emails chronologically, oldest first (matches seed message order).
    t._emails.sort((a, b) => (Date.parse(a.receivedAt || '') || 0) - (Date.parse(b.receivedAt || '') || 0));
    t.msgs = t._emails.map((e) => emailToMsg(e, mine));

    // Subject: the first non-empty subject in the thread.
    const subjEmail = t._emails.find((e) => e.subject) || t._emails[0];
    t.subject = (subjEmail && subjEmail.subject) || '(no subject)';

    // read = every email seen; starred = any email flagged.
    t.read = t._emails.every((e) => e.keywords && e.keywords.$seen);
    t.starred = t._emails.some((e) => e.keywords && e.keywords.$flagged);

    // Folder: from the mailbox of the most-recent email (last after the sort).
    const last = t._emails[t._emails.length - 1];
    const mbId = last && last.mailboxIds ? Object.keys(last.mailboxIds).find((k) => last.mailboxIds[k]) : null;
    t.folder = mailboxToFolder(mbId ? mailboxById.get(mbId) : null);

    // Labels: union of non-system keywords across the thread, kept as-is (a known LABELS id
    // renders a chip; an unknown one is simply carried without one — never a crash).
    const labels = new Set();
    for (const e of t._emails) {
      for (const kw of Object.keys(e.keywords || {})) {
        if (!SYSTEM_KEYWORDS.has(kw.toLowerCase())) labels.add(kw);
      }
    }
    t.labels = [...labels];

    delete t._emails;
    threads.push(t);
  }
  // Newest thread first (the list re-sorts by lastTime anyway, but keep a sane default).
  threads.sort((a, b) => (b.msgs[b.msgs.length - 1].time) - (a.msgs[a.msgs.length - 1].time));
  return threads;
}

// Pull the full mailbox from the node and rebuild state.mail. Returns { threads, sessionState }.
async function pullMail(client) {
  await client.discover();
  const mbRes = await client.mailboxGet(null);
  const mailboxById = new Map();
  for (const mb of (mbRes && mbRes.list) || []) mailboxById.set(mb.id, mb);

  // One round-trip: Email/query (all) → Email/get via back-reference.
  const getRes = await client.emailQueryGet(null, EMAIL_PROPS);
  const emails = (getRes && getRes.list) || [];

  const mine = ownAddresses(client.accountId);
  const threads = emailsToThreads(emails, mailboxById, mine);
  return { threads, sessionState: client.sessionState };
}

// Point the mail UI selection at something sensible after the store is swapped.
function reselectInbox() {
  const first = state.mail.find((t) => t.folder === 'inbox') || state.mail[0];
  state.ui.selThread = first ? first.id : null;
  state.ui.mailFolder = 'inbox';
  state.ui.mailLabel = null;
}

/**
 * Connect to the node with an explicit config, sync mail, and flip to REAL mode on success.
 * On any failure the store is left in SIMULATION mode (the demo keeps working). Returns
 * `{ ok, mode, count?, reason? }`.
 */
export async function connect(cfg) {
  if (!cfg || !cfg.baseUrl || !cfg.username || !cfg.appPassword) {
    setNetStatus({ mode: 'sim', status: 'idle', error: null });
    return { ok: false, mode: 'sim', reason: 'unconfigured' };
  }
  setNetStatus({ status: 'connecting', error: null });
  const client = new JmapClient(cfg);
  try {
    const { threads, sessionState } = await pullMail(client);
    state.mail = threads;
    reselectInbox();
    setNetStatus({
      mode: 'real', status: 'connected', error: null,
      client, accountId: client.accountId, sessionState, lastSync: Date.now(),
    });
    return { ok: true, mode: 'real', count: threads.length };
  } catch (err) {
    setNetStatus({ mode: 'sim', status: 'error', error: err && err.message ? err.message : String(err), client: null });
    return { ok: false, mode: 'sim', reason: err && err.message ? err.message : 'unreachable' };
  }
}

/**
 * Auto-connect on boot from the resolved node config (an injected Tauri config, else the saved
 * settings). Silent: if nothing is configured or the node is unreachable, the app simply stays
 * in its clearly-labeled SIMULATION. Returns the same shape as connect().
 */
export async function autoConnect() {
  const cfg = resolveNodeConfig();
  if (!cfg || !cfg.enabled || !cfg.baseUrl || !cfg.username || !cfg.appPassword) {
    setNetStatus({ mode: 'sim', status: 'idle', error: null });
    return { ok: false, mode: 'sim', reason: 'unconfigured' };
  }
  return connect(cfg);
}

/** Drop back to SIMULATION mode (used by the Settings "Disconnect" affordance). */
export function disconnect() {
  setNetStatus({ mode: 'sim', status: 'idle', error: null, client: null, sessionState: null });
}

/**
 * Refresh live mail while in REAL mode. Uses Email/changes to skip a re-pull when nothing has
 * changed; otherwise re-pulls the mailbox. No-op (returns unchanged) in SIMULATION mode.
 */
export async function syncNow() {
  const net = state.net;
  if (net.mode !== 'real' || !net.client) return { ok: false, reason: 'not-real' };
  const client = net.client;
  try {
    let changed = true;
    if (net.sessionState) {
      const delta = await client.emailChanges(net.sessionState);
      if (delta && !delta.cannotCalculateChanges) {
        const created = (delta.created || []).length;
        const updated = (delta.updated || []).length;
        const destroyed = (delta.destroyed || []).length;
        changed = created + updated + destroyed > 0;
      }
    }
    if (!changed) {
      setNetStatus({ lastSync: Date.now() });
      return { ok: true, changed: false };
    }
    const { threads, sessionState } = await pullMail(client);
    const prevSel = state.ui.selThread;
    state.mail = threads;
    if (!state.mail.some((t) => t.id === prevSel)) reselectInbox();
    setNetStatus({ sessionState, lastSync: Date.now(), status: 'connected', error: null });
    return { ok: true, changed: true, count: threads.length };
  } catch (err) {
    setNetStatus({ status: 'error', error: err && err.message ? err.message : String(err) });
    return { ok: false, reason: err && err.message ? err.message : 'sync-failed' };
  }
}
