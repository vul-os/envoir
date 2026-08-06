// ui.js — the rendering primitives that were byte-identical (or identical modulo a defaultable
// option) across all four buildless browser surfaces (client/, console/, superadmin/, status/),
// each of which used to carry its own drifting copy. See each app's js/ui.js header for how it
// wraps these — every export here is either re-exported as-is or wrapped in a couple of lines
// that supply that app's own historical default, so no existing call site anywhere in any of the
// four apps changed behaviour by this file existing.
//
// Plain ES module, no bundler: this is loaded via a bare relative import (`../../shared/js/ui.js`
// from each app's js/ui.js) exactly like every other .js file in these surfaces — see e.g.
// client/index.html's `<script type="module" src="js/app.js">`.
//
// What did NOT move here, and why (see the 2026-08-06 dedup pass that added this file):
//   - icon()/the icon paths (P): each app's icon set is entirely different SVG path data; the
//     only identical part is the 1-line wrapper `<svg class="ic ...">`, not worth a shared
//     indirection over.
//   - brandMark(): the gradient/path geometry is identical, but the wrapper (class, role,
//     aria-label text, id-prefix) genuinely differs, and console/setup.js's onboarding brand mark
//     (not aria-hidden) relies on its distinct "Envoir Console" accessible name — left app-local.
//   - timeAgo(): superadmin/status handle negative deltas (future timestamps, "in 5m") that
//     client/console do not (they'd render "now"); this is an INPUT-triggered difference, not an
//     opt-in one, so it stays app-local in all four rather than being merged by inference over
//     today's call sites.
//   - fmtLong(): three genuinely different verbosity levels (client: full weekday+month names;
//     console/superadmin: short weekday+month; status: no weekday at all) — a real content
//     difference, not a shared primitive.
//   - avatar(): client's is a rich photo/ring/badge avatar keyed on a person object; console's is
//     a bare initials badge keyed on (name, hue, size) — different signatures, different purpose.
//   - initials(): client and console are byte-identical (re-exported from here); superadmin's
//     split regex also matches "-"/"_" (`/[\s.@\-_]+/` vs `/[\s.@]+/`), a real behavioural
//     difference for hyphenated/underscored names, so superadmin keeps its own local copy; status
//     doesn't have this concept (no avatars) at all.

/** @param {string} html @returns {Element} */
export const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return /** @type {Element} */ (t.content.firstElementChild); };

/** @param {unknown} s @returns {string} */
export const esc = (s) => (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] || c));

// ---- Date formatting: identical across console/superadmin/status; client uses its own fmtDay
// instead (a different format, so it never imports this) ------------------------------------
/** @param {number} t @returns {string} */
export const fmtDate = (t) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });

// ---- Avatars: initials from a name, byte-identical between client and console --------------
/** @param {string | null | undefined} name @returns {string} */
export function initials(name) {
  const parts = (name || '?').replace(/^@/, '').split(/[\s.@]+/).filter(Boolean);
  // [...s][0] takes the first CODE POINT — s[0] would split an astral-plane char (emoji,
  // rare CJK) into a lone surrogate that renders as U+FFFD.
  if (parts.length >= 2) return ([...parts[0]][0] + [...parts[1]][0]).toUpperCase();
  return [...(parts[0] || '?')].slice(0, 2).join('').toUpperCase();
}

/**
 * @typedef {Object} ToastOpts
 * @property {number} [ms]
 * @property {string} [action] optional action-button label — the button only renders when this
 *   is set, so callers that never pass it (superadmin, status) get byte-for-byte their old
 *   no-action markup.
 * @property {() => void} [onAction]
 */

// ---- Toast ------------------------------------------------------------------------------
// The full logic (incl. the action-button) was already byte-identical between client and
// console; superadmin and status had a strictly smaller version with no action-button support
// at all. Since neither ever calls toast with `opts.action` today (grepped), this superset is
// behaviour-preserving for every existing call site in all four apps. Each app's local wrapper
// supplies its own historical `ms` default (2800 / 3000 / 3000 / 2600) — see each ui.js.
/**
 * @param {string} msg
 * @param {ToastOpts} [opts]
 * @returns {HTMLElement}
 */
export function toast(msg, opts = {}) {
  const t = /** @type {HTMLElement & { _h?: ReturnType<typeof setTimeout> }} */ (document.getElementById('toast'));
  const ms = opts.ms || 3000;
  t.setAttribute('role', 'status');
  t.setAttribute('aria-live', 'polite');
  t.innerHTML = `<span>${msg}</span>${opts.action ? `<button class="toast-act">${esc(opts.action)}</button>` : ''}`;
  t.classList.remove('hidden'); t.classList.add('show');
  clearTimeout(t._h);
  if (opts.action && opts.onAction) {
    const btn = t.querySelector('.toast-act');
    const onAction = opts.onAction;
    if (btn) btn.addEventListener('click', () => { clearTimeout(t._h); t.classList.remove('show'); onAction(); });
  }
  t._h = setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.classList.add('hidden'), 200); }, ms);
  return t;
}

// ---- Modal --------------------------------------------------------------------------------
// Accessible dialog: role=dialog + aria-modal, a Tab focus-trap, initial focus onto the first
// control, and focus restoration to whatever was focused before it opened. This core reconciles
// three real differences found across the four copies:
//   - `opts.compose` (an extra "compose-card" class) — client-only; the other three never pass
//     it, so it's inert for them (verified: grepped for "compose:" outside client/js, no hits).
//   - Escape-to-close — superadmin/status wired it unconditionally, client/console didn't at all.
//     Not opt-out-able in the originals either way, so each app's wrapper hardcodes its own
//     historical default via `opts.escClose` rather than exposing a real per-call toggle.
//   - the initial-focus selector — status's original was narrower (`input, [autofocus]`, missing
//     `textarea, select`) than the other three's (`input, textarea, select, [autofocus]`); status's
//     wrapper passes `initialFocusSelector` to preserve that exactly.
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
/** @type {Element | null} */
let _modalReturnFocus = null;
/** @type {((e: KeyboardEvent) => void) | null} */
let _modalTrap = null;
/** @type {((e: KeyboardEvent) => void) | null} */
let _modalEsc = null;

/**
 * @typedef {Object} ModalOpts
 * @property {boolean} [wide]
 * @property {boolean} [compose] client-only "compose-card" styling hook — inert elsewhere.
 * @property {string} [label]
 * @property {boolean} [sticky] when true, the scrim click and Escape (if wired) don't close it.
 * @property {boolean} [escClose] whether Escape closes the modal — set by each app's wrapper,
 *   not intended as a genuine per-call toggle (see header note above).
 * @property {string} [initialFocusSelector] overrides the query used to find the control that
 *   receives initial focus; defaults to the selector every app but status originally used.
 */

/**
 * @param {string} html
 * @param {ModalOpts} [opts]
 * @returns {Element}
 */
export function openModal(html, opts = {}) {
  const m = /** @type {HTMLElement} */ (document.getElementById('modal'));
  _modalReturnFocus = document.activeElement;
  const labelAttr = opts.label ? ` aria-label="${esc(opts.label)}"` : '';
  m.innerHTML = `<div class="modal-scrim"></div><div class="modal-card ${opts.wide ? 'wide' : ''} ${opts.compose ? 'compose-card' : ''}" role="dialog" aria-modal="true"${labelAttr}>${html}</div>`;
  m.classList.remove('hidden');
  requestAnimationFrame(() => m.classList.add('show'));
  const card = /** @type {HTMLElement} */ (m.querySelector('.modal-card'));
  const scrim = m.querySelector('.modal-scrim');
  if (scrim) scrim.addEventListener('click', () => { if (!opts.sticky) closeModal(); });

  // Focus trap — keep Tab within the dialog.
  _modalTrap = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...card.querySelectorAll(FOCUSABLE)].filter(x => /** @type {HTMLElement} */ (x).offsetParent !== null);
    if (!items.length) return;
    const first = /** @type {HTMLElement} */ (items[0]), last = /** @type {HTMLElement} */ (items[items.length - 1]);
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  card.addEventListener('keydown', _modalTrap);

  if (opts.escClose) {
    _modalEsc = (e) => { if (e.key === 'Escape' && !opts.sticky) closeModal(); };
    document.addEventListener('keydown', _modalEsc);
  }

  // Initial focus: first field/control, else the dialog itself.
  requestAnimationFrame(() => {
    const target = /** @type {HTMLElement} */ (card.querySelector(opts.initialFocusSelector || 'input, textarea, select, [autofocus]') || card.querySelector(FOCUSABLE) || card);
    target.focus?.();
  });
  return card;
}

/** @returns {void} */
export function closeModal() {
  const m = /** @type {HTMLElement} */ (document.getElementById('modal'));
  m.classList.remove('show');
  const ret = _modalReturnFocus; _modalReturnFocus = null; _modalTrap = null;
  if (_modalEsc) { document.removeEventListener('keydown', _modalEsc); _modalEsc = null; }
  setTimeout(() => { m.classList.add('hidden'); m.innerHTML = ''; }, 180);
  if (ret && /** @type {HTMLElement} */ (ret).isConnected) /** @type {HTMLElement} */ (ret).focus?.();
}

// ---- Loading shimmer ------------------------------------------------------------------------
// status's row template unconditionally adds an extra `.sh-bars` placeholder the other three
// never had; `opts.bars` makes that an opt-in rather than baking it into every app. `n` has no
// default here on purpose — each app's wrapper supplies its own historical default (6/5/5/4).
/**
 * @param {number} n
 * @param {{ bars?: boolean }} [opts]
 * @returns {string}
 */
export function shimmerRows(n, opts = {}) {
  return `<div class="shimmer-wrap">${Array.from({ length: n }, () => `<div class="shimmer-row"><div class="sh-av"></div><div class="sh-lines"><div class="sh-line w70"></div><div class="sh-line w40"></div></div>${opts.bars ? '<div class="sh-bars"></div>' : ''}</div>`).join('')}</div>`;
}

/** A per-app icon renderer, e.g. each ui.js's own `icon` — see icon()'s own file for why the
 * icon SETS themselves stay app-local. @typedef {(name: string, cls?: string) => string} IconFn */

// ---- Empty / error states --------------------------------------------------------------------
// Both take the app's own icon() as their first argument (rather than duplicating an icon SET
// here, which would defeat the point) so the rendered glyph is always that app's own. console and
// superadmin already had `actionHtml`; client and status's local wrappers simply don't forward a
// 4th argument, so their call sites are unaffected either way.
/**
 * @param {IconFn} iconFn
 * @param {string} iconName
 * @param {string} title
 * @param {string} sub
 * @param {string} [actionHtml]
 * @returns {string}
 */
export function emptyState(iconFn, iconName, title, sub, actionHtml = '') {
  return `<div class="empty"><div class="empty-glow">${iconFn(iconName)}</div><b>${esc(title)}</b><span>${esc(sub)}</span>${actionHtml ? `<div class="empty-act">${actionHtml}</div>` : ''}</div>`;
}

/**
 * errorState was already byte-identical across console/superadmin/status (client doesn't have
 * one at all).
 * @param {IconFn} iconFn
 * @param {string} title
 * @param {string} sub
 * @param {string} [retryId]
 * @returns {string}
 */
export function errorState(iconFn, title, sub, retryId = '') {
  return `<div class="empty err"><div class="empty-glow bad">${iconFn('warn')}</div><b>${esc(title)}</b><span>${esc(sub)}</span>${retryId ? `<div class="empty-act"><button class="btn" id="${retryId}">${iconFn('refresh')} Retry</button></div>` : ''}</div>`;
}
