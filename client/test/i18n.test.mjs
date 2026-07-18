// client/test/i18n.test.mjs — headless coverage for the globalization-audit fixes that live in
// pure, import-testable functions (the DOM-bound fixes — dir="auto", <bdi>, IME keydown guards —
// have no headless surface and are excluded by design; see the audit notes). Zero dependencies:
// node:test + node:assert, run by `npm run test:client`.
//
// Locale-sensitive assertions never hard-code a separator or a suffix word: expected fragments
// are computed with the same Intl formatters the code under test uses, so the tests pass no
// matter what default ICU locale the host runs under.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { splitRecips } from '../js/compose.js';
import { initials, timeAgo } from '../js/ui.js';
import { fmtBytes } from '../js/seed.js';

// ---- splitRecips: CJK comma variants (compose.js) ------------------------------------------

test('splitRecips splits on ASCII, full-width and ideographic commas alike', () => {
  assert.deepEqual(splitRecips('ada@envoir.org, bo@envoir.org'), ['ada@envoir.org', 'bo@envoir.org']);
  assert.deepEqual(splitRecips('ada@envoir.org，bo@envoir.org、cy@envoir.org'),
    ['ada@envoir.org', 'bo@envoir.org', 'cy@envoir.org']);
  // mixed separators + stray whitespace + empty fragments all collapse cleanly
  assert.deepEqual(splitRecips(' ada@envoir.org ，  ,、 bo@envoir.org '), ['ada@envoir.org', 'bo@envoir.org']);
  assert.deepEqual(splitRecips(''), []);
  assert.deepEqual(splitRecips(null), []);
});

// ---- initials: first code point, never a lone surrogate (ui.js) ----------------------------

test('initials takes whole code points — astral-plane chars are never split into U+FFFD halves', () => {
  assert.equal(initials('Ada Okonkwo'), 'AO');                    // the ASCII path is unchanged
  assert.equal(initials('𝔘nicode 𝔅old'), '𝔘𝔅');                  // astral-plane letters survive intact
  assert.equal(initials('😀face'), '😀F');                        // single-part: first two code points
  assert.ok(!initials('𝔘nicode 𝔅old').includes('�'));
  // no lone surrogates anywhere in the output (a lone surrogate is what renders as U+FFFD)
  for (const ch of initials('😀🎉')) assert.ok(!/^[\uD800-\uDFFF]$/.test(ch));
});

// ---- timeAgo: localized via Intl.RelativeTimeFormat, same thresholds (ui.js) ---------------

test('timeAgo renders through Intl.RelativeTimeFormat with the original thresholds', () => {
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'narrow' });
  const now = Date.now();
  assert.equal(timeAgo(now), rtf.format(0, 'second'));                 // < 45s → "now"
  assert.equal(timeAgo(now - 5 * 60e3), rtf.format(-5, 'minute'));     // < 1h  → minutes
  assert.equal(timeAgo(now - 3 * 3600e3), rtf.format(-3, 'hour'));     // < 1d  → hours
  assert.equal(timeAgo(now - 2 * 86400e3), rtf.format(-2, 'day'));     // < 7d  → days
  // ≥ 7d falls back to a short calendar date, exactly as before
  const old = now - 30 * 86400e3;
  assert.equal(timeAgo(old), new Date(old).toLocaleDateString([], { month: 'short', day: 'numeric' }));
});

// ---- fmtBytes: locale-correct decimal separator (seed.js) ----------------------------------

test('fmtBytes keeps the compact unit style but renders the decimal via the host locale', () => {
  assert.equal(fmtBytes(512), '512 B');                                // sub-KB path unchanged
  const dec = (v) => v.toLocaleString([], { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  assert.equal(fmtBytes(1536), dec(1.5) + ' KB');
  assert.equal(fmtBytes(1.5 * 1024 * 1024), dec(1.5) + ' MB');
});
