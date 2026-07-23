// client/test/sanitize.test.mjs — headless coverage for the rich-body HTML allow-list sanitizer
// (ui.js sanitizeNode/sanitizeHtml) and the address-shape validation that feeds it defense-in-depth
// (identity.js isDnsShapedAddress/sanitizeAddressInput). This is the client's primary XSS defense
// for rendering peer-authored mail bodies (spec §17#8) and for the free-typed address fields
// (Settings → aliases, onboarding's own-domain field) whose raw text several toasts render.
//
// sanitizeNode is DOM-STRUCTURE logic factored out of sanitizeHtml specifically so it's testable
// here: Node's `node --test` runner has no `document` (see i18n.test.mjs's header note), so this
// exercises the allow-list/attribute-stripping/href-scheme DECISIONS against a minimal fake node
// tree built by hand, rather than against real parsed HTML. What stays untested by design is the
// browser's own HTML parser (building that tree from a string) — the same DOM-bound exclusion the
// rest of this test suite already documents.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeNode, SANITIZE_ALLOWED_TAGS } from '../js/ui.js';
import { isDnsShapedAddress, sanitizeAddressInput } from '../js/identity.js';

// ---- A minimal fake DOM node, just enough surface for sanitizeNode's walk -------------------
class FakeText {
  constructor(text) { this.nodeType = 3; this.textContent = text; }
}
class FakeElement {
  constructor(tagName, attrs = {}, children = []) {
    this.nodeType = 1;
    this.tagName = tagName.toUpperCase();
    this._attrs = new Map(Object.entries(attrs));
    this.childNodes = children;
    this._parent = null;
    for (const c of children) c._parent = this;
  }
  get attributes() { return [...this._attrs.entries()].map(([name, value]) => ({ name, value })); }
  getAttribute(name) { return this._attrs.has(name) ? this._attrs.get(name) : null; }
  setAttribute(name, value) { this._attrs.set(name, value); }
  removeAttribute(name) { this._attrs.delete(name); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  replaceWith(node) {
    const idx = this._parent.childNodes.indexOf(this);
    this._parent.childNodes[idx] = node;
    node._parent = this._parent;
  }
}
const mkText = (s) => new FakeText(s);
const root = (...children) => new FakeElement('DIV', {}, children);

test('sanitizeNode drops a disallowed tag (script) but keeps its text, inert', () => {
  const r = root(new FakeElement('SCRIPT', {}, [mkText("alert('xss')")]));
  sanitizeNode(r, mkText);
  assert.equal(r.childNodes.length, 1);
  assert.equal(r.childNodes[0].nodeType, 3);
  assert.equal(r.childNodes[0].textContent, "alert('xss')"); // literal text, never executable
});

test('sanitizeNode strips an <img> entirely (no allow-listed content, no onerror sink)', () => {
  const r = root(new FakeElement('IMG', { src: 'x', onerror: "alert(1)" }, []));
  sanitizeNode(r, mkText);
  assert.equal(r.childNodes.length, 1);
  assert.equal(r.childNodes[0].nodeType, 3);
  assert.equal(r.childNodes[0].textContent, ''); // img has no text content to preserve
});

test('sanitizeNode strips a javascript: href on <a> (classic sandbox/XSS bypass)', () => {
  const a = new FakeElement('A', { href: 'javascript:alert(1)' }, [mkText('click me')]);
  const r = root(a);
  sanitizeNode(r, mkText);
  assert.equal(a.getAttribute('href'), null);
  assert.equal(a.getAttribute('target'), '_blank');
  assert.equal(a.getAttribute('rel'), 'noopener noreferrer nofollow');
});

test('sanitizeNode keeps a real https href on <a> and forces target/rel (tabnabbing guard)', () => {
  const a = new FakeElement('A', { href: 'https://example.com/x' }, [mkText('link')]);
  sanitizeNode(root(a), mkText);
  assert.equal(a.getAttribute('href'), 'https://example.com/x');
  assert.equal(a.getAttribute('target'), '_blank');
  assert.equal(a.getAttribute('rel'), 'noopener noreferrer nofollow');
});

test('sanitizeNode keeps a mailto: href on <a>', () => {
  const a = new FakeElement('A', { href: 'mailto:you@example.com' }, [mkText('mail')]);
  sanitizeNode(root(a), mkText);
  assert.equal(a.getAttribute('href'), 'mailto:you@example.com');
});

test('sanitizeNode strips a data: href on <a> (not in the https/mailto allow-list)', () => {
  const a = new FakeElement('A', { href: 'data:text/html,<script>alert(1)</script>' }, [mkText('x')]);
  sanitizeNode(root(a), mkText);
  assert.equal(a.getAttribute('href'), null);
});

test('sanitizeNode strips an onclick attribute even alongside a valid https href', () => {
  const a = new FakeElement('A', { href: 'https://example.com', onclick: 'alert(1)' }, []);
  sanitizeNode(root(a), mkText);
  assert.equal(a.getAttribute('href'), 'https://example.com');
  assert.equal(a.getAttribute('onclick'), null);
});

test('sanitizeNode strips ALL attributes on a non-<a> allowed tag (no style/onclick smuggling)', () => {
  const div = new FakeElement('DIV', { style: 'background:url(javascript:alert(1))', onclick: 'x()' }, [mkText('hi')]);
  sanitizeNode(root(div), mkText);
  assert.equal(div.attributes.length, 0);
});

test('sanitizeNode compares attribute names case-insensitively — an uppercase HREF with a valid scheme survives, ONCLICK never does', () => {
  const a = new FakeElement('A', { HREF: 'https://example.com', ONCLICK: 'alert(1)' }, []);
  sanitizeNode(root(a), mkText);
  assert.equal(a.getAttribute('HREF'), 'https://example.com'); // name-cased check, still recognized as href
  assert.equal(a.getAttribute('ONCLICK'), null); // never allow-listed regardless of case
});

test('sanitizeNode unwraps a disallowed tag NESTED inside an allowed one, flattening its text', () => {
  const svg = new FakeElement('SVG', { onload: 'alert(1)' }, [new FakeElement('B', {}, [mkText('hi')])]);
  const p = new FakeElement('P', {}, [svg]);
  sanitizeNode(root(p), mkText);
  assert.equal(p.childNodes.length, 1);
  assert.equal(p.childNodes[0].nodeType, 3);
  assert.equal(p.childNodes[0].textContent, 'hi'); // flattened, no markup survives
});

test('sanitizeNode recurses into allowed nested formatting (b inside p stays structured)', () => {
  const b = new FakeElement('B', {}, [mkText('bold')]);
  const p = new FakeElement('P', {}, [mkText('plain '), b]);
  sanitizeNode(root(p), mkText);
  assert.equal(p.childNodes.length, 2);
  assert.equal(p.childNodes[1].tagName, 'B');
  assert.equal(p.childNodes[1].nodeType, 1);
});

test('sanitizeNode allow-list matches the documented tag set exactly', () => {
  assert.deepEqual([...SANITIZE_ALLOWED_TAGS].sort(), [
    'A', 'B', 'BLOCKQUOTE', 'BR', 'CODE', 'DIV', 'EM', 'H1', 'H2', 'H3',
    'I', 'LI', 'OL', 'P', 'PRE', 'SPAN', 'STRONG', 'U', 'UL',
  ].sort());
});

// ---- Address-shape validation (identity.js) — the source-side half of the same defense --------
// (client/js/views/settings.js's alias list + toasts, and onboarding.js's own-domain address
// field, both funnel through this before an address is ever stored or rendered.)

test('isDnsShapedAddress accepts ordinary name@domain and plus-addressed forms', () => {
  assert.equal(isDnsShapedAddress('ada@envoir.org'), true);
  assert.equal(isDnsShapedAddress('ada+work@envoir.org'), true);
  assert.equal(isDnsShapedAddress('a.b-c_d@sub.example.co'), true);
});

test('isDnsShapedAddress rejects HTML-dangerous characters even in an otherwise valid shape', () => {
  assert.equal(isDnsShapedAddress('<script>alert(1)</script>@evil.com'), false);
  assert.equal(isDnsShapedAddress('<img/src=x/onerror=alert(1)>@evil.com'), false);
  assert.equal(isDnsShapedAddress('"><svg/onload=alert(1)>@evil.com'), false);
  assert.equal(isDnsShapedAddress("a'b@evil.com"), false);
  assert.equal(isDnsShapedAddress('a`b@evil.com'), false);
});

test('isDnsShapedAddress rejects whitespace and non-DNS shapes', () => {
  assert.equal(isDnsShapedAddress('a b@evil.com'), false);
  assert.equal(isDnsShapedAddress('no-at-sign.example.com'), false);
  assert.equal(isDnsShapedAddress('a@b'), false); // no TLD dot
});

test('sanitizeAddressInput strips HTML-dangerous characters, leaving the rest untouched', () => {
  assert.equal(sanitizeAddressInput('<img src=x onerror=alert(1)>you@brand.com'), 'img src=x onerror=alert(1)you@brand.com');
  assert.equal(sanitizeAddressInput('you@brand.com'), 'you@brand.com');
  assert.equal(sanitizeAddressInput(`"'<>\``), '');
  assert.equal(sanitizeAddressInput(null), '');
});
