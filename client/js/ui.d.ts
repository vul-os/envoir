// Hand-written type declaration for ui.js. This is a SIDECAR .d.ts, not a converted module:
// ui.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This file
// exists so client/test/*.test.ts get real type-checking on the two pieces of ui.js they exercise
// headlessly: the HTML allow-list sanitizer walk and a couple of pure formatting helpers. ui.js's
// much larger public surface (icon, avatar, toast, openModal, commandMenu, …) is DOM-bound and
// not covered here because no TS-checked code imports it. It is not authoritative — if ui.js's
// behavior changes, this file must be updated by hand alongside it.

/** The minimal text-node shape sanitizeNode's walk needs (nodeType 3, plain text content). */
export interface SanitizableTextNode {
  nodeType: number;
  textContent?: string;
}

/** The minimal element-node shape sanitizeNode's walk needs (nodeType 1). Deliberately loose —
 * real callers pass a live DOM Element; tests pass a plain-object stand-in with the same shape
 * (client/test/sanitize.test.ts's FakeElement). */
export interface SanitizableElementNode {
  nodeType: number;
  tagName: string;
  textContent?: string;
  childNodes: SanitizableChildNode[];
  attributes: Array<{ name: string; value: string }>;
  getAttribute(name: string): string | null;
  setAttribute(name: string, value: string): void;
  removeAttribute(name: string): void;
  replaceWith(node: SanitizableChildNode): void;
}

export type SanitizableChildNode = SanitizableElementNode | SanitizableTextNode;

export interface SanitizableParent {
  childNodes: SanitizableChildNode[];
}

/** The rich-body allow-list tag set (spec §17#8), as a Set of uppercase tag names. */
export const SANITIZE_ALLOWED_TAGS: Set<string>;

/**
 * The allow-list walk factored out of sanitizeHtml for headless testing. `mkText` defaults to a
 * real DOM text node in the browser; tests inject a plain stand-in.
 */
export function sanitizeNode(
  node: SanitizableParent,
  mkText?: (s: string) => SanitizableChildNode,
): void;

/** First code point(s) of a name, never a lone UTF-16 surrogate. */
export function initials(name: string): string;

/** Localized relative time via Intl.RelativeTimeFormat, falling back to a short date past 7d. */
export function timeAgo(t: number): string;
