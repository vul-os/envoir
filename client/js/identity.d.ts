// Hand-written type declaration for identity.js. This is a SIDECAR .d.ts, not a converted
// module: identity.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This file
// exists so client/test/sanitize.test.ts gets real type-checking on the address-shape validation
// it exercises. It declares only the exports the tests use; identity.js has a much larger public
// surface (createIdentity, loadIdentity, addAlias, sign, …) that is not covered here because no
// TS-checked code imports it. It is not authoritative — if identity.js's behavior changes, this
// file must be updated by hand alongside it.

/** A bare name@domain shape (no whitespace, no HTML-dangerous characters). */
export function isDnsShapedAddress(a: string): boolean;

/** Strips HTML-dangerous characters from free-typed address input. */
export function sanitizeAddressInput(s: string | null | undefined): string;
