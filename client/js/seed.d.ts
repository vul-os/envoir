// Hand-written type declaration for seed.js. This is a SIDECAR .d.ts, not a converted module:
// seed.js stays plain JS (it is served straight to the browser via a bare
// `<script type="module">`, with no bundler in front of it — see client/index.html — so it
// cannot become real TypeScript without adding a build step this repo does not have). This file
// exists so client/test/i18n.test.ts gets real type-checking on the one formatting helper it
// exercises. seed.js's much larger public surface (PEOPLE, seedMail, seedChats, …) is simulated
// demo data and not covered here because no TS-checked code imports it. It is not authoritative —
// if seed.js's behavior changes, this file must be updated by hand alongside it.

/** Compact byte-size formatting (locale-correct decimal separator via toLocaleString). */
export function fmtBytes(n: number): string;
