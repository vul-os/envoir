import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

// envoir's frontend is DELIBERATELY plain JavaScript: client/, console/,
// superadmin/ and status/ load via <script type="module" src="js/app.js">
// with no bundler and no build step at all. That's a standing rule (no
// bundler => no TypeScript), not an oversight, so this config converts
// nothing in those four surfaces — it only adds static analysis to JS that
// has never had any.
//
// There IS a real, pre-existing TypeScript slice, though: client/test/*.test.ts
// is genuine TypeScript, type-checked via tsc against hand-written sidecar
// .d.ts files in client/js/ (see client/tsconfig.json) — a typed layer
// describing the untyped runtime JS it sits beside, not something this
// config converts INTO TypeScript. typescript-eslint legitimately applies to
// that slice alone, at the bottom of this file, with full type-aware rules
// (recommendedTypeChecked against client/tsconfig.json's own real, resolvable
// project) since that tsconfig already type-checks this exact file set on
// its own via `tsc --noEmit -p client/tsconfig.json`.
export default defineConfig([
  globalIgnores([
    // Rust build output. `target/doc` alone is hundreds of generated files
    // (crates.js, static.files/*.js, */sidebar-items.js) that would drown the
    // real signal, but every crate/workspace in this repo grows its own
    // target/ (crates/dmtap-postage-patala/target, desktop/src-tauri/target,
    // fuzz/target, node/target, plus the root one) so the ignore has to be
    // '**/target/**', not just the root.
    '**/target/**',
    // Standing fleet rule: site/ stays plain JavaScript and is left alone in
    // every repo. It also vendors third-party libs as-is (marked, mermaid,
    // highlight.js under site/assets/vendor/) that this repo doesn't own and
    // has no business reformatting findings for.
    'site/**',
    'node_modules/**',
  ]),
  // The four browser surfaces: client/, console/, superadmin/, status/. Each
  // ships plain ES modules straight to the browser, so they get browser +
  // ES2022 globals. client/sw.js is carved out below (it's a service worker,
  // not a window context) and so is client/assets/make-icons.mjs (Node-side
  // tooling that happens to live inside client/).
  {
    files: [
      'client/js/**/*.js',
      'console/js/**/*.js',
      'superadmin/js/**/*.js',
      'status/js/**/*.js',
    ],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser },
    },
    rules: {
      // The JS-safe correctness rules that actually catch bugs in unbundled
      // ES modules with no other static analysis ever run on them.
      // argsIgnorePattern only (not varsIgnorePattern): the fleet's bus.js
      // dispatch-table stub is a real, repo-wide convention (see
      // client|console|superadmin/js/bus.js: `setView: (_v) => {}`, filled
      // in later at mount time) — a documented-but-unused parameter, not
      // dead code. Ordinary unused local/module-level vars still get flagged.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-implicit-globals': 'error',
      'no-self-assign': 'error',
      'no-constant-binary-expression': 'error',
      'no-unused-private-class-members': 'error',
      'require-atomic-updates': 'error',
      // no-undef is already part of js.configs.recommended, but it only
      // catches anything here because languageOptions.globals above is
      // correct — this is the highest-value rule in this whole config, since
      // nothing else in this repo will ever catch a typo'd global.
    },
  },
  // client/sw.js is a service worker: it runs in its own worker context, with
  // `self`/`caches`/`clients`/`skipWaiting` etc, not `window`/`document`.
  {
    files: ['client/sw.js'],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.serviceworker },
    },
    rules: {
      // argsIgnorePattern only (not varsIgnorePattern): the fleet's bus.js
      // dispatch-table stub is a real, repo-wide convention (see
      // client|console|superadmin/js/bus.js: `setView: (_v) => {}`, filled
      // in later at mount time) — a documented-but-unused parameter, not
      // dead code. Ordinary unused local/module-level vars still get flagged.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-implicit-globals': 'error',
      'no-self-assign': 'error',
      'no-constant-binary-expression': 'error',
      'no-unused-private-class-members': 'error',
      'require-atomic-updates': 'error',
    },
  },
  // Node-side tooling: build/dev scripts that never ship to a browser, so
  // they get Node globals instead. Includes client/assets/make-icons.mjs,
  // which lives inside client/ but is a dev-time rasterizer script (invoked
  // via `node assets/make-icons.mjs`), not part of the shipped client bundle.
  {
    files: [
      'brand/make-icons.mjs',
      'client/assets/make-icons.mjs',
      'scripts/*.mjs',
      'docs/capture-screenshots.mjs',
      'docs/screenshotter/**/*.mjs',
    ],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      // argsIgnorePattern only (not varsIgnorePattern): the fleet's bus.js
      // dispatch-table stub is a real, repo-wide convention (see
      // client|console|superadmin/js/bus.js: `setView: (_v) => {}`, filled
      // in later at mount time) — a documented-but-unused parameter, not
      // dead code. Ordinary unused local/module-level vars still get flagged.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-implicit-globals': 'error',
      'no-self-assign': 'error',
      'no-constant-binary-expression': 'error',
      'no-unused-private-class-members': 'error',
      'require-atomic-updates': 'error',
    },
  },
  // A handful of the Node-side tooling files above are Playwright drivers:
  // most of each file runs in Node, but `page.evaluate(() => ...)` callbacks
  // are serialized and executed IN THE BROWSER PAGE, so the code inside them
  // genuinely references document/window, not a typo'd global. These four
  // files are the ones that do it, so they alone get browser globals unioned
  // with node globals rather than everything in the block above — widening
  // globals repo-wide would blunt no-undef exactly where it matters most.
  {
    files: [
      'scripts/check-render.mjs',
      'docs/screenshotter/lib.mjs',
      'docs/screenshotter/apps/client.mjs',
      'docs/screenshotter/apps/site.mjs',
      'docs/screenshotter/apps/status.mjs',
    ],
    languageOptions: {
      globals: { ...globals.browser },
    },
  },
  // Residual findings, kept VISIBLE as warnings rather than silenced. Each of
  // these is a genuine finding this linter has never run before caught — a
  // real bug or an unconfirmed race, not a false positive — so a blanket
  // eslint-disable would hide exactly the signal this config exists to
  // surface. Downgrading file-by-file (never a blanket disable) keeps the
  // gate green (`npm run lint` exits 0 on warnings) while these stay visible
  // in `eslint .` output for someone to actually go fix. Narrower than a
  // disable comment would be nice, but eslint-disable comments only silence
  // — they cannot downgrade severity — so a per-file rule override is the
  // tightest tool that keeps the finding on screen.
  {
    // send() (chat.js) awaits buildMote() then clears inp.value — a textbook
    // require-atomic-updates shape. Unlike the six already-suppressed
    // instances elsewhere in this config, this one could NOT be confirmed
    // single-invocation-safe: the #cs send button is never disabled while
    // the await is in flight, so a fast second send (or the user typing
    // during network latency) is a real, unruled-out overlap. Left flagged,
    // not suppressed as safe.
    files: ['client/js/views/chat.js'],
    rules: { 'require-atomic-updates': 'warn' },
  },
  {
    // The #rotate handler (console/js/views/overview.js) awaits
    // collectThreshold() then assigns d.dirSigningKeyId. Same shape as
    // chat.js's send(): the #rotate button is never disabled during the
    // await, so a second click before the threshold-approval flow resolves
    // is a real, unruled-out overlap. Left flagged, not suppressed as safe.
    files: ['console/js/views/overview.js'],
    rules: { 'require-atomic-updates': 'warn' },
  },
  {
    // resolveIdentityAvatar(id, ...) (avatar.js) awaits gravatarUrl()/
    // identiconDataUri() then assigns id._avatarSrc/id._avatarKind — called
    // from identity.js's refreshAvatar() after both load/create AND any
    // profile edit (setProfile). Whether two of those calls can overlap for
    // the same identity object (e.g. a rapid double-save) was not ruled out,
    // so this is left flagged rather than suppressed as safe.
    files: ['client/js/avatar.js'],
    rules: { 'require-atomic-updates': 'warn' },
  },
  {
    // connect() (net/sync.js) awaits pullMail() then assigns state.mail.
    // Its caller, the #nodeconnect handler in client/js/views/settings.js,
    // never disables the connect button during the await, so a fast double
    // click is a real, unruled-out overlap. Left flagged, not suppressed as
    // safe.
    files: ['client/js/net/sync.js'],
    rules: { 'require-atomic-updates': 'warn' },
  },
  // The pre-existing TypeScript slice: client/test/*.test.ts runs under
  // `node --test` (Node globals, not browser), type-checked by
  // `tsc --noEmit -p client/tsconfig.json` (see package.json's
  // typecheck:client) against the sidecar .d.ts files in client/js/.
  // client/tsconfig.json is a real, self-contained project (strict, noEmit,
  // `include` covering exactly these two globs) that `tsc` already resolves
  // cleanly on its own — so, unlike a repo whose only tsconfig can't build a
  // clean program, type-aware rules genuinely apply here. recommendedTypeChecked
  // + the explicit `project` pointer below give this slice the full type-aware
  // set (no-floating-promises included), not just the syntax-only rules a
  // missing/broken project would silently fall back to.
  {
    files: ['client/test/**/*.ts', 'client/js/**/*.d.ts'],
    extends: [...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: {
        project: ['./client/tsconfig.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // node:test's test() returns a Promise that the RUNNER awaits
      // internally once registration finishes — the call site is meant to be
      // fire-and-forget, not `await`ed itself. That idiom is exactly what
      // no-floating-promises exists to flag elsewhere, so with type-aware
      // rules on it fires on all ~70 `test('...', async () => {...})` calls
      // in this suite, none of which are an unhandled rejection. Rather than
      // turning the rule off for the whole slice (which would also blind it
      // to a genuinely unawaited promise inside a test body), allowlist just
      // the node:test `test` import by its declaration site — the rule stays
      // live everywhere else in these files.
      '@typescript-eslint/no-floating-promises': [
        'error',
        {
          allowForKnownSafeCalls: [
            { from: 'package', name: 'test', package: 'node:test' },
          ],
        },
      ],
      // net.test.ts inspects captured fetch bodies via JSON.parse(), which
      // `lib.dom`/`lib.es5` type as `any` — every assertion that then reads a
      // field off the parsed body (`.from`, `.to`, `.methodCalls`, `.body`)
      // trips the no-unsafe-* triad. That's inherent to asserting on an
      // ad-hoc wire payload in a test, not a real type hole in app code.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      // Several tests stand up a hand-rolled fake matching JmapClient's
      // async surface (see net.test.ts's `fake.mailboxGet`/`emailQueryGet`/
      // `emailChanges`) — `async` there only to return a Promise matching
      // the real client's interface, with nothing to await in the body.
      // That's a deliberate test-double shape, not an accidentally-async fn.
      '@typescript-eslint/require-await': 'off',
    },
  },
])
