import js from '@eslint/js'
import globals from 'globals'
import { defineConfig, globalIgnores } from 'eslint/config'

// envoir is DELIBERATELY plain JavaScript: client/, console/, superadmin/ and
// status/ load via <script type="module" src="js/app.js"> with no bundler and
// no build step at all. That's a standing rule (no bundler => no TypeScript),
// not an oversight, so this config converts nothing — it only adds static
// analysis to JS that has never had any. There is no TypeScript in the
// frontend, so (unlike gitstate's web/eslint.config.js, the fleet reference
// this file's shape follows) there is no typescript-eslint block here: its
// type-aware rules have nothing to check without a tsconfig project, and
// faking one would just be theater.
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
      'no-unused-vars': 'error',
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
      'no-unused-vars': 'error',
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
      'no-unused-vars': 'error',
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
])
