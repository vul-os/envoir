#!/usr/bin/env node
/**
 * check-lint-config.mjs — CI gate that proves the lint config actually does
 * what it claims, instead of trusting that it says the right words.
 *
 * Why this exists: two real failures across this 13-repo programme would
 * both have been caught here.
 *   1. A repo ran untyped `tseslint.configs.recommended` while reporting full
 *      file coverage — "352 files linted, 0 errors" looks identical whether
 *      type-aware rules (no-floating-promises, no-misused-promises, the
 *      no-unsafe-* family) are wired up or entirely absent.
 *   2. A repo's package.json had `"typescript": "^6.0.3"`; npm resolved
 *      7.0.2, on which typescript-eslint cannot load at all (native rewrite,
 *      classic Compiler API gone). Install succeeded, lint enforced nothing.
 *      envoir itself was on `"typescript": "^5.7.0"` until today.
 *
 * So every assertion here is BEHAVIOURAL: it runs the real tools and checks
 * what they actually did, never what the config file merely says.
 *   - Do NOT grep eslint.config.js for "recommendedTypeChecked" — a config
 *     can name that preset and still resolve no type information.
 *   - Do NOT assert on no-unused-vars — it fires untyped and proves nothing
 *     about type-awareness. no-floating-promises requires real type info
 *     (it has to know probeAsync() returns a Promise), so it's the one rule
 *     in the recommended-type-checked set that can't false-positive its way
 *     to a pass.
 *
 * ---------------------------------------------------------------------------
 * ENVOIR FORK NOTE: envoir's frontend (client/, console/, superadmin/,
 * status/) is DELIBERATELY plain, buildless JavaScript — no bundler, nothing
 * gets converted to TypeScript. The only real TypeScript is
 * client/test/**\/*.ts (+ sidecar client/js/**\/*.d.ts), type-aware per
 * eslint.config.js's bottom block, which resolves type info from
 * client/tsconfig.eslint.json — an ESLint-only project, split out from
 * client/tsconfig.json on 2026-08-06 once the latter became a ratchet
 * scoped to only the client/js files that typecheck clean today (see both
 * files' own header comments). So Assertion A's fixture goes in
 * client/test/, matching where tsconfig.eslint.json's "include" actually
 * resolves files — NOT under client/js/ or any
 * of the other three browser surfaces, which have no tsconfig at all and
 * would make the assertion meaningless (see the canonical script's footer).
 *
 * A FOURTH assertion is added below, specific to this repo: Assertion D
 * proves `no-undef` fires on a typo'd global in a plain browser-surface JS
 * file. eslint.config.js's own comment calls this "the highest-value rule in
 * this whole config, since nothing else in this repo will ever catch a typo'd
 * global" — buildless JS with no bundler, no TypeScript, and no runtime type
 * checking has exactly one static defence against a renamed/typo'd global,
 * and assertions A-C say nothing about whether it's actually live (no-undef
 * needs the right `languageOptions.globals` block wired to the right file
 * glob, which a coverage-floor or TS-pin check cannot see).
 * ---------------------------------------------------------------------------
 */

import { ESLint } from 'eslint'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// ============================================================================
// CONFIG — the only block a sibling repo should need to edit.
// ============================================================================
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url))

const CONFIG = {
  // Root of the frontend project — where eslint.config.js, tsconfig
  // reference and package.json for the app live, and the cwd ESLint runs
  // from. envoir's eslint.config.js and package.json are both at the repo
  // root (there is no web/ subdirectory), unlike gitstate.
  webRoot: path.resolve(SCRIPT_DIR, '..'),

  // Directory (relative to webRoot) that client/tsconfig.eslint.json's
  // "include" covers (`["test/**/*.ts", "js/**/*.d.ts", "js/**/*.js"]`,
  // resolved relative to that tsconfig itself — see its header for why
  // ESLint's type resolution uses this file and not the narrower,
  // ratchet-scoped client/tsconfig.json) so the type-awareness probe
  // fixture lands somewhere `parserOptions.project` actually resolves it.
  fixtureDir: 'client/test',
  // NOT *.test.ts: `npm run test:client` runs `node --test
  // 'client/test/**/*.test.ts'` — a fixture matching that glob would be
  // picked up and executed as a real test file, not just linted.
  fixtureName: '__lint_config_gate_probe.ts',

  // Repo root to walk for package.json files (assertion B).
  repoRoot: path.resolve(SCRIPT_DIR, '..'),

  // Directory names to prune anywhere in the walk (assertion B). `target` is
  // load-bearing here: every Rust crate/workspace in this repo (including
  // fuzz/, desktop/src-tauri/, node/) grows its own target/, same as
  // eslint.config.js's own `**/target/**` ignore.
  excludeDirNames: new Set(['node_modules', 'dist', 'build', 'target', '.git', 'out']),

  // Minimum number of files `eslint .` must report linting from webRoot
  // (assertion C). Measured today: `eslint .` from the repo root lints 87
  // files (0 errors, 0 warnings).
  coverageFloor: 70,
}

const FIXTURE_SOURCE = `// Auto-generated by check-lint-config.mjs — a genuine floating promise.
// If @typescript-eslint/no-floating-promises does not fire on this file,
// type-aware linting is not actually running.
async function probeAsync() {
  return 1
}

function probeFloating() {
  probeAsync()
}
`

// ----------------------------------------------------------------------------
// Assertion D fixture (envoir-specific) — no-undef on a typo'd global in a
// plain browser-surface JS file. Placed under client/js/ (one of the four
// buildless surfaces eslint.config.js's first file-block covers), which
// resolves `languageOptions.globals: { ...globals.browser }` — so a real
// browser global (`document`) resolves fine, and a plausible-looking but
// nonexistent one does not.
// ----------------------------------------------------------------------------
const NO_UNDEF_FIXTURE_DIR = 'client/js'
const NO_UNDEF_FIXTURE_NAME = '__lint_config_gate_probe_no_undef.js'
const NO_UNDEF_FIXTURE_SOURCE = `// Auto-generated by check-lint-config.mjs — a genuine typo'd global.
// If no-undef does not fire on this file, the highest-value rule in this
// repo's buildless-JS surfaces (see eslint.config.js's own comment) is not
// actually catching anything. Deliberately NOT eslint-disabled: an inline
// disable comment would suppress the very finding this fixture exists to
// produce.
function probeUndefinedGlobal() {
  return documnet.title
}
`

const failures = []
let lastPing = Date.now()

/** Watchdog heartbeat: print progress at least every ~30s of wall time. */
function tick(label) {
  const now = Date.now()
  if (now - lastPing >= 15_000) {
    console.log(`  ... ${label}`)
    lastPing = now
  }
}

function fail(id, message) {
  failures.push({ id, message })
  console.log(`FAIL [${id}] ${message}`)
}

function pass(id, message) {
  console.log(`PASS [${id}] ${message}`)
}

// ============================================================================
// Assertion A — type-awareness is live.
// ============================================================================
async function assertTypeAwarenessLive() {
  console.log('\n-- Assertion A: type-aware linting actually resolves type information --')

  const fixturePath = path.join(CONFIG.webRoot, CONFIG.fixtureDir, CONFIG.fixtureName)

  if (existsSync(fixturePath)) {
    fail(
      'A',
      `stale probe fixture already present at ${fixturePath}. Refusing to run — ` +
        `a previous run may have crashed before cleanup. Remove it by hand and re-run.`,
    )
    return
  }

  let written = false
  try {
    mkdirSync(path.dirname(fixturePath), { recursive: true })
    writeFileSync(fixturePath, FIXTURE_SOURCE)
    written = true
    tick('probe fixture written, linting it')

    const eslint = new ESLint({ cwd: CONFIG.webRoot })
    const relPath = path.relative(CONFIG.webRoot, fixturePath)
    const results = await eslint.lintFiles([relPath])
    const messages = results.flatMap((r) => r.messages)
    const hit = messages.find((m) => m.ruleId === '@typescript-eslint/no-floating-promises')

    if (hit) {
      pass('A', '@typescript-eslint/no-floating-promises fired on the probe fixture — type info is live.')
    } else {
      const ruleIds = [...new Set(messages.map((m) => m.ruleId).filter(Boolean))]
      fail(
        'A',
        'no-floating-promises did NOT fire on a genuine floating promise. ' +
          `Type-aware linting is not actually running (rules that did fire: ${ruleIds.join(', ') || 'none'}). ` +
          `Checked file: ${relPath}`,
      )
    }
  } finally {
    if (written) {
      rmSync(fixturePath, { force: true })
    }
  }
}

// ============================================================================
// Assertion B — TypeScript is pinned exactly, and node_modules agrees.
// ============================================================================
const EXACT_SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/

function walkForPackageJsons(dir, out = []) {
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return out
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (CONFIG.excludeDirNames.has(entry.name)) continue
      walkForPackageJsons(full, out)
    } else if (entry.isFile() && entry.name === 'package.json') {
      out.push(full)
    }
  }
  return out
}

function resolveInstalledTypescriptVersion(startDir) {
  // Walk upward from the package.json's own directory looking for
  // node_modules/typescript — handles both a locally-installed typescript
  // and a hoisted workspace install, without assuming a workspace exists.
  let dir = startDir
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, 'node_modules', 'typescript', 'package.json')
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, 'utf8'))
        return pkg.version
      } catch {
        return null
      }
    }
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

function assertTypescriptPinned() {
  console.log('\n-- Assertion B: typescript is pinned to an exact version, and node_modules agrees --')

  const packageJsons = walkForPackageJsons(CONFIG.repoRoot)
  tick(`scanning ${packageJsons.length} package.json files`)

  let checked = 0
  let ok = true

  for (const pkgPath of packageJsons) {
    let pkg
    try {
      pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
    } catch (err) {
      fail('B', `${pkgPath}: could not parse as JSON (${err.message})`)
      ok = false
      continue
    }

    const depFields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
    let spec = null
    for (const field of depFields) {
      if (pkg[field] && typeof pkg[field].typescript === 'string') {
        spec = pkg[field].typescript
        break
      }
    }
    if (spec === null) continue // this package.json has no typescript dependency at all

    checked++
    const rel = path.relative(CONFIG.repoRoot, pkgPath)

    if (!EXACT_SEMVER.test(spec)) {
      fail('B', `${rel}: typescript is "${spec}" — not an exact pin (ranges/carets/wildcards are how a repo silently resolves an untested TS major).`)
      ok = false
      continue
    }

    const resolved = resolveInstalledTypescriptVersion(path.dirname(pkgPath))
    if (resolved === null) {
      fail('B', `${rel}: typescript is pinned to "${spec}" but no installed node_modules/typescript was found to verify it against.`)
      ok = false
      continue
    }
    if (resolved !== spec) {
      fail('B', `${rel}: package.json pins typescript "${spec}" but the resolved/installed version is "${resolved}" — stale node_modules or lockfile.`)
      ok = false
      continue
    }

    pass('B', `${rel}: typescript exactly pinned at "${spec}", and node_modules/typescript resolves to the same version.`)
  }

  if (checked === 0) {
    fail('B', `no package.json under ${CONFIG.repoRoot} declares a typescript dependency at all — expected at least one (${path.relative(CONFIG.repoRoot, CONFIG.webRoot)}/package.json).`)
    ok = false
  }

  return ok
}

// ============================================================================
// Assertion C — ESLint actually lints a real number of files.
// ============================================================================
async function assertCoverageFloor() {
  console.log('\n-- Assertion C: ESLint actually lints a real number of files --')

  const eslint = new ESLint({ cwd: CONFIG.webRoot, errorOnUnmatchedPattern: false })
  const results = await eslint.lintFiles(['.'])
  tick(`eslint . returned ${results.length} results`)

  const lintedCount = results.length

  if (lintedCount < CONFIG.coverageFloor) {
    fail(
      'C',
      `eslint . linted only ${lintedCount} file(s), below the floor of ${CONFIG.coverageFloor}. ` +
        `A glob that stops matching still exits 0 with zero files linted — this is the exact ` +
        `failure mode this assertion exists to catch.`,
    )
  } else {
    pass('C', `eslint . linted ${lintedCount} file(s) (floor: ${CONFIG.coverageFloor}).`)
  }
}

// ============================================================================
// Assertion D (envoir-specific) — no-undef fires on a typo'd global in a
// buildless browser-surface JS file. See the file-header note for why this
// repo gets a fourth assertion that the canonical script does not have.
// ============================================================================
async function assertNoUndefLive() {
  console.log('\n-- Assertion D (envoir-specific): no-undef fires on a typo\'d global in buildless browser JS --')

  const fixturePath = path.join(CONFIG.webRoot, NO_UNDEF_FIXTURE_DIR, NO_UNDEF_FIXTURE_NAME)

  if (existsSync(fixturePath)) {
    fail(
      'D',
      `stale probe fixture already present at ${fixturePath}. Refusing to run — ` +
        `a previous run may have crashed before cleanup. Remove it by hand and re-run.`,
    )
    return
  }

  let written = false
  try {
    mkdirSync(path.dirname(fixturePath), { recursive: true })
    writeFileSync(fixturePath, NO_UNDEF_FIXTURE_SOURCE)
    written = true
    tick('no-undef probe fixture written, linting it')

    const eslint = new ESLint({ cwd: CONFIG.webRoot })
    const relPath = path.relative(CONFIG.webRoot, fixturePath)
    const results = await eslint.lintFiles([relPath])
    const messages = results.flatMap((r) => r.messages)
    const hit = messages.find((m) => m.ruleId === 'no-undef')

    if (hit) {
      pass('D', "no-undef fired on the probe fixture's typo'd global (`documnet`) — the buildless surfaces' one static defence against a typo'd global is live.")
    } else {
      const ruleIds = [...new Set(messages.map((m) => m.ruleId).filter(Boolean))]
      fail(
        'D',
        "no-undef did NOT fire on a genuine typo'd global in a buildless browser-surface file. " +
          `This is the highest-value rule in this repo's plain-JS config — nothing else catches a ` +
          `typo'd global there (rules that did fire: ${ruleIds.join(', ') || 'none'}). Checked file: ${relPath}`,
      )
    }
  } finally {
    if (written) {
      rmSync(fixturePath, { force: true })
    }
  }
}

// ============================================================================
// main
// ============================================================================
async function main() {
  console.log(`check-lint-config: webRoot=${CONFIG.webRoot}`)

  await assertTypeAwarenessLive()
  assertTypescriptPinned()
  await assertCoverageFloor()
  await assertNoUndefLive()

  console.log('')
  if (failures.length > 0) {
    console.log(`check-lint-config: ${failures.length} failure(s).`)
    process.exitCode = 1
  } else {
    console.log('check-lint-config: all assertions passed.')
  }
}

main().catch((err) => {
  console.error('check-lint-config: crashed —', err)
  process.exitCode = 1
})
