#!/usr/bin/env node
/**
 * sync-site-docs.mjs — generate site/docs/*.md from the repo's canonical docs/*.md.
 *
 * Before this script existed, docs/*.md and site/docs/*.md were two independently-maintained
 * copies with no sync step at all: 9 files were byte-identical by coincidence (whoever edited
 * last remembered to paste into both places), 8 more (docs/features/*.md) had a site-only
 * sibling under a flattened name, and site/docs/overview.md had no docs/ source file matching
 * its slug (docs/index.md, pre-rename). Editing the wrong copy silently did nothing on the
 * site. docs/ is now the single source of truth; this script derives every site/docs/*.md page
 * from it, the same pattern lilmail and wede already use in their own sync scripts.
 *
 * Run it via `npm run docs:sync`. `npm run docs:sync:check` runs the drift check instead of
 * writing (see below) — wire this into CI so a hand-edited site/docs/*.md, or a docs/*.md
 * change that was never synced, fails the build instead of silently shipping stale prose.
 *
 * Transforms applied to every page:
 *   - a generated-file banner is prepended as an HTML comment, naming the source file
 *   - repo-relative image paths (img/foo-dark.png, ../img/foo-dark.png) are rewritten to
 *     assets/screens/foo-dark.png — the lighter, site-bundled copies of the same screenshots
 *     (see scripts/sync-site-screens.mjs; site/ never reaches into docs/img/ at serve time)
 *   - cross-document .md links (including the docs/features/*.md → site/docs/*.md flattening,
 *     e.g. "features/mail.md" or "../naming.md" both resolve to "#mail" / "#naming") are
 *     rewritten to the viewer's hash routes, "#slug" or "#slug#anchor" when the link carried a
 *     heading fragment
 *   - links to anything that isn't one of our own published docs resolve to the file's real
 *     location on GitHub, so no link the site renders is ever dead
 *
 * Usage:
 *   node scripts/sync-site-docs.mjs           write site/docs/*.md (+ copy site/docs/img refs)
 *   node scripts/sync-site-docs.mjs --check    exit non-zero if site/docs/ disagrees with a
 *                                               fresh generation; writes nothing
 *
 * The --check path is a real dry run: it never calls writeFileSync/unlinkSync. A guard that
 * "checks" by writing and then declaring success is not a check — see this repo's own
 * mutation-tested history of gates that printed PASS while examining nothing.
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync, existsSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'site', 'docs');
const REPO = 'https://github.com/vul-os/envoir/blob/main/';
const CHECK = process.argv.includes('--check');

/**
 * Source of truth → published slug, in sidebar order (this order is also what the coverage
 * count below is measured against, and what docs.html's own GROUPS constant must mirror).
 */
const PAGES = [
  // ---- Start here ----
  { slug: 'overview',              src: 'docs/overview.md',                        group: 'Start here' },
  { slug: 'why-different',         src: 'docs/why-different.md',                   group: 'Start here' },
  { slug: 'getting-started',       src: 'docs/getting-started.md',                 group: 'Start here' },
  { slug: 'identity',              src: 'docs/features/identity.md',               group: 'Start here' },
  // ---- Using Envoir ----
  { slug: 'mail',                  src: 'docs/features/mail.md',                   group: 'Using Envoir' },
  { slug: 'compose',               src: 'docs/features/compose.md',                group: 'Using Envoir' },
  { slug: 'chat',                  src: 'docs/features/chat.md',                   group: 'Using Envoir' },
  { slug: 'calendar',              src: 'docs/features/calendar.md',               group: 'Using Envoir' },
  { slug: 'contacts',              src: 'docs/features/contacts.md',               group: 'Using Envoir' },
  { slug: 'files',                 src: 'docs/features/files.md',                  group: 'Using Envoir' },
  { slug: 'groups',                src: 'docs/features/groups.md',                 group: 'Using Envoir' },
  { slug: 'settings',              src: 'docs/features/settings.md',               group: 'Using Envoir' },
  // ---- Understanding it ----
  { slug: 'naming',                src: 'docs/naming.md',                          group: 'Understanding it' },
  { slug: 'transport-traceability',src: 'docs/features/transport-traceability.md', group: 'Understanding it' },
  { slug: 'privacy',               src: 'docs/privacy.md',                         group: 'Understanding it' },
  { slug: 'security',              src: 'docs/security.md',                        group: 'Understanding it' },
  // ---- Advanced ----
  { slug: 'architecture',          src: 'docs/architecture.md',                    group: 'Advanced' },
  { slug: 'protocol',              src: 'docs/protocol.md',                        group: 'Advanced' },
  { slug: 'self-hosting',          src: 'docs/features/self-hosting.md',           group: 'Advanced' },
  { slug: 'running-the-gateway',   src: 'docs/features/running-the-gateway.md',    group: 'Advanced' },
  { slug: 'client-setup',          src: 'docs/features/client-setup.md',           group: 'Advanced' },
  { slug: 'pwa-and-push',          src: 'docs/pwa-and-push.md',                    group: 'Advanced' },
  { slug: 'contributing',          src: 'docs/contributing.md',                    group: 'Advanced' },
  { slug: 'roadmap',               src: 'docs/roadmap.md',                         group: 'Advanced' },
  { slug: 'faq',                   src: 'docs/faq.md',                             group: 'Advanced' },
];

/** Basename (lowercased) → slug, for rewriting cross-document links regardless of which
 *  directory (docs/ or docs/features/) the link was written relative to. */
const BY_FILE = new Map(PAGES.map((p) => [basename(p.src).toLowerCase(), p.slug]));
BY_FILE.set('index.md', 'overview'); // pre-rename filename; defensive alias, see header comment

const BANNER = (src) =>
  `<!-- GENERATED by scripts/sync-site-docs.mjs from ${src} — do not hand-edit this file, edit the source instead. -->\n\n`;

/** Rewrite one link/image target. Returns the replacement href. */
function rewriteTarget(href, { isImage }) {
  if (/^(https?:)?\/\//i.test(href) || /^mailto:/i.test(href) || href.startsWith('#')) return href;

  const bare = href.replace(/^(?:\.\.\/)+/, '');

  if (isImage) {
    // docs/img/foo-dark.png (source) → assets/screens/foo-dark.png (the site's own,
    // lighter-weight copy of the same screenshot — see scripts/sync-site-screens.mjs).
    const shot = bare.match(/^(?:docs\/)?img\/(.+)$/i);
    if (shot) return `assets/screens/${shot[1]}`;
    return REPO.replace('/blob/', '/raw/') + bare;
  }

  // A markdown link, with or without a leading "docs/" or "features/" and with or without a
  // "#anchor" — matches "mail.md", "features/mail.md", "../naming.md#foo", "../../README.md".
  const md = bare.match(/^(?:docs\/)?(?:features\/)?([^/#?]+\.md)(?:#(.+))?$/i);
  if (md) {
    const file = md[1].toLowerCase();
    const slug = BY_FILE.get(file);
    if (slug) return `#${slug}${md[2] ? `#${md[2]}` : ''}`;
    return REPO + bare;
  }

  return REPO + bare;
}

function transform(md, src) {
  let out = md;

  // ![alt](path) and [text](path)
  out = out.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)(\s+"[^"]*")?\)/g, (m, bang, text, href, title) => {
    const next = rewriteTarget(href, { isImage: bang === '!' });
    return `${bang}[${text}](${next}${title || ''})`;
  });

  // <img src="…"> / <a href="…"> written as raw HTML (rare in these docs, handled for safety)
  out = out.replace(/(<img\b[^>]*\bsrc=")([^"]+)(")/gi, (m, a, href, b) =>
    a + rewriteTarget(href, { isImage: true }) + b);
  out = out.replace(/(<a\b[^>]*\bhref=")([^"]+)(")/gi, (m, a, href, b) =>
    a + rewriteTarget(href, { isImage: false }) + b);

  return BANNER(src) + out;
}

mkdirSync(OUT, { recursive: true });

// Drop previously generated pages that are no longer in PAGES, so a renamed/retired doc cannot
// linger on the site. In --check mode this only reports — deleting a tracked file during a
// read-only check would itself be a mutation the caller didn't ask for.
const keep = new Set(PAGES.map((p) => `${p.slug}.md`));
const existingOut = existsSync(OUT) ? readdirSync(OUT).filter((f) => f.endsWith('.md')) : [];
const stale = existingOut.filter((f) => !keep.has(f));
for (const f of stale) {
  if (CHECK) {
    console.error(`  stale    site/docs/${f} (no longer published)`);
  } else {
    unlinkSync(join(OUT, f));
    console.log(`  removed  site/docs/${f} (no longer published)`);
  }
}

let missing = 0;
let changed = 0;
let examined = 0;
for (const page of PAGES) {
  const from = join(ROOT, page.src);
  let raw;
  try {
    raw = readFileSync(from, 'utf8');
  } catch {
    console.error(`  MISSING  ${page.src} → site/docs/${page.slug}.md`);
    missing++;
    continue;
  }
  examined++;
  const to = join(OUT, `${page.slug}.md`);
  const want = transform(raw, page.src);
  const have = existsSync(to) ? readFileSync(to, 'utf8') : null;
  if (have === want) continue;
  changed++;
  if (CHECK) {
    console.error(`  drift    ${page.src} → site/docs/${page.slug}.md`);
  } else {
    writeFileSync(to, want);
    console.log(`  synced   ${page.src} → site/docs/${page.slug}.md`);
  }
}

if (missing) {
  console.error(`\nsync-site-docs: ${missing} source file(s) missing — the site will 404 on those pages.`);
  process.exit(1);
}

// Coverage assertion: every declared page must actually have been examined. A loop that
// silently examined fewer than PAGES.length is a check that passed by doing less than it
// claims to — see the repo-wide standing note on guards with no coverage-count assertion.
if (examined !== PAGES.length) {
  console.error(
    `\nsync-site-docs: examined ${examined} of ${PAGES.length} declared page(s) — the gate did not do its whole job.`,
  );
  process.exit(1);
}
if (examined === 0) {
  console.error('\nsync-site-docs: examined 0 pages — PAGES is empty or nothing resolved. Refusing to report success.');
  process.exit(1);
}

if (CHECK) {
  if (changed || stale.length) {
    console.error(
      `\nsync-site-docs: site/docs is out of date (${changed} to write, ${stale.length} stale).\n` +
      'Run `npm run docs:sync` and commit the result.',
    );
    process.exit(1);
  }
  console.log(`sync-site-docs: ${examined}/${PAGES.length} pages already up to date, 0 stale.`);
} else {
  console.log(`\nsync-site-docs: ${examined}/${PAGES.length} pages written to site/docs/ (${changed} changed, ${stale.length} removed).`);
}
