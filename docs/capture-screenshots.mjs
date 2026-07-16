// docs/capture-screenshots.mjs
//
// Throwaway dev script — captures real screenshots of the client (client/) for the root
// README. Not part of the build, not imported by anything. Requires:
//   - the client served statically (see README below)
//   - a local Chrome binary (path below) and puppeteer-core from the sibling dmtap build tree
//
// Usage:
//   cd client && python3 -m http.server 8137 &
//   node docs/capture-screenshots.mjs
//   kill %1   # stop the http.server job when done
//
// Output: PNGs written to docs/img/.

import puppeteer from '/Users/pc/code/envoir/dmtap/build/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, 'img');
mkdirSync(OUT, { recursive: true });

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const URL = 'http://localhost:8137/';

async function shot(page, name) {
  const path = join(OUT, name);
  await page.screenshot({ path });
  console.log('captured', name);
}

async function setTheme(page, theme) {
  // Use the real theme-toggle button so in-app state (icon, persisted settings) stays correct,
  // rather than poking data-theme directly.
  await page.evaluate((t) => {
    const current = document.documentElement.getAttribute('data-theme');
    if (current !== t) document.getElementById('theme-toggle')?.click();
  }, theme);
  await new Promise((r) => setTimeout(r, 200));
}

async function goToView(page, id) {
  await page.evaluate((viewId) => {
    document.querySelector(`.rail-btn[data-view="${viewId}"]`)?.click();
  }, id);
  await new Promise((r) => setTimeout(r, 250));
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: true,
    defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 2 },
  });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.error('pageerror:', e));
  page.on('console', (m) => { if (m.type() === 'error') console.error('console error:', m.text()); });

  await page.goto(URL, { waitUntil: 'networkidle0' });

  // ---- Onboarding: create a demo identity -------------------------------------------------
  await page.waitForSelector('#disp', { timeout: 5000 });
  await page.type('#disp', 'Ada Okonkwo');
  await page.type('#local', 'ada');
  await page.click('#next');

  await page.waitForSelector('.ob-phrase', { timeout: 5000 });
  await shot(page, 'onboarding-safety.png'); // bonus: recovery-phrase / identity-creation step (not referenced yet)
  await page.click('#next');

  await page.waitForSelector('.ob-final', { timeout: 5000 });
  await new Promise((r) => setTimeout(r, 200));
  await shot(page, 'onboarding-identity.png');
  await page.click('#go');

  // ---- Shell mounted -------------------------------------------------------------------------
  await page.waitForSelector('.app', { timeout: 5000 });
  await new Promise((r) => setTimeout(r, 300));

  // Mail — dark (default theme)
  await goToView(page, 'mail');
  await new Promise((r) => setTimeout(r, 300));
  await shot(page, 'mail-dark.png');

  // Mail — light
  await setTheme(page, 'light');
  await new Promise((r) => setTimeout(r, 250));
  await shot(page, 'mail-light.png');
  await setTheme(page, 'dark');

  // Mail reading pane with transport path graph expanded
  await goToView(page, 'mail');
  await new Promise((r) => setTimeout(r, 250));
  const pathBtn = await page.$('[data-pathbtn]');
  if (pathBtn) {
    await pathBtn.click();
    await new Promise((r) => setTimeout(r, 300));
    await shot(page, 'path-graph.png');
  } else {
    console.error('WARNING: no [data-pathbtn] found on the currently-open message — path-graph.png skipped');
  }

  // Chat — dark, with the deniable-vs-MLS protocol pill visible
  await goToView(page, 'chat');
  await new Promise((r) => setTimeout(r, 300));
  await shot(page, 'chat-dark.png');

  // Chat — light
  await setTheme(page, 'light');
  await new Promise((r) => setTimeout(r, 250));
  await shot(page, 'chat-light.png');
  await setTheme(page, 'dark');

  // Files
  await goToView(page, 'files');
  await new Promise((r) => setTimeout(r, 300));
  await shot(page, 'files-dark.png');

  // Identity (safety number view)
  await goToView(page, 'identity');
  await new Promise((r) => setTimeout(r, 300));
  await shot(page, 'identity-dark.png');

  await browser.close();
})();
