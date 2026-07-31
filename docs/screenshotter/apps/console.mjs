// docs/screenshotter/apps/console.mjs
//
// Captures the Envoir Management Console (console/): runs the real "connect your domain" setup
// (generates a real Ed25519 domain-authority keypair + seeds a believable demo org), then the
// Overview, Members, Directory and Billing views, each in both themes.

import { goToView, captureThemePair, waitForText, wait } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });

  // ---- setup: "connect your domain" ----------------------------------------------------------
  await page.waitForSelector('#dom', { timeout: 8000 });
  await page.type('#dom', 'abc.com');
  await page.click('#next');

  await page.waitForSelector('#go', { timeout: 8000 });
  await page.click('#go');

  // Seeding generates several real Ed25519 keypairs (members + authority) — give it real headroom.
  await page.waitForSelector('.rail-btn', { timeout: 15000 });
  await wait(400);

  // ---- Overview ---------------------------------------------------------------------------------
  await goToView(page, 'overview');
  await captureThemePair(page, capture, 'console-overview', {
    assert: () => waitForText(page, '#view', 'Overview'),
  });

  // ---- Members (sovereign vs org-managed custody) ------------------------------------------------
  await goToView(page, 'members');
  await captureThemePair(page, capture, 'console-members', {
    assert: () => waitForText(page, '#view', 'Members'),
  });

  // ---- Directory (GAL) --------------------------------------------------------------------------
  await goToView(page, 'directory');
  await captureThemePair(page, capture, 'console-directory', {
    assert: () => waitForText(page, '#view', 'Directory'),
  });

  // ---- Billing (the operator seam's metering) -----------------------------------------------------
  await goToView(page, 'billing');
  await captureThemePair(page, capture, 'console-billing', {
    assert: () => waitForText(page, '#view', 'Billing'),
  });
}
