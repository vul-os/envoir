// docs/screenshotter/apps/superadmin.mjs
//
// Captures the Envoir Superadmin (superadmin/): it auto-seeds a believable fleet snapshot on
// first load (no setup flow), so this just waits for the shell to mount and walks Overview,
// Fleet, Abuse ops and Billing, each in both themes.

import { goToView, waitForText, wait, captureThemePair } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });
  await page.waitForSelector('.rail-btn', { timeout: 10000 });
  await wait(300);

  // ---- Overview ---------------------------------------------------------------------------------
  await goToView(page, 'overview');
  await captureThemePair(page, capture, 'superadmin-overview', {
    assert: () => waitForText(page, '#view', 'Overview'),
  });

  // ---- Fleet (nodes / gateways / mix nodes / relays) ---------------------------------------------
  await goToView(page, 'fleet');
  await captureThemePair(page, capture, 'superadmin-fleet', {
    assert: () => waitForText(page, '#view', 'Fleet'),
  });

  // ---- Abuse ops (content-blind by construction) -------------------------------------------------
  await goToView(page, 'abuse');
  await captureThemePair(page, capture, 'superadmin-abuse', {
    assert: () => waitForText(page, '#view', 'Abuse'),
  });

  // ---- Billing (the operator seam's metering) -----------------------------------------------------
  await goToView(page, 'billing');
  await captureThemePair(page, capture, 'superadmin-billing', {
    assert: () => waitForText(page, '#view', 'Billing'),
  });
}
