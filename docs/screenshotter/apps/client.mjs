// docs/screenshotter/apps/client.mjs
//
// Captures the Envoir web client (client/): runs the real onboarding flow to create a demo
// sovereign identity, then every left-rail view (Mail, Chat, Calendar, Contacts, Files,
// Identity, Groups, Settings) in both themes, plus three flows layered on top of Mail — the
// reading pane's transport-path graph, the MOTE inspector's three sealed layers, and the
// compose window. Mirrors (and generalizes) the original throwaway docs/capture-screenshots.mjs,
// which only drove this one app.

import { goToView, setTheme, captureThemePair, wait } from '../lib.mjs';

export async function run(page, baseUrl, capture) {
  await page.goto(baseUrl, { waitUntil: 'networkidle0' });

  // ---- onboarding: create a demo identity ----------------------------------------------------
  await page.waitForSelector('#disp', { timeout: 8000 });
  await page.type('#disp', 'Ada Okonkwo');
  await page.type('#local', 'ada');
  await page.click('#next');

  // Bonus, non-required shots of the onboarding flow itself — nice for docs, but a UI reshuffle
  // here shouldn't fail the whole run since the views below are the real deliverable. There is
  // no theme toggle during onboarding (data-theme is hardcoded dark in client/index.html until
  // the shell mounts), so these stay dark-only rather than faking a light variant with CSS.
  await capture('onboarding-safety.png', {
    required: false,
    assert: () => page.waitForSelector('.ob-phrase', { timeout: 6000 }),
  });
  await page.click('#next').catch(() => {});

  await capture('onboarding-identity.png', {
    required: false,
    assert: async () => { await page.waitForSelector('.ob-final', { timeout: 6000 }); await wait(200); },
  });
  await page.click('#go').catch(() => {});

  await page.waitForSelector('.rail-btn', { timeout: 8000 });
  await wait(300);

  // ---- Mail -----------------------------------------------------------------------------------
  await goToView(page, 'mail');
  await captureThemePair(page, capture, 'mail', {
    assert: () => page.waitForSelector('.mail-view', { timeout: 6000 }),
  });

  // Reading-pane transport-path graph (needs an open message with a path button). The button is
  // a real open/close toggle, so the assert only clicks it when it isn't already expanded —
  // otherwise a second click (e.g. re-asserting for the light shot) would close it again.
  // NOTE: the dark shot keeps the pre-existing theme-less filename `path-graph.png` (not
  // `path-graph-dark.png`) because site/index.html already hardcodes that path and Wave 2 — not
  // this pass — owns site/index.html; only the light pair is new.
  await goToView(page, 'mail');
  const ensurePathOpen = async () => {
    const btn = await page.$('[data-pathbtn]');
    if (!btn) throw new Error('no [data-pathbtn] found on the currently-open message');
    const expanded = await page.evaluate((el) => el.getAttribute('aria-expanded'), btn);
    if (expanded !== 'true') { await btn.click(); await wait(300); }
  };
  await capture('path-graph.png', { assert: ensurePathOpen });
  await setTheme(page, 'light');
  await capture('path-graph-light.png', { assert: ensurePathOpen });
  await setTheme(page, 'dark');

  // MOTE inspector (spec §2.1): the "why is this private" info button on the open message opens
  // a real side panel with the three sealed layers (outer/envelope/payload) plus the delivery
  // path. Re-clicking always re-populates it (it's not a toggle), so no idempotency guard needed.
  await goToView(page, 'mail');
  const openInspector = async () => {
    const btn = await page.$('[data-insp]');
    if (!btn) throw new Error('no [data-insp] found on the currently-open message');
    await btn.click();
    await page.waitForSelector('#inspector.show', { timeout: 6000 });
    await wait(150);
  };
  await captureThemePair(page, capture, 'inspector', { assert: openInspector });
  await page.evaluate(() => document.getElementById('inspector')?.querySelector('#insp-close')?.click());
  await wait(200);

  // Compose window (rich-text body, recipient resolver hint, privacy tier, attachments).
  await goToView(page, 'mail');
  const openCompose = async () => {
    await page.evaluate(() => document.querySelector('#quick-compose')?.click());
    await page.waitForSelector('#modal.show .compose', { timeout: 6000 });
    await wait(150);
  };
  await captureThemePair(page, capture, 'compose', { assert: openCompose });
  await page.evaluate(() => document.querySelector('#modal.show .compose #cx')?.click());
  await wait(250);

  // ---- Chat -----------------------------------------------------------------------------------
  await goToView(page, 'chat');
  await captureThemePair(page, capture, 'chat', {
    assert: () => page.waitForSelector('.chat-view', { timeout: 6000 }),
  });

  // ---- Calendar (month view, then the agenda panel opened alongside it) -----------------------
  await goToView(page, 'calendar');
  const toMonth = async () => {
    await page.evaluate(() => document.querySelector('#calseg [data-v="month"]')?.click());
    await page.waitForFunction(
      () => document.querySelector('#calseg [data-v="month"]')?.classList.contains('on'),
      { timeout: 6000 },
    );
  };
  await captureThemePair(page, capture, 'calendar', { assert: toMonth });

  const openAgenda = async () => {
    const already = await page.evaluate(() => document.querySelector('.cal-view')?.classList.contains('agenda-open'));
    if (!already) await page.evaluate(() => document.querySelector('#agtoggle')?.click());
    await page.waitForSelector('.cal-view.agenda-open', { timeout: 6000 });
  };
  await captureThemePair(page, capture, 'calendar-agenda', { assert: openAgenda });
  // Leave the agenda panel closed for anything captured after this.
  await page.evaluate(() => {
    if (document.querySelector('.cal-view')?.classList.contains('agenda-open')) document.querySelector('#agtoggle')?.click();
  });

  // ---- Contacts -------------------------------------------------------------------------------
  await goToView(page, 'contacts');
  await captureThemePair(page, capture, 'contacts', {
    assert: () => page.waitForSelector('.contacts-view', { timeout: 6000 }),
  });

  // ---- Files (default seed data already includes shared folders, so this one shot documents
  // both plain files and group-shared files without needing a separate "sharing" capture) -------
  await goToView(page, 'files');
  await captureThemePair(page, capture, 'files', {
    assert: () => page.waitForSelector('.files-view', { timeout: 6000 }),
  });

  // ---- Identity (safety number, device cluster, signed-in apps) -------------------------------
  await goToView(page, 'identity');
  await captureThemePair(page, capture, 'identity', {
    assert: () => page.waitForSelector('.identity-view', { timeout: 6000 }),
  });

  // ---- Groups (addresses with members — broadcast lists and channels) -------------------------
  await goToView(page, 'groups');
  await captureThemePair(page, capture, 'groups', {
    assert: () => page.waitForSelector('.groups-view', { timeout: 6000 }),
  });

  // ---- Settings -------------------------------------------------------------------------------
  await goToView(page, 'settings');
  await captureThemePair(page, capture, 'settings', {
    assert: () => page.waitForSelector('.settings-view', { timeout: 6000 }),
  });
}
