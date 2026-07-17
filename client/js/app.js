// app.js — boot controller. Loads (or creates) the sovereign identity, then mounts the
// unified shell. Everything network-facing is simulated (seed.js + mesh-sim.js) and labeled;
// the crypto (keygen, signing, hashing, safety-number derivation) is real Web Crypto.

import { loadIdentity } from './identity.js';
import { renderOnboarding } from './onboarding.js';
import { mountShell } from './shell.js';
import { registerServiceWorker, onWakeSync } from './pwa.js';
import { state, simulateIncomingInvite } from './store.js';
import { bus } from './bus.js';

(async function main() {
  const id = await loadIdentity();
  if (id) { mountShell(); tryConnectNode(); }
  else renderOnboarding(() => { mountShell(); tryConnectNode(); });

  // PWA: register the service worker (app-shell offline cache + push wake-pings). Guarded and
  // fully optional — a browser/context without serviceWorker support just skips this, and the
  // rest of the app is unaffected either way.
  registerServiceWorker();
  // (tryConnectNode is defined below and invoked right after the shell mounts.)
  // Close the loop, honestly: a wake ping (real Push event OR the Settings "Send test wake-ping"
  // button — both post the exact same message from sw.js) means "go sync." Here that means one
  // new calendar invite MOTE actually lands — badges update, and if you're already looking at
  // Mail or Calendar the view refreshes in place so the new content visibly appears.
  onWakeSync(() => {
    const { thread, organizer } = simulateIncomingInvite();
    bus.refreshChrome();
    if (state.view === 'mail' || state.view === 'calendar') bus.rerender();
    import('./ui.js').then(({ toast, icon }) => toast(
      `${icon('bell')} Wake ping — new invite from ${organizer.name} synced over the mesh`,
      { ms: 5200, action: 'View', onAction: () => {
        state.ui.mailFolder = 'inbox'; state.ui.mailLabel = null;
        bus.setView('mail');
        state.ui.selThread = thread.id;
        bus.rerender();
      } },
    ));
  });
})();

// Graceful REAL-mode upgrade: if a node base-URL + app-password are configured (Settings → Node,
// or a host-injected config) and the node is reachable, replace the seeded mail with live JMAP
// data and flip the UI to "live node". If nothing is configured or the node is unreachable, the
// clearly-labeled SIMULATION simply stays — the client still runs standalone as a demo. Never
// throws into boot: any failure leaves the demo intact.
async function tryConnectNode() {
  try {
    const { autoConnect } = await import('./net/sync.js');
    const res = await autoConnect();
    bus.refreshChrome();
    if (res.ok) {
      if (state.view === 'mail') bus.rerender();
      const { toast, icon } = await import('./ui.js');
      toast(`${icon('network')} Live node connected — ${res.count} conversation${res.count === 1 ? '' : 's'} synced over JMAP`, { ms: 4200 });
    }
  } catch { /* stay in simulation — the demo is unaffected */ }
}
