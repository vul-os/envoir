// Ambient global declaration for the Tauri/host injection seam (spec §8.1 seam): a desktop shell
// may inject a node connection config onto `window.__ENVOIR_NODE__` before store.js's
// resolveNodeConfig() runs. This has no corresponding .js file of its own — it augments the
// global scope for every sidecar .d.ts in this directory and for client/test/*.test.ts, which
// pokes this exact global to simulate an injected-host config.

import type { NodeConfig } from './store.js';

declare global {
  var __ENVOIR_NODE__: Partial<NodeConfig> | undefined;
}

export {};
