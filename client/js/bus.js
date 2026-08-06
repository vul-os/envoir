// bus.js — this app's dispatch table, built on the shared factory (see ../../shared/js/bus.js for
// the base + why). client alone adds openCompose (wired by shell.js at mount time, called by
// compose.js/profileModal.js/app.js) — the one field none of the other three apps' bus.js have.
import { createBus } from '../../shared/js/bus.js';

/**
 * @typedef {Object} Bus
 * @property {(view: string) => void} setView switch primary view
 * @property {() => void} rerender re-render the current view in place
 * @property {(opts?: unknown) => void} openCompose
 * @property {() => void} refreshChrome update rail badges / topbar after data changes
 */
/** @type {Bus} */
export const bus = /** @type {Bus} */ (createBus({ openCompose: (/** @type {unknown} */ _opts) => {} }));
