// bus.js — this app's dispatch table, built on the shared factory (see ../../shared/js/bus.js for
// the base + why). Unlike client, console has no extra dispatch method — just the shared three.
import { createBus } from '../../shared/js/bus.js';

/**
 * @typedef {Object} Bus
 * @property {(view: string) => void} setView switch primary view
 * @property {() => void} rerender re-render the current view in place
 * @property {() => void} refreshChrome update rail counts / topbar after data changes
 */
/** @type {Bus} */
export const bus = /** @type {Bus} */ (createBus());
