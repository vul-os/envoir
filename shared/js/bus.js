// bus.js — the shared factory behind the tiny late-bound dispatch table every app's own js/bus.js
// exports as `bus`, so view modules and the shell don't import each other in a cycle. The shell
// fills these in at mount time; views just call bus.rerender(). Three of the four apps carried a
// near-verbatim copy of this object literal (client's also adds an `openCompose` field the other
// two don't have); status has no bus.js at all (no view/shell split needing one).
//
// createBus(extra) returns the three methods every app shares (setView/rerender/refreshChrome, all
// no-ops until the shell overwrites them at mount time) plus whatever extra dispatch methods the
// caller passes — client alone passes one (openCompose), see client/js/bus.js.
/**
 * @typedef {Object} BaseBus
 * @property {(view: string) => void} setView switch primary view
 * @property {() => void} rerender re-render the current view in place
 * @property {() => void} refreshChrome update rail counts / topbar after data changes
 */

/** @type {BaseBus} */
const BASE_BUS = {
  setView: (_v) => {},
  rerender: () => {},
  refreshChrome: () => {},
};

/**
 * @template {Record<string, unknown>} T
 * @param {T} [extra]
 * @returns {BaseBus & T}
 */
export function createBus(extra) {
  return Object.assign({}, BASE_BUS, extra);
}
