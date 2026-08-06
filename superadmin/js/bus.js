// bus.js — a tiny late-bound dispatch table so view modules and the shell don't import each
// other in a cycle. The shell fills these in at mount time; views just call bus.rerender().
/**
 * @typedef {Object} Bus
 * @property {(view: string) => void} setView switch primary view
 * @property {() => void} rerender re-render the current view in place
 * @property {() => void} refreshChrome update rail counts / topbar after data changes
 */
/** @type {Bus} */
export const bus = {
  setView: (_v) => {},     // switch primary view
  rerender: () => {},      // re-render the current view in place
  refreshChrome: () => {}, // update rail counts / topbar after data changes
};
