/*
 * Envoir landing page — the page IS the app shell (topbar / rail / list column /
 * reading pane / statusbar), so this file's job is mostly the same wiring
 * client/js/shell.js does for the real app: theme toggle (persisted), a working
 * command palette, and an IntersectionObserver-driven "what's active" sync across
 * the rail, the folder list, and the statusbar — plus the landing-only bits
 * (scroll reveals, the hero address readout, a reading-progress rule).
 * No dependencies, no build step.
 */
(function () {
  "use strict";

  var root = document.documentElement;
  var STORAGE_KEY = "envoir-theme";
  var $ = function (s, c) { return (c || document).querySelector(s); };
  var $$ = function (s, c) { return [].slice.call((c || document).querySelectorAll(s)); };

  /* ---------------- theme toggle ---------------- */
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var toggle = document.getElementById("theme-toggle");
    if (toggle) toggle.setAttribute("aria-checked", theme === "light" ? "true" : "false");
    try { window.dispatchEvent(new Event("envoir:theme-changed")); } catch (e) { /* older browsers */ }
  }

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(STORAGE_KEY); } catch (e) { /* storage disabled */ }
    // dark is the deliberate primary; only a returning visitor's explicit
    // choice moves it to light.
    applyTheme(saved === "light" ? "light" : "dark");

    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(next);
      try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* ignore */ }
    });
  }

  /* ---------------- theme-aware screenshots ----------------
   * Every product screenshot is wrapped in <picture data-shot data-dark="..."
   * data-light="...">, with a plain dark-theme <img> as the pre-JS / no-JS
   * fallback. Deliberately NOT a <source media="prefers-color-scheme"> — see
   * the note this file used to carry: a matching <source> silently overrides
   * this script's own img.src writes once the toggle disagrees with the OS.
   * One flat img target removes the competing resolution path entirely. */
  function initThemeShots() {
    var pics = document.querySelectorAll("picture[data-shot]");
    if (!pics.length) return;

    function apply() {
      var dark = root.getAttribute("data-theme") !== "light";
      pics.forEach(function (pic) {
        var img = pic.querySelector("img");
        if (!img) return;
        var wanted = dark ? pic.getAttribute("data-dark") : pic.getAttribute("data-light");
        if (wanted && img.getAttribute("src") !== wanted) img.setAttribute("src", wanted);
      });
    }

    apply();
    window.addEventListener("envoir:theme-changed", apply);
  }

  /* ---------------- scroll reveals ----------------
   * root: the reading pane — it's the only scrolling surface on this page
   * (the app's real .view scrolls independently of its rail/list chrome too),
   * so intersection has to be measured against it, not the browser viewport. */
  function initReveals() {
    var pane = document.querySelector(".reading-pane");
    var items = document.querySelectorAll(".reveal");
    if (!items.length) return;

    if (!("IntersectionObserver" in window)) {
      items.forEach(function (el) { el.classList.add("in-view"); });
      return;
    }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          io.unobserve(entry.target);
        }
      });
    }, { root: pane || null, threshold: 0.1, rootMargin: "0px 0px -6% 0px" });

    items.forEach(function (el) { io.observe(el); });
  }

  /* ---------------- hero address cycling readout ---------------- */
  function initAddress() {
    var el = document.getElementById("address-readout");
    if (!el) return;
    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) return; // leave the static example address, no cycling

    var names = [
      "you@envoir.org",
      "alice@yourbrand.com",
      "sam+news@envoir.org"
    ];
    var idx = 0;
    var cursor = '<span class="cursor">&nbsp;</span>';

    function typeOut(text, cb) {
      var i = 0;
      (function tick() {
        el.innerHTML = text.slice(0, i) + cursor;
        i++;
        if (i <= text.length) {
          setTimeout(tick, 26);
        } else if (cb) {
          setTimeout(cb, 2600);
        }
      })();
    }

    function eraseThenNext() {
      var text = names[idx];
      var i = text.length;
      (function tick() {
        el.innerHTML = text.slice(0, i) + cursor;
        i--;
        if (i >= 0) {
          setTimeout(tick, 14);
        } else {
          idx = (idx + 1) % names.length;
          typeOut(names[idx], eraseThenNext);
        }
      })();
    }

    setTimeout(function () { eraseThenNext(); }, 3200);
  }

  /* ---------------- in-page nav: smooth-scroll every #anchor link ---------------- */
  function initNavLinks() {
    var links = document.querySelectorAll('a[href^="#"]');
    links.forEach(function (a) {
      a.addEventListener("click", function (e) {
        var id = a.getAttribute("href").slice(1);
        if (!id) return;
        if (id.charAt(0) === "/") return; // docs.js's own hash router, not an anchor
        var target = document.getElementById(id);
        if (!target) return;
        e.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        history.pushState(null, "", "#" + id);
      });
    });
  }

  /* ---------------- reading-progress bar ----------------
   * Sticky inside the reading pane, driven off the PANE's scroll, not the
   * window's — the window itself never scrolls on this page. */
  function initProgress() {
    var pane = document.querySelector(".reading-pane");
    var bar = document.getElementById("scroll-progress-bar");
    if (!pane || !bar) return;
    var ticking = false;
    function update() {
      ticking = false;
      var max = (pane.scrollHeight - pane.clientHeight) || 1;
      var p = Math.min(1, Math.max(0, pane.scrollTop / max));
      bar.style.transform = "scaleX(" + p + ")";
    }
    pane.addEventListener("scroll", function () {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    window.addEventListener("resize", update, { passive: true });
    update();
  }

  /* ---------------- shell nav sync: rail + folder list + statusbar ----------------
   * Two IntersectionObservers, both rooted at the reading pane:
   *  - one over the 7 rail targets (Mail/Chat/Calendar/Contacts/Files/Identity/
   *    Groups — the same surfaces the real rail switches between)
   *  - one over the 11 top-level sections the folder list indexes
   * Whichever target is crossing the pane's vertical middle gets the "on"
   * treatment — same rule wede's activity bar / explorer / tabbar use. */
  var SECTION_LABEL = {
    top: "Welcome", why: "Why different", naming: "Your address", product: "Product tour",
    "how-to": "How to use it", traceability: "Traceability", parity: "Feature parity",
    privacy: "Honest status", "open-source": "Self-hosting", trust: "Trust", "get-started": "Get started"
  };
  var RAIL_IDS = ["top", "chat", "calendar", "contacts", "files", "identity", "groups"];
  var LIST_IDS = ["top", "why", "naming", "product", "how-to", "traceability", "parity", "privacy", "open-source", "trust", "get-started"];

  function initShellNav() {
    var pane = document.querySelector(".reading-pane");
    if (!pane) return;

    var railEls = {};
    $$(".rail-btn[data-rail]").forEach(function (a) { railEls[a.dataset.rail] = a; });
    var folderEls = {};
    $$(".folder[data-folder]").forEach(function (a) { folderEls[a.dataset.folder] = a; });
    var sbSection = document.getElementById("sb-section");

    function setRail(id) {
      Object.keys(railEls).forEach(function (k) { railEls[k].classList.toggle("on", k === id); });
    }
    function setFolder(id) {
      Object.keys(folderEls).forEach(function (k) { folderEls[k].classList.toggle("on", k === id); });
      if (sbSection && SECTION_LABEL[id]) sbSection.textContent = SECTION_LABEL[id];
    }

    if (!("IntersectionObserver" in window)) return;

    var railTargets = RAIL_IDS.map(function (id) { return document.getElementById(id); }).filter(Boolean);
    var railIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) setRail(e.target.id); });
    }, { root: pane, rootMargin: "-40% 0px -55% 0px" });
    railTargets.forEach(function (el) { railIO.observe(el); });

    var listTargets = LIST_IDS.map(function (id) { return document.getElementById(id); }).filter(Boolean);
    var listIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) setFolder(e.target.id); });
    }, { root: pane, rootMargin: "-12% 0px -70% 0px" });
    listTargets.forEach(function (el) { listIO.observe(el); });
  }

  /* ---------------- count-up for the parity tally ---------------- */
  function initCounters() {
    var nums = document.querySelectorAll(".pt-num");
    if (!nums.length) return;
    var pane = document.querySelector(".reading-pane");
    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    nums.forEach(function (el) {
      var target = parseInt((el.textContent || "").replace(/[^0-9]/g, ""), 10);
      if (isNaN(target)) return;
      el.setAttribute("data-target", String(target));
    });

    if (reduceMotion || !("IntersectionObserver" in window)) return;

    function run(el) {
      var target = parseInt(el.getAttribute("data-target"), 10);
      if (isNaN(target)) return;
      var dur = 900, start = null;
      el.textContent = "0";
      (function frame(ts) {
        if (start === null) start = ts;
        var t = Math.min(1, (ts - start) / dur);
        var eased = 1 - Math.pow(1 - t, 3);
        el.textContent = String(Math.round(target * eased));
        if (t < 1) requestAnimationFrame(frame);
        else el.textContent = String(target);
      })(performance.now());
    }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { run(e.target); io.unobserve(e.target); }
      });
    }, { root: pane || null, threshold: 0.6 });
    nums.forEach(function (el) { io.observe(el); });
  }

  /* ---------------- command palette — the app ships one, so the page has one ----------------
   * Same pattern as wede's site: a flat list of jump targets (every section this
   * page actually has, plus real external links), fuzzy-filtered by substring. */
  function initPalette() {
    var backdrop = document.getElementById("paletteBackdrop");
    var input = document.getElementById("paletteInput");
    var results = document.getElementById("paletteResults");
    var openBtn = document.getElementById("cmd-open");
    var searchBox = document.getElementById("site-search");
    if (!backdrop || !input || !results) return;

    var CMDS = LIST_IDS.map(function (id) {
      return { label: SECTION_LABEL[id], hint: "section", href: "#" + id, icon: "file" };
    }).concat([
      { label: "Mail",     hint: "rail",     href: "#top",      icon: "file" },
      { label: "Chat",     hint: "rail",     href: "#chat",     icon: "file" },
      { label: "Calendar", hint: "rail",     href: "#calendar", icon: "file" },
      { label: "Contacts", hint: "rail",     href: "#contacts", icon: "file" },
      { label: "Files",    hint: "rail",     href: "#files",    icon: "file" },
      { label: "Identity", hint: "rail",     href: "#identity", icon: "file" },
      { label: "Groups",   hint: "rail",     href: "#groups",   icon: "file" },
      { label: "Read the docs",      hint: "docs",     href: "docs.html",                          icon: "book" },
      { label: "Envoir on GitHub",   hint: "external",  href: "https://github.com/vul-os/envoir",   icon: "ext" },
      { label: "DMTAP spec (kotva)", hint: "external",  href: "https://github.com/vul-os/kotva",    icon: "ext" },
      { label: "Toggle theme",       hint: "command",   action: function () { document.getElementById("theme-toggle").click(); }, icon: "sun" }
    ]);
    var ICONS = {
      file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
      book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
      ext:  '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6M10 14L21 3"/>',
      sun:  '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"/>'
    };

    var shown = [], sel = 0;

    function render(q) {
      var needle = q.trim().toLowerCase();
      shown = CMDS.filter(function (c) {
        return !needle || (c.label + " " + c.hint).toLowerCase().indexOf(needle) !== -1;
      });
      sel = 0;
      if (!shown.length) { results.innerHTML = '<div class="empty">Nothing matches that.</div>'; return; }
      results.innerHTML = shown.map(function (c, i) {
        return '<button class="row" data-i="' + i + '" aria-selected="' + (i === 0) + '">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
          ICONS[c.icon] + '</svg>' + c.label + '<span class="k">' + c.hint + '</span></button>';
      }).join("");
    }
    function highlight() {
      $$(".row", results).forEach(function (r, i) { r.setAttribute("aria-selected", String(i === sel)); });
      var el = $$(".row", results)[sel];
      if (el) el.scrollIntoView({ block: "nearest" });
    }
    function run(i) {
      var c = shown[i];
      if (!c) return;
      close();
      if (c.action) { c.action(); return; }
      if (/^https?:/.test(c.href)) { window.open(c.href, "_blank", "noopener"); return; }
      if (c.href.charAt(0) === "#") {
        var target = document.getElementById(c.href.slice(1));
        if (target) { target.scrollIntoView({ behavior: "smooth", block: "start" }); history.pushState(null, "", c.href); return; }
      }
      window.location.href = c.href;
    }
    function open(prefill) {
      backdrop.hidden = false;
      input.value = prefill || "";
      render(input.value);
      input.focus();
    }
    function close() { backdrop.hidden = true; if (searchBox) searchBox.blur(); }

    if (openBtn) openBtn.addEventListener("click", function () { open(""); });
    if (searchBox) {
      searchBox.addEventListener("focus", function () { open(""); });
      searchBox.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); open(searchBox.value); } });
    }
    backdrop.addEventListener("click", function (e) { if (e.target === backdrop) close(); });
    input.addEventListener("input", function () { render(input.value); });
    results.addEventListener("click", function (e) {
      var row = e.target.closest(".row");
      if (row) run(parseInt(row.dataset.i, 10));
    });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, shown.length - 1); highlight(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); highlight(); }
      else if (e.key === "Enter") { e.preventDefault(); run(sel); }
      else if (e.key === "Escape") { e.preventDefault(); close(); }
    });
    document.addEventListener("keydown", function (e) {
      var k = e.key.toLowerCase();
      if ((e.metaKey || e.ctrlKey) && (k === "k" || k === "p")) { e.preventDefault(); open(""); }
      else if (e.key === "Escape" && !backdrop.hidden) close();
    });
  }

  function init() {
    initTheme();
    initThemeShots();
    initReveals();
    initAddress();
    initNavLinks();
    initProgress();
    initShellNav();
    initCounters();
    initPalette();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
