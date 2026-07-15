# Envoir — marketing site

The public landing page for **Envoir**, the open-source reference implementation of
**[DMTAP](../../dmtap)**. This is the OSS landing page: self-contained static HTML/CSS/vanilla
JS, no framework, no build step, no external CDNs or fonts — everything (including the brand
mark) is inlined.

## Run it

```sh
cd site
python3 -m http.server 8096
# open http://localhost:8096
```

Or just open `index.html` directly in a browser.

## Structure

```
site/
├── index.html        all copy + markup, single page
├── css/style.css      design system (tokens, type, components, motion)
├── js/mesh.js          canvas hero animation: illustrative mixnet routing
├── js/main.js          theme toggle, scroll reveals, key-name readout, nav
└── assets/favicon.svg  the Envoir mark (from ../brand/logo-mark.svg)
```

## Design notes

- **Type system:** serif for editorial voice (headlines, the manifesto tone), sans for UI
  chrome, monospace for anything technical — keys, the 8-word key-name, protocol traces, spec
  section tags. The three are never mixed arbitrarily.
- **Dark-primary, theme-aware:** the site loads dark by default (the deliberate "instrument
  panel" aesthetic) and offers a manual light/dark toggle in the nav, persisted to
  `localStorage`. It does not follow `prefers-color-scheme` automatically, by design — dark is
  the brand's primary voice, not a fallback.
- **Hero visual:** a small canvas animation of a peer mesh with packets ("MOTEs") hopping
  through 2–3 relay nodes before reaching an always-on "home" node — a literal, honest
  illustration of mixnet routing, explicitly labeled "simulated routing — not live network
  telemetry" so it's never mistaken for a real dashboard. It pauses off-screen, pauses when the
  tab is hidden, and renders a single static frame under `prefers-reduced-motion`.
- **Every claim is grounded in the spec.** Section references (`§0`, `§3`, `§6`, `§12`, `§13`
  …) throughout the copy point at real DMTAP spec sections in `../../dmtap/`, and the "honest
  boundary" callout in the privacy section is drawn directly from `06-privacy.md` / the
  overview's §0.6 — this project explicitly avoids "zero-knowledge magic" framing.

## Editing

No build step. Edit `index.html` / `css/style.css` / `js/*.js` directly and reload. Keep new
sections consistent with the existing corner-bracket / eyebrow-label motifs in `style.css`
(`.eyebrow`, `.bracketed`, `.panel`) rather than introducing new card styles.
