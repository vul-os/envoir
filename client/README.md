# Envoir reference web client

A **comprehensive but simple** web client for DMTAP — mail, chat, and files on one sovereign
identity. Plain HTML + CSS + vanilla JS ES modules. **No framework, no build step, no npm.**

## Run

```sh
cd client
python3 -m http.server 8099
# open http://localhost:8099
```

Or open `index.html` via any static server. Everything is self-contained — no CDNs, no
external assets.

## What it demonstrates

- **Onboarding** with the three naming tiers (spec §3.8): A (key-only), B (name@gateway —
  the zero-DNS default), C (vanity domain). Generates a real keypair and a recovery phrase,
  and derives your **key-name** (below) — every identity gets one no matter which tier you
  picked.
- **The naming ladder** (spec §3.9): every identity's default, zero-authority address is an
  **8-word key-name + checksum word** derived from the key itself (e.g.
  `otter-heron-...-swan`) — shown at the end of onboarding and in Settings, with a
  "recompute & verify" action that re-derives it live to demonstrate it's a pure function of
  the key (same key in → same name out), not something stored or looked up. From there the
  ladder goes up in authority and down in "zero-authority-ness": an optional **@handle**
  (first-come in a simulated directory) or a **name@domain**, both explained inline and
  claimable from Settings.
- **"Sign in with Envoir"** (DMTAP-Auth, spec §13) — a mock relying-party panel in Settings.
  Clicking it builds an origin-bound challenge (`rp_origin`, `nonce`, `issued_at`, `exp`,
  `aud`), and approving it produces a **real signature** from your identity key over that
  challenge, shown as the signed assertion. The panel is explicit that this demo's origin
  display is the *weaker*, user-verified mode the spec calls out (§13.7 #1) — real
  phishing-resistance requires a trusted client (WebAuthn) binding the origin (§13.3.1),
  which a static page cannot provide.
- **Mail** — inbox, threads, compose. Sending builds a real **MOTE** and opens the
  **inspector**, visualizing its three layers (outer / envelope / payload, spec §2.1) and
  animating delivery through the mixnet (private tier) vs. direct (fast) vs. gateway (legacy).
- **Chat** — the same MOTE substrate, `kind=chat`, fast tier — showing mail and chat are one
  object rendered two ways.
- **Calendar & contacts** (spec §8.4) — events and an address book as two more MOTE kinds
  (`kind=calendar`, `kind=contact`) on the same substrate, not separate CalDAV/CardDAV
  services. "+ New event" / "+ New contact" build real signed MOTEs and open the inspector,
  the same way composing mail does. (Distinct from **People**, below: that view is about
  cryptographic *trust* in a contact; this is their address-book *details*.)
- **Files** — drop a file; it's chunked + hashed into a content-addressed manifest,
  client-side; any size (spec §5.5).
- **People** — contacts pinned by key (TOFU), with safety-number verification (spec §3.4).
- **Network** — a diagram of the node / relay / mixnet / gateway roles.
- **Settings** — naming ladder (key-name / handle / domain), default privacy tier, gateway
  toggle, identity + recovery phrase, and the sign-in demo.

## What is real vs. simulated

**Real (browser Web Crypto):**
- Ed25519 keypair generation and **signing** of the MOTE payload (falls back to ECDSA-P256
  with a clear label if the browser lacks Ed25519).
- SHA-256 hashing.
- The **key-name derivation** (`js/keyname.js`) — SHA-256 of the real public key, sliced into
  8 word-indices + a checksum word. Deterministic: verified live via the "recompute & verify"
  button, and by construction two different keys produce two different names.
- The **sign-in demo's signature** — a real Ed25519/ECDSA signature over the canonical
  challenge bytes, using the same identity key and `sign()` path as mail/chat/calendar MOTEs.
- Identity persistence (localStorage; a real node uses an OS keystore).

**Stand-in / simulated (honest limitations):**
- **SHA-256 substitutes for BLAKE3** content-addressing and for the key-name hash (browsers
  have no BLAKE3) — labeled `b3:` in the UI to match the spec's intent.
- **The key-name word list is 256 words** (8 bits/word, byte-aligned for simple code), not
  the spec's curated ~1024-word / 10-bits-per-word list for the full 80-bit (2⁸⁰) space — see
  the comment in `js/keyname.js`.
- **The @handle directory is simulated** — an in-memory `Set` in `mesh-sim.js` with a few
  pre-taken names, not a real first-come-first-served service with a key-transparency log
  (the "kt:" value shown on claim is a fake stand-in for one).
- **The "Connect a domain" action is a label only** — clicking it shows a toast describing
  the real flow (Domain Connect / registrar API, spec §3.8 tier C); it performs no DNS setup.
- **The sign-in demo's origin binding is *not* phishing-resistant** — it displays the origin
  in-page and signs directly (SIWE/NIP-98-style), which the spec explicitly calls the weaker
  mode (§13.7 #1); it does not implement WebAuthn, so it cannot make the anti-phishing claim
  a production DMTAP-Auth client would (§13.3.1). This is stated in the panel itself.
- **The network is simulated** — there are no real peers, no real mixnet, no real gateway. An
  in-memory mock provides contacts, latency, and hop animation. The UI says so.
- **Payload "encryption"** is represented structurally, not performed (the demo has no real
  recipient key exchange / MLS session).
- The recovery phrase uses a small demo word list, not the full SLIP-0039 list.
- Calendar/contacts seed data and the "People" trust view are demo/in-memory; nothing here
  talks to a real CalDAV/CardDAV or directory service.

A production client replaces `mesh-sim.js` with a libp2p connection to the user's node,
compiles the Rust MOTE/MLS/identity core to WASM (the libsignal model), and does the sign-in
ceremony's origin-binding via WebAuthn — the UI layer stays essentially the same.

## Files

```
index.html          shell + rail nav (now incl. Calendar)
css/app.css         instrument-panel styling (dark primary, theme-aware)
js/identity.js      Web Crypto identity (real keygen + signing) + key-name/handle persistence
js/keyname.js       the 8-word key-name (spec §3.9.1) — real SHA-256 derivation, deterministic
js/mote.js          MOTE construction (spec §2), real payload signature; mail/chat/calendar/contact kinds
js/mesh-sim.js      SIMULATED mesh/mixnet + @handle directory + seed data (incl. calendar/contacts)
js/ui.js            DOM helpers + MOTE inspector + network diagram + key-name pills
js/app.js           controller: onboarding + all views (incl. Calendar, sign-in demo)
```
