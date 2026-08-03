# Envoir

**Sovereign mail, chat, files & identity — your key is your identity, not an account.**

Envoir is the open-source reference implementation of **DMTAP** (the Decentralized Message
Transfer & Access Protocol): one keypair identity for mail, chat, calendar, contacts, files, and
groups, designed to move peer-to-peer over a mesh and mixnet so that not even a global observer
sees who talks to whom — see [Security](security.md) and [Roadmap](roadmap.md) for exactly what's
real today (mesh transport is proven on loopback; the mixnet's mix cryptography is a structural
BLAKE3 stand-in, so only the `fast` tier runs end-to-end so far). A human address like
`you@envoir.org` is a *pointer* to your key, not the identity itself — lose the provider, keep the
key. An optional gateway bridges DMTAP to legacy SMTP so it is useful on day one, and fades in
importance as the network grows.

Envoir is to DMTAP what Element is to Matrix: the branded, MIT-licensed apps for an open protocol.
New here? [Why Envoir is different](why-different.md) is the plain-language pitch; this page is
the reference summary.

**Status: pre-alpha / reference implementation.** This is a preview build for demonstrating the
protocol end to end, not a production mail service. See [Security](security.md) for exactly what
has (and hasn't) been verified, and read the honesty notes throughout — this project deliberately
avoids overclaiming.

![Envoir — three-pane mail, with per-message transport-path provenance](img/mail-dark.png)

**No cryptocurrency, no blockchain, anywhere in this project.** Naming is pluggable — a key-name,
a local petname, and the default `name@domain` (DNS + key transparency) are the core ladder — and
the *only* place DMTAP admits anything chain-like at all is an OPTIONAL, off-by-default
`name-chain` resolver (ENS `.eth` / SNS `.sol`) bound by four guardrails: optional, key-is-identity
(a bidirectional binding, never a trust root), free to resolve, and no DMTAP token of its own. See
[naming.md](naming.md) for the full ladder. Anti-abuse for cold contact instead uses anonymous
Privacy-Pass-style rate-limit tokens, proof-of-work, and an optional real-money postage stamp —
never a coin. See [FAQ](faq.md).

## What you get

| Surface | What it gives you | Docs |
|---|---|---|
| Mail | Three-pane inbox, threading, labels, snooze, scheduled/undo send, per-message transport-path provenance | [features/mail.md](features/mail.md) |
| Chat | DMs (deniable X3DH + Double Ratchet) and channels (signed MLS groups) on the same MOTE substrate | [features/chat.md](features/chat.md) |
| Calendar | Month/week/day + agenda, recurring events, peer-to-peer meeting invitations + RSVP | [features/calendar.md](features/calendar.md) |
| Contacts | Per-contact key verification — TOFU-pinned vs. verified via safety number — not just a name and photo | [features/contacts.md](features/contacts.md) |
| Files | Content-addressed, end-to-end encrypted, any size; a shared folder *is* a group | [features/files.md](features/files.md) |
| Groups | An address that represents its members — broadcast lists and channels, one MLS roster | [features/groups.md](features/groups.md) |
| Identity | Safety numbers, avatars/profile, linked devices, recovery phrase, decentralized login (DMTAP-Auth) | [features/identity.md](features/identity.md) |
| Settings & devices | Addresses/aliases, filters, node connection, notifications, and every linked device in one place | [features/settings.md](features/settings.md) |
| Transport provenance | Know which trust boundaries a message crossed, without weakening the mixnet | [features/transport-traceability.md](features/transport-traceability.md) |
| PWA & mobile | Installable app, offline app-shell load, content-free Web Push wake-pings, responsive to ~360px | [pwa-and-push.md](pwa-and-push.md) |
| Self-hosting | Run your own domain, node, and optionally your own gateway — for $0 | [features/self-hosting.md](features/self-hosting.md) |

Calendar and contacts ride the same substrate as additional MOTE kinds (JSCalendar/JSContact over
JMAP, with CalDAV/CardDAV compatibility) — see [protocol.md](protocol.md#messaging-files),
[features/calendar.md](features/calendar.md), and [features/contacts.md](features/contacts.md).

## Map of the docs

This manual is organized the way you'll actually use it — start here, then the day-to-day apps,
then how it all works, then the operator-grade advanced material at the bottom:

- **Start here** — [Why Envoir is different](why-different.md), [Getting started](getting-started.md), [Your identity & safety numbers](features/identity.md).
- **Using Envoir** — [Mail](features/mail.md) · [Compose & send](features/compose.md) · [Chat](features/chat.md) · [Calendar](features/calendar.md) · [Contacts](features/contacts.md) · [Files & sharing](features/files.md) · [Groups](features/groups.md) · [Settings & devices](features/settings.md).
- **Understanding it** — [Naming](naming.md), [Transport & provenance](features/transport-traceability.md), [Privacy & threat model](privacy.md), [Security](security.md).
- **Advanced** — [Architecture](architecture.md), [Protocol / DMTAP internals](protocol.md), [Self-hosting a node](features/self-hosting.md), [Running the gateway](features/running-the-gateway.md), [JMAP/IMAP/CalDAV client setup](features/client-setup.md), [PWA & push](pwa-and-push.md), [Contributing](contributing.md), [Roadmap](roadmap.md), [FAQ](faq.md).

## Repository map

| Path | What it is |
|---|---|
| `node/` | envoir-node — the whole client side: identity, mailbox, mesh, messaging, files, JMAP, the Send API, plus the substrate crates (`kotva-core`/`kotva-mail`) as a pinned git dependency |
| `crates/dmtap-auth` | DMTAP-Auth — decentralized, key-based sign-in |
| `crates/dmtap-deniable` | Deniable 1:1 messaging (X3DH + Double Ratchet) |
| `crates/dmtap-mls` | MLS group messaging (handshake ordering, committer) |
| `crates/dmtap-naming` | The pluggable naming/addressing resolver framework + key transparency |
| `crates/dmtap-namechain-rpc` | Real, network-backed name-chain resolvers (ENS/SNS) behind `dmtap-naming` |
| `crates/dmtap-p2p` | The real libp2p mesh transport (TCP/QUIC+Noise+Yamux, Kademlia, Circuit Relay v2 + DCUtR), proven on loopback — not yet the node binary's default transport |
| `crates/dmtap-clustersync` | Device-cluster sync (§5.6): an owner's own devices converge with no primary and no central server |
| `crates/dmtap-send` | Envoir Send — the reusable library core of a capability-scoped programmatic mail API |
| `crates/dmtap-seam` | The operator seam — the contract a hosted operator implements (no billing logic, no payment provider) |
| `crates/dmtap-operator` | Reference operator machinery implementing `dmtap-seam`: quotas, usage queue, fail-closed gateway-authz, gateway DNS |
| `crates/dmtap-postage-patala` | Optional, isolated reference postage payment-provider adapter — never a dependency of the default build |
| `crates/conformance-runner` | Runs the implementation against the spec's conformance catalog and vectors, both drawn from the sibling KOTVA repo |
| `crates/netsim`, `crates/downgrade-tests` | Mixnet mechanism-model simulation + downgrade/fail-closed regression suite |
| `client/` | Web client — mail, chat, calendar, contacts, files, groups, identity |
| `console/` | Open-source domain-admin console |
| `status/` | Public + personal status page |
| `superadmin/` | Fleet operator console — content-blind by construction |
| `site/` | Marketing/landing page |
| `formal/`, `fuzz/`, `integration/` | ProVerif symbolic models, wire-decoder fuzzing, adversarial cross-component tests |

**Not in this repository:** the legacy-mail gateway — it moved permanently to
[`github.com/vul-os/pier`](https://github.com/vul-os/pier) as its `gateway` coordinator kind —
and `crates/dmtap-core`/`crates/dmtap-mail`, now `kotva-core`/`kotva-mail` in the sibling
**vul-os/kotva** repo, consumed here as a tag-pinned git dependency.

The normative specification lives in the sibling **vul-os/kotva** repo (22 markdown sections plus
a compiled `dmtap.pdf`), not in this repository — see [protocol.md](protocol.md).
