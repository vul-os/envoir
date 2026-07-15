# Envoir

**Sovereign mail, chat & files** — the open-source reference implementation of
**[DMTAP](../dmtap)** (the Decentralized Message Transfer & Access Protocol), for private,
metadata-protected communication and decentralized login over a peer-to-peer mesh, with an
optional bridge to legacy email.

Envoir is to DMTAP what Element is to Matrix, or Fastmail is to JMAP: the branded, open-source
apps that implement an open protocol. Fully open source under the **MIT license**. This is the
OSS monorepo (client + node + gateway + the operator seam). The DMTAP spec lives in the sibling
[`../dmtap`](../dmtap) repo; the private billing/management layer lives in
[`../envoir-cloud`](../envoir-cloud) and plugs in through the documented **operator seam** —
withholding *no* protocol, client, or privacy feature. Everything a user touches and everything
trust depends on is here and open.

> Licensing note: shipped as MIT. Apache-2.0 dual-licensing is under consideration for its
> explicit patent grant (relevant to novel mechanisms like anti-abuse postage/tokens); some
> crate manifests currently declare `Apache-2.0 OR MIT` toward that end.

## The model in one paragraph

Your identity is a **keypair**, not an account or an address. You run a **node** on any box
that stays on most of the time (a Raspberry Pi, NAS, old laptop, or $2 VPS); the node holds
your keys and data and does the work. Nodes form a **mesh** (discovery + relaying + delivery)
and route through a **mixnet** so not even a global observer sees who talks to whom. A human
name like `abc@def.com` is only a *pointer* to your key. An **optional gateway** bridges DMTAP
⇄ legacy SMTP, and fades as the network grows.

## Repository layout (monorepo)

```
envoir/
├── node/            Reference node (Rust): identity, mailbox, mesh, messaging, files, clients
├── gateway/         Reference legacy SMTP gateway (Rust), optional
├── crates/
│   └── dmtap-seam/   The OPERATOR SEAM: metering / provisioning / policy / gateway-authz
│                    traits with self-host defaults, consumed by envoir-cloud over a contract
└── client/          Comprehensive-but-simple web client (no build; mail + chat + files)
```

The normative specification is **not** in this repo — it lives in the sibling **DMTAP spec
repo** (`../dmtap/`, e.g. [`../dmtap/00-overview.md`](../dmtap/00-overview.md); 12 sections).
The private billing/management layer lives in the sibling **`envoir-cloud`** repo (not open
source, not part of this workspace). It implements the `dmtap-seam` contract out-of-process.

## Two components, one seam

You build only two pieces of software plus DNS (which we don't build):

- **Node** — the whole client side; *it is the mesh*.
- **Gateway** — the optional legacy bridge.

Both expose the **operator seam** (`crates/dmtap-seam`): clean hooks for metering, account
provisioning, policy/entitlements, and gateway authorization. In **self-host** mode the seam's
default implementations are unlimited/no-op, so the OSS is fully functional standalone. A
**hosted operator** (e.g. `envoir-cloud`) implements the seam to add billing, quotas, and
multi-tenant management — *without forking or gating the protocol*. This is the GitLab-style
open-software + paid-operations split, done cleanly: the paid thing is *running it*, never a
crippled feature set. Privacy and crypto are always free and open.

## Build

```sh
cargo build            # workspace builds std-only; heavy deps are commented in each Cargo.toml
cargo run -p envoir-node -- --help
```

The web client in `client/` needs no build — serve it with any static server (or the node
serves it in production).

## Status

Pre-alpha. The spec is written and grounded against current standards (see the DMTAP spec
repo, [`../dmtap/11-grounding-and-references.md`](../dmtap/11-grounding-and-references.md)); the
Rust crates and web client are scaffolds/references. Not production-ready.

## License

MIT — see [`LICENSE-MIT`](LICENSE-MIT).
