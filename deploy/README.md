<!-- no-broker-dep:allow-file: deploy docs explain the gateway moved permanently to the separate,
     external Ephor broker repo, with build instructions for that OTHER repo
     -- describes an external, optional component, not a dependency of this one. -->

# Self-hosting Envoir

This directory is a self-contained deployment scaffold for the **node** half of the Envoir
reference implementation of **[DMTAP](https://github.com/vul-os/kotva)** (the Decentralized
Message Transfer & Access Protocol, KOTVA's mail profile) — a Dockerfile, a `docker-compose.yml`,
an env-var reference, and a one-command wrapper script.

**The legacy SMTP/IMAP/POP3 gateway is not part of this workspace or this scaffold.** It moved
permanently to the separate, external **[Ephor broker repo](https://github.com/vul-os/ephor)**
(its `gateway` coordinator kind), with zero crate dependency on `envoir` in either direction. If
you correspond with the legacy email world, build `ephor-gateway` from that repo, run it as its
own process (a container of your own, a bare-metal service, whatever you prefer), and point this
node's dispatch shim at the resulting binary with `ENVOIR_GATEWAY_BIN` — see "The gateway
(external, optional)" below. A node with no legacy correspondents never needs to touch any of
this.

**Status: pre-alpha reference implementation, not audited.** Nothing here has had a security
review. Several pieces are honestly-labelled demo/seam behavior rather than hardened,
production-ready self-host infrastructure — read this whole document before exposing any of it
past your own loopback/LAN. See the root [`README.md`](../README.md) `Security & honesty` section
for the wider project context.

Every command and environment variable below was checked against the real source
(`node/src/main.rs`) and, where practical, against a real `docker build` + `docker run`/`docker
compose up` in this environment — not invented. Where something doesn't exist yet, it's called
out explicitly rather than glossed over.

## What's actually in this repo (one binary)

The Cargo workspace (`../Cargo.toml`) builds one binary relevant to self-hosting:

| Binary | Crate/path | What it is |
|---|---|---|
| `envoir-node` | `../node` (`node/src/main.rs`) | The reference DMTAP client: identity, MOTE store, mesh participation, and the §8 mail-client-protocol projection. **It is the whole client side** — there is no separate server binary for "your mailbox" in this repository. |

Plain `std`-heavy, synchronous-first Rust — no external database. The substrate
(`kotva-core`/`kotva-mail`) is fetched as a tag-pinned git dependency, not built from a sibling
path.

## Prerequisites

- **Docker** (verified with Docker 28.x / the Compose v2 plugin, `docker compose ...`) — the
  supported path in this scaffold. `deploy/selfhost.sh` also falls back to the standalone
  `docker-compose` (v1) if the plugin isn't installed.
- Or, to build without Docker: a **Rust toolchain**. The crates declare `rust-version = "1.75"`,
  but the committed workspace `Cargo.lock` (repo root — it IS tracked in git, not `.gitignore`d)
  pins a `zeroize_derive` release that requires the `edition2024` Cargo feature, which only
  stabilized in **Rust 1.85** — a plain 1.75 toolchain will fail with `feature edition2024 is
  required`. The Dockerfile here is pinned to `rust:1.90-slim-bookworm` and builds `--locked`
  against that committed lockfile, verified to build clean. Use a 1.85+ toolchain (or newer) to
  build outside Docker too.

## Quickstart (Docker)

```sh
# from the repo root, or run the script directly — it resolves paths relative to itself
./deploy/selfhost.sh up
```

This copies `deploy/.env.example` to `deploy/.env` on first run (edit it if you want to override
any `ENVOIR_*` default), then builds and starts the node container. `./deploy/selfhost.sh logs` /
`ps` / `down` manage it afterward.

Equivalent, by hand:

```sh
cp deploy/.env.example deploy/.env    # edit it
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build -d
```

The build context is the **repo root** (`context: ..` in `docker-compose.yml`), not `deploy/`
itself — the binary lives in the Cargo workspace and its Dockerfile needs the sibling workspace
members (`crates/*`, `integration`) to resolve the manifest at all.

## Building without Docker

```sh
# from the repo root
cargo build --release -p envoir-node
./target/release/envoir-node version
```

(`cargo build --workspace` also works and additionally builds the test-only `integration` crate
and every other crate under `crates/*` — see the root README's own Quickstart.)

## What the binary actually does when you run it

### `envoir-node` (see `node/src/main.rs` for the exact source)

| Subcommand | Behavior |
|---|---|
| `version` | Prints the version and default cipher suite. Exits immediately. |
| `init` | Generates a **real** Ed25519 identity key + X25519 HPKE sealing keypair and **persists them to disk** in a keystore at `$ENVOIR_DATA_DIR/keystore.json` (encrypted-at-rest with Argon2id + ChaCha20-Poly1305 if `ENVOIR_PASSPHRASE` is set, else a clearly-marked plaintext-for-dev keystore), then prints the address material + the `_dmtap` DNS TXT record to publish. Refuses to overwrite an existing keystore unless `ENVOIR_FORCE_INIT=1`. |
| `run` (alias `serve`) | The **real long-running daemon** (`node/src/daemon.rs::serve`): loads the keystore + the durable outbound journal (`$ENVOIR_DATA_DIR/journal.json`), binds the mesh transport on `ENVOIR_NODE_BIND` (default `0.0.0.0:4600`), and serves until SIGINT/SIGTERM. Requires an existing keystore — run `init` first. Optionally also serves JMAP, the Envoir Send HTTP API, DMTAP-PUB, and/or Sync, each gated behind its own opt-in env var (see below). |
| `demo` | Runs an **in-process, two-node demo** over an in-memory transport (Alice seals a real encrypted MOTE, sends it, Bob validates/decrypts/acks it) to prove the delivery engine end-to-end. Prints the transcript and exits — not a server. This is the former behavior of `run` before it became the real daemon. |
| `record` | Reloads the existing keystore and reprints just its `_dmtap` DNS TXT record — a convenience for re-publishing without regenerating identity. |
| `gateway <args>` / `--gateway <args>` | Hands off to an externally-built gateway binary named by `ENVOIR_GATEWAY_BIN`, as a genuinely separate OS process (`exec` on Unix) — fails closed with a clear error if no such binary is reachable. See "The gateway (external, optional)" below. |

`envoir-node` reads a real set of `ENVOIR_*` environment variables (`node/src/config.rs`, ~25 in
total, every one with a sane default) — data dir, mesh bind, passphrase, claimed names, KT
anchors, and the opt-in JMAP/Send-API/DMTAP-PUB/Sync surfaces. See `deploy/.env.example` for the
full list with defaults, or `node/src/config.rs`'s own doc comment for the authoritative one.

## The gateway (external, optional)

Legacy IMAP/POP3/SMTP-submission clients aren't served by the node, and this scaffold builds no
gateway image. If you want to bridge to the legacy email world:

1. Clone and build the gateway from the separate **[Ephor repo](https://github.com/vul-os/ephor)**
   (`cargo build -p gateway` there, binary name `ephor-gateway`) — its own README documents its
   `GATEWAY_*` environment variables (inbound MX listener, DKIM/attestation selector, STARTTLS,
   DNS-based MX/MTA-STS resolution), none of which live in this repository anymore.
2. Run it as its own process — its own container, a bare-metal service, a separate VM — reachable
   from wherever you run `envoir-node`.
3. Set `ENVOIR_GATEWAY_BIN=/path/to/ephor-gateway` and invoke `envoir-node gateway run` (or
   `envoir-node --gateway run`) to have the node's dispatch shim exec it.

A node with no legacy correspondents never needs any of this. See the root
[`README.md`](../README.md#node-binary-and-the-gateway-optional-external) and
[`node/tests/gateway_dispatch.rs`](../node/tests/gateway_dispatch.rs) for exactly what the
dispatch shim does and does not guarantee.

## Ports

| Port | Service | Protocol | Notes |
|---|---|---|---|
| 4600 | `envoir-node run`/`serve` | DMTAP mesh transport | `ENVOIR_NODE_BIND`, published by default (see `docker-compose.yml`). |

The node's other surfaces — JMAP (`ENVOIR_JMAP`), the Envoir Send HTTP API (`ENVOIR_SEND_API`),
DMTAP-PUB (`ENVOIR_PUB_SERVE`), and Sync (`ENVOIR_SYNC_SERVE`) — are all opt-in and off by
default, so none of their ports are published in `docker-compose.yml`; add a `ports:` entry
yourself if you enable one and need it reachable from outside the container. JMAP and Sync
default to loopback binds, so reaching them off-container also needs an explicit
`ENVOIR_JMAP_BIND=0.0.0.0:...` / `ENVOIR_SYNC_BIND=0.0.0.0:...` override plus your own TLS front
for JMAP (the daemon refuses an off-localhost JMAP bind without one, fail-closed).

## Keys, journal, and what's actually persisted

- **`envoir-node init` persists a real keystore** at `$ENVOIR_DATA_DIR/keystore.json` (default
  `./envoir-data`, or `/data` in this compose stack — the `node-data` volume). Encrypted-at-rest
  with Argon2id + ChaCha20-Poly1305 if `ENVOIR_PASSPHRASE` is set; otherwise a clearly-marked
  plaintext-for-dev keystore. `init` also prints the address material to stdout for your records,
  but the durable copy is the keystore file, not the terminal output.
- **The outbound retry-queue journal is wired and durable.** `node/src/journal.rs`'s real
  `FileJournal` (atomic write via temp-file + rename) is constructed by `run`/`serve`
  (`node/src/daemon.rs::load_node`) at `$ENVOIR_DATA_DIR/journal.json` — the outbound queue, dedup
  set, suite high-water-marks, and mix-directory state all survive a restart (spec §19.3.3).
- **`docker-compose.yml`'s `node-data` volume at `/data`** holds both `keystore.json` and
  `journal.json` for the daemon — real, in-use state, not a placeholder.
- **JMAP, when enabled (`ENVOIR_JMAP=1`), reads from the node's live MOTE store** — a client sees
  actual delivered mail, not a demo in-memory projection. It needs at least one app-password set
  via `ENVOIR_JMAP_APP_PASSWORDS`, else no client can authenticate (fail-closed by design).

In short: `init` once, then `run`/`serve` is a real persistent daemon across restarts — both the
identity and the outbound queue survive as long as the `node-data` volume does.

## DNS: publishing your `_dmtap` record (spec §3.2)

The DMTAP naming spec (`03-naming.md` §3.2 in the sibling [vul-os/kotva](https://github.com/vul-os/kotva)
repo) defines the discovery record a resolver looks up for `abc@def.com`:

```
abc._dmtap.def.com.  IN  TXT  "v=dmtap1; suite=1; ik=<base64url IK>; id=<hash of Identity §1.3>;
                               kt=<KT log URL>; keypkgs=<KeyPackage bundle locator §5.3>"
_dmtap.def.com.      IN  SVCB 1 . ( ... )     ; optional service params, KT anchors
def.com.             IN  MX   ...             ; only if a legacy gateway serves the domain (§7)
```

**Honest seam:** nothing in this workspace *publishes* this record for you today. The
`dmtap-naming` crate (`../crates/dmtap-naming`) is a library implementing KT-verified
*resolution* — parsing/verifying these records once they exist — with no publish-side tooling and
no CLI binary of its own. `envoir-node init` (and `record`) does print the record already
formatted as the spec's TXT line (base64url `ik=`, per §3.9.1/§3.2), so you just copy it into your
zone through your own DNS provider/registrar; there is no key-transparency (KT) log integration
wired up either — see spec §3.5 for what a real KT log needs to provide. If you run a gateway
(built from the separate Ephor repo), also publish a normal `MX` record for your domain pointing
at wherever you forward inbound port 25 to that gateway, plus the SPF/DKIM-selector/DMARC records
the spec's §7.3 assumes (a delegated DKIM selector, not your DMTAP key) — the gateway's own README
documents its exact configuration.

## Known limitations / seams (summary)

| Area | Status |
|---|---|
| Node identity persistence | Real — `init` writes a keystore to `$ENVOIR_DATA_DIR/keystore.json` |
| Node outbound-queue durability | Real — `run`/`serve` loads/checkpoints a `FileJournal` at `$ENVOIR_DATA_DIR/journal.json` |
| Node long-running daemon | Real — `run` (alias `serve`) is a service, until SIGINT/SIGTERM |
| Node bind address | Configurable via `ENVOIR_NODE_BIND`, defaults to `0.0.0.0:4600` (Docker-reachable by default) |
| Node client protocols | JMAP is native on the node (`ENVOIR_JMAP`, opt-in, app-password auth); legacy IMAP/POP3/SMTP-submission live only on an externally-built gateway (see above), never in this image |
| Node mesh transport | The real libp2p mesh (`crates/dmtap-p2p`) is proven at the crate level but not yet the node daemon's default transport — see [`docs/roadmap.md`](../docs/roadmap.md) |
| Mixnet | `node/src/onion.rs`'s Sphinx onion-wrap is a structural, keyed-BLAKE3 stand-in for the real mix cryptography — no live mix network runs; only the `fast` (direct) tier is real end-to-end today. See [`docs/roadmap.md`](../docs/roadmap.md). |
| Gateway | Not part of this repo or this scaffold — build and run it from the separate [Ephor repo](https://github.com/vul-os/ephor) |
| `_dmtap` DNS record | Generated correctly by `init`/`record`; publishing to your zone is still a manual/operator step, no KT log wired up |
| Build reproducibility | Committed `Cargo.lock`, builder image pinned, the Dockerfile builds `--locked` |
| Security review | None yet — pre-alpha |

## Reference

- Root project README: [`../README.md`](../README.md)
- Node crate docs: [`../node/README.md`](../node/README.md)
- Gateway (separate repo): [github.com/vul-os/ephor](https://github.com/vul-os/ephor)
- Normative spec (sibling repo): [github.com/vul-os/kotva](https://github.com/vul-os/kotva) —
  naming/DNS is §3 (`03-naming.md`), the gateway is §7 (`07-gateway.md`)
