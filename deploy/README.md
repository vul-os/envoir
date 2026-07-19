# Self-hosting Envoir

This directory is a self-contained deployment scaffold for the Envoir reference implementation
of **[DMTAP](../../dmtap/)** (the Decentralized Message Transfer & Access Protocol) — Dockerfiles,
a `docker-compose.yml`, an env-var reference, and a one-command wrapper script.

**Status: pre-alpha reference implementation, not audited.** Nothing here has had a security
review. Several pieces are honestly-labelled demo/seam behavior rather than hardened,
production-ready self-host infrastructure — read this whole document before exposing any of it
past your own loopback/LAN. See the root [`README.md`](../README.md) `Security & honesty` section
and the spec's own status notes for the wider project context.

Every command and environment variable below was checked against the real source
(`node/src/main.rs`, `gateway/src/main.rs`) and, where practical, against a real `docker build` +
`docker run`/`docker compose up` in this environment — not invented. Where something doesn't
exist yet, it's called out explicitly rather than glossed over.

## What's actually in this repo (the two binaries)

The Cargo workspace (`../Cargo.toml`) builds two binaries relevant to self-hosting:

| Binary | Crate/path | What it is |
|---|---|---|
| `envoir-node` | `../node` (`node/src/main.rs`) | The reference DMTAP client: identity, MOTE store, mesh participation, and the §8 mail-client-protocol projection. **It is the whole client side** — there is no separate server binary for "your mailbox." |
| `envoir-gateway` | `../gateway` (`gateway/src/main.rs`) | The **optional** legacy bridge between DMTAP and SMTP (spec §7) — stateless, and the only component that speaks plaintext SMTP. |

Both are plain `std`-only, synchronous Rust binaries — no async runtime, no external database.

## Prerequisites

- **Docker** (verified with Docker 28.x / the Compose v2 plugin, `docker compose ...`) — the
  supported path in this scaffold. `deploy/selfhost.sh` also falls back to the standalone
  `docker-compose` (v1) if the plugin isn't installed.
- Or, to build without Docker: a **Rust toolchain**. The crates declare `rust-version = "1.75"`,
  but the committed workspace `Cargo.lock` (repo root — it IS tracked in git, not `.gitignore`d)
  pins a `zeroize_derive` release that requires the `edition2024` Cargo feature, which only
  stabilized in **Rust 1.85** — a plain 1.75 toolchain will fail with `feature edition2024 is
  required`. The Dockerfiles here are pinned to `rust:1.90-slim-bookworm` and build `--locked`
  against that committed lockfile, verified to build clean; `rust:1.82-slim-bookworm` was tried
  first and failed with exactly that error. Use a 1.85+ toolchain (or newer) to build outside
  Docker too.

## Quickstart (Docker)

```sh
# from the repo root, or run the script directly — it resolves paths relative to itself
./deploy/selfhost.sh up
```

This copies `deploy/.env.example` to `deploy/.env` on first run (edit it — at minimum set
`GATEWAY_DOMAIN` to your real domain if you intend to receive real legacy mail), then builds and
starts both containers. `./deploy/selfhost.sh logs` / `ps` / `down` manage the stack afterward.

Equivalent, by hand:

```sh
cp deploy/.env.example deploy/.env    # edit it
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build -d
```

The build context is the **repo root** (`context: ..` in `docker-compose.yml`), not `deploy/`
itself — both binaries live in one Cargo workspace and their Dockerfiles need the sibling
workspace members (`node`, `gateway`, `crates/*`, `integration`) to resolve the manifest at all.

## Building without Docker

```sh
# from the repo root
cargo build --release -p envoir-node -p envoir-gateway
./target/release/envoir-node version
./target/release/envoir-gateway version
```

(`cargo build --workspace` also works and additionally builds the test-only `integration` crate
and the crates not on the node/gateway dependency path — see the root README's own Quickstart.)

## What each binary actually does when you run it

### `envoir-node` (see `node/src/main.rs` for the exact source)

| Subcommand | Behavior |
|---|---|
| `version` | Prints the version and default cipher suite. Exits immediately. |
| `init` | Generates a **real** Ed25519 identity key + X25519 HPKE sealing keypair and **persists them to disk** in a keystore at `$ENVOIR_DATA_DIR/keystore.json` (encrypted-at-rest with Argon2id + ChaCha20-Poly1305 if `ENVOIR_PASSPHRASE` is set, else a clearly-marked plaintext-for-dev keystore), then prints the address material + the `_dmtap` DNS TXT record to publish. Refuses to overwrite an existing keystore unless `ENVOIR_FORCE_INIT=1`. |
| `run` (alias `serve`) | The **real long-running daemon** (`node/src/daemon.rs::serve`): loads the keystore + the durable outbound journal (`$ENVOIR_DATA_DIR/journal.json`), binds the mesh transport on `ENVOIR_NODE_BIND` (default `0.0.0.0:4600`), and serves until SIGINT/SIGTERM. Requires an existing keystore — run `init` first. Optionally also serves JMAP, the Envoir Send HTTP API, DMTAP-PUB, and/or Sync, each gated behind its own opt-in env var (see below). |
| `demo` | Runs an **in-process, two-node demo** over an in-memory transport (Alice seals a real encrypted MOTE, sends it, Bob validates/decrypts/acks it) to prove the delivery engine end-to-end. Prints the transcript and exits — not a server. This is the former behavior of `run` before it became the real daemon. |
| `record` | Reloads the existing keystore and reprints just its `_dmtap` DNS TXT record — a convenience for re-publishing without regenerating identity. |
| `gateway` | Just prints a pointer to the dedicated `envoir-gateway` binary; does nothing else. |

`envoir-node` reads a real set of `ENVOIR_*` environment variables (`node/src/config.rs`, ~25 in
total, every one with a sane default) — data dir, mesh bind, passphrase, claimed names, KT
anchors, and the opt-in JMAP/Send-API/DMTAP-PUB/Sync surfaces. See `deploy/.env.example` for the
full list with defaults, or `node/src/config.rs`'s own doc comment for the authoritative one.

### `envoir-gateway` (see `gateway/src/main.rs`)

`run` is a genuine long-running daemon: it binds a real inbound MX (SMTP) TCP listener
(`envoir_gateway::MxListener`, with optional STARTTLS if you supply a cert/key) and serves
connections forever, and it configures a real outbound leg (SMTP-over-STARTTLS transport, real MX
resolution, real MTA-STS policy discovery). **Honest limitation:** the recipient directory and the
mesh-delivery adapter are unconfigured *operator seams* in this reference build (`EmptyDirectory`
/ `UnreachableMesh` in `gateway/src/main.rs`) — every inbound `RCPT` is refused with SMTP `550`,
and nothing is ever durably acknowledged (`451`), until a real directory + mesh are wired in. What
you get out of the box is the real, working inbound-MX and outbound-MX/MTA-STS/DKIM socket
plumbing, not an end-to-end legacy⟷DMTAP bridge.

`envoir-gateway` reads about 30 environment variables in total (`gateway/src/main.rs`,
`gateway/src/personal.rs`); `deploy/.env.example` and `deploy/docker-compose.yml` wire up the 5
this self-host stack actually uses today: `GATEWAY_DOMAIN`, `GATEWAY_LISTEN`,
`GATEWAY_GW_SELECTOR`, `GATEWAY_TLS_CERT`, `GATEWAY_TLS_KEY`, `GATEWAY_DNS_SERVER`. The rest
(`GATEWAY_DIRECTORY`, `GATEWAY_MESH_ENDPOINT`, `GATEWAY_AUTHZ_MODE`, the IMAP/POP3/submission
listener flags, quota/enforcement toggles, etc.) configure gateway features this scaffold doesn't
enable by default — see `gateway/src/main.rs`'s own `help` text for the full list.

## Ports

| Port | Service | Protocol | Notes |
|---|---|---|---|
| 2525 | `envoir-gateway` | SMTP (MX, inbound) | Not 25, so the container needs no root/`cap_net_bind_service`. Forward your real port 25 to this at your firewall/router if receiving real internet mail. |
| 4600 | `envoir-node run`/`serve` | DMTAP mesh transport | `ENVOIR_NODE_BIND`, published by default (see `docker-compose.yml`). |

Legacy IMAP/POP3/SMTP-submission are **not** served by the node image at all — they live only on
the gateway (`node/Cargo.toml`'s own comment: the node intentionally does not enable
`dmtap-mail`'s `net` feature). The node's other surfaces — JMAP (`ENVOIR_JMAP`), the Envoir Send
HTTP API (`ENVOIR_SEND_API`), DMTAP-PUB (`ENVOIR_PUB_SERVE`), and Sync (`ENVOIR_SYNC_SERVE`) — are
all opt-in and off by default, so none of their ports are published in `docker-compose.yml`; add a
`ports:` entry yourself if you enable one and need it reachable from outside the container. JMAP
and Sync default to loopback binds, so reaching them off-container also needs an explicit
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

## TLS for the gateway (STARTTLS)

Leave `GATEWAY_TLS_CERT` / `GATEWAY_TLS_KEY` **unset** (not set-to-empty — see the note in
`docker-compose.yml`/`.env.example`, this specific footgun is verified: a set-but-empty value
crash-loops the container) to run a plaintext dev listener. To enable STARTTLS, put your PEM cert
chain and private key in `deploy/certs/` (bind-mounted read-only into the container at `/certs`)
and set both variables in `deploy/.env` to the in-container paths, e.g.
`GATEWAY_TLS_CERT=/certs/fullchain.pem`, `GATEWAY_TLS_KEY=/certs/privkey.pem`. TLS itself is real
(`rustls`, ring provider, embedded `webpki-roots` trust store for the outbound leg — no system CA
bundle or OpenSSL dependency at runtime).

## DNS: publishing your `_dmtap` record (spec §3.2)

The DMTAP naming spec (`../../dmtap/03-naming.md` §3.2) defines the discovery record a resolver
looks up for `abc@def.com`:

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
wired up either — see spec §3.5 for what a real KT log needs to provide. If you run the gateway, also
publish a normal `MX` record for your domain pointing at wherever you forward port 25 to this
gateway's port 2525 (see the Ports table above), plus the SPF/DKIM-selector/DMARC records
`gateway/src/dkim.rs` and the spec's §7.3 assume (a delegated DKIM selector, not your DMTAP key).

## Known limitations / seams (summary)

| Area | Status |
|---|---|
| Node identity persistence | Real — `init` writes a keystore to `$ENVOIR_DATA_DIR/keystore.json` |
| Node outbound-queue durability | Real — `run`/`serve` loads/checkpoints a `FileJournal` at `$ENVOIR_DATA_DIR/journal.json` |
| Node long-running daemon | Real — `run` (alias `serve`) is a service, until SIGINT/SIGTERM |
| Node bind address | Configurable via `ENVOIR_NODE_BIND`, defaults to `0.0.0.0:4600` (Docker-reachable by default) |
| Node client protocols | JMAP is native on the node (`ENVOIR_JMAP`, opt-in, app-password auth); legacy IMAP/POP3/SMTP-submission live only on the gateway |
| Node mesh transport | The real libp2p mesh (`crates/dmtap-p2p`) is proven at the crate level but not yet the node daemon's default transport — see `docs/roadmap.md` |
| Gateway recipient directory | Unconfigured seam (`EmptyDirectory`) — all inbound `RCPT` refused (`550`) |
| Gateway mesh delivery | Unconfigured seam (`UnreachableMesh`) — no durable ack (`451`) |
| Gateway core (inbound MX, outbound MX/MTA-STS/DKIM, STARTTLS) | Real, verified working |
| `_dmtap` DNS record | Generated correctly by `init`/`record`; publishing to your zone is still a manual/operator step, no KT log wired up |
| Build reproducibility | Committed `Cargo.lock`, builder image pinned, both Dockerfiles build `--locked` |
| Security review | None yet — pre-alpha |

## Reference

- Root project README: [`../README.md`](../README.md)
- Node crate docs: [`../node/README.md`](../node/README.md)
- Gateway crate docs: [`../gateway/README.md`](../gateway/README.md)
- Normative spec (sibling repo): [`../../dmtap/`](../../dmtap/) — naming/DNS is §3
  (`03-naming.md`), the gateway is §7 (`07-gateway.md`)
