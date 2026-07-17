# Self-hosting Envoir

This directory is a self-contained deployment scaffold for the Envoir reference implementation
of **[DMTAP](../../dmtap/)** (the Decentralized Message Transfer & Access Protocol) — a Dockerfile,
a `docker-compose.yml`, an env-var reference, and a one-command wrapper script.

**Status: pre-alpha reference implementation, not audited.** Nothing here has had a security
review. Several pieces are honestly-labelled demo/seam behavior rather than hardened,
production-ready self-host infrastructure — read this whole document before exposing any of it
past your own loopback/LAN. See the root [`README.md`](../README.md) `Security & honesty` section
and the spec's own status notes for the wider project context.

Every command and environment variable below was checked against the real source
(`node/src/main.rs`) and, where practical, against a real `docker build` +
`docker run`/`docker compose up` in this environment — not invented. Where something doesn't
exist yet, it's called out explicitly rather than glossed over.

> **The legacy SMTP gateway lives in its own repo now.** `envoir-gateway` (the optional
> DMTAP⟷SMTP bridge, spec §7) was split out to **env-oir/envoir-gateway**, which ships its own
> Dockerfile, compose service, and self-host docs. This scaffold now deploys the node only.

## What's actually in this repo (the node binary)

The Cargo workspace (`../Cargo.toml`) builds one binary relevant to self-hosting here:

| Binary | Crate/path | What it is |
|---|---|---|
| `envoir-node` | `../node` (`node/src/main.rs`) | The reference DMTAP client: identity, MOTE store, mesh participation, and the §8 mail-client-protocol projection. **It is the whole client side** — there is no separate server binary for "your mailbox." |

It is a plain `std`-only, synchronous Rust binary — no async runtime, no external database.

## Prerequisites

- **Docker** (verified with Docker 28.x / the Compose v2 plugin, `docker compose ...`) — the
  supported path in this scaffold. `deploy/selfhost.sh` also falls back to the standalone
  `docker-compose` (v1) if the plugin isn't installed.
- Or, to build without Docker: a **Rust toolchain**. The crates declare `rust-version = "1.75"`,
  but **no `Cargo.lock` is committed** upstream (it's `.gitignore`d), so `cargo build` resolves
  the newest semver-compatible dependency versions at build time. As of this writing that pulls
  in a `zeroize_derive` release that requires the `edition2024` Cargo feature, which only
  stabilized in **Rust 1.85** — a plain 1.75 toolchain will fail with `feature edition2024 is
  required`. The Dockerfile here is pinned to `rust:1.90-slim-bookworm`, verified to build
  clean; `rust:1.82-slim-bookworm` was tried first and failed with exactly that error. If you
  need a fully reproducible / older-toolchain build, generate and commit your own `Cargo.lock`
  first.

## Quickstart (Docker)

```sh
# from the repo root, or run the script directly — it resolves paths relative to itself
./deploy/selfhost.sh up
```

This copies `deploy/.env.example` to `deploy/.env` on first run, then builds and starts the node
container. `./deploy/selfhost.sh logs` / `ps` / `down` manage the stack afterward. (The node reads
no environment variables at all today, so there is nothing you must edit in `.env` for it — see
below.)

Equivalent, by hand:

```sh
cp deploy/.env.example deploy/.env
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build -d
```

The build context is the **repo root** (`context: ..` in `docker-compose.yml`), not `deploy/`
itself — the binary lives in a Cargo workspace and its Dockerfile needs the sibling workspace
members (`node`, `crates/*`, `integration`) to resolve the manifest at all.

## Building without Docker

```sh
# from the repo root
cargo build --release -p envoir-node
./target/release/envoir-node version
```

(`cargo build --workspace` also works and additionally builds the test-only `integration` crate
and the crates not on the node dependency path — see the root README's own Quickstart.)

## What the node binary actually does when you run it

### `envoir-node` (see `node/src/main.rs` for the exact source)

| Subcommand | Behavior |
|---|---|
| `version` | Prints the version and default cipher suite. Exits immediately. |
| `init` | Generates a **real** Ed25519 identity key + X25519 HPKE sealing keypair in memory and **prints them to stdout** (hex + the spec §3.9.1 8-word key-name). It does **not** write anything to disk — see "Keys, journal, and what's actually persisted" below. |
| `run` | Runs an **in-process, two-node demo** over an in-memory transport (Alice seals a real encrypted MOTE, sends it, Bob validates/decrypts/acks it) to prove the delivery engine end-to-end. It is **not a long-running daemon** — it prints the demo transcript and the process exits. The real libp2p mesh/mixnet transport is not wired into this binary. |
| `serve-mail` | Runs the §8 client-protocol servers (IMAP, POP3, SMTP-submission) against a fresh **in-memory** MOTE-store projection with **one hardcoded demo login** (`owner@dmtap.local` / `app-password`). This one blocks forever (it's the only subcommand that behaves like a server) — see the container/port caveats below. |
| `gateway` | Just prints a pointer to the dedicated `envoir-gateway` binary (now in the env-oir/envoir-gateway repo); does nothing else. |

`envoir-node` reads **no environment variables and no config file** — its entire configuration
surface is the single subcommand argument.

## Ports

| Port | Service | Protocol | Notes |
|---|---|---|---|
| 1143 | `envoir-node serve-mail` | IMAP | Demo/dev only — see below. |
| 1110 | `envoir-node serve-mail` | POP3 | Demo/dev only — see below. |
| 1587 | `envoir-node serve-mail` | SMTP submission | Demo/dev only — see below. |

### Testing the node demo servers

`serve-mail` hard-codes its listeners to bind `127.0.0.1` **inside the process** — this is not
configurable via any flag or environment variable today (`node/src/main.rs` has no bind-address
knob at all). We verified with a real `docker build`/`docker run` of the image in this directory
that a container's `ports:`/`-p` publish does **not** reliably make this reachable: the TCP
handshake completes (something accepts the connection), but the process itself never sees it —
connecting from the host and reading returns an immediate EOF instead of the real IMAP greeting.
Only a connection that shares the container's own network namespace gets the real banner. Two ways
to actually exercise it:

```sh
# 1. From another container sharing the same network namespace (always works):
docker run --rm --network container:$(docker compose -f deploy/docker-compose.yml ps -q node) \
  python:3-slim python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 1143), timeout=3)
print(s.recv(200))
"

# 2. docker compose exec into the node container itself and drive it from there.
```

`docker-compose.yml` has a commented-out `network_mode: "host"` alternative for Linux hosts (it
makes the container's `127.0.0.1` the same as the Docker *host's* own loopback, so `serve-mail`
becomes reachable at `localhost` on the host — not from other machines, and not reliably
equivalent on Docker Desktop for Mac/Windows). It is commented out by default because Compose
rejects `network_mode: host` combined with a `ports:` mapping on the same service.

## Keys, journal, and what's actually persisted

Be aware of a real gap before treating any of this as durable:

- **`envoir-node init` does not persist anything.** It generates identity key material in memory
  and prints it to stdout. There is no keystore file, no `--out`/`--keystore-path` flag, nothing
  written to disk by this binary. If you want to keep an identity, you must capture and store the
  printed output yourself (and treat that terminal output as sensitive key material).
- **The outbound retry-queue journal is a library-only feature, not wired to any CLI.**
  `node/src/journal.rs` implements a real `FileJournal` (atomic write via temp-file + rename,
  restores the outbound queue / dedup set / suite high-water-marks / mix-directory state across a
  restart — this is the actual spec §19.3.3 durability requirement) — but no subcommand in
  `node/src/main.rs` constructs one or takes a path for it. `run`'s demo and `serve-mail`'s
  in-memory store both use no journal / an in-memory store, so state does not survive a restart
  today.
- **`docker-compose.yml` still mounts a `node-data` volume at `/data`** for the node service. It
  is currently unused by the binary — it exists so you have somewhere durable to put whatever you
  capture by hand (e.g. redirect `init`'s stdout there) until a CLI flag exposes `FileJournal`/a
  real keystore. Don't mistake the volume's existence for the binary actually persisting to it.
- **`serve-mail`'s mailbox store (`MemoryStore`) is in-memory** and is wiped on every container
  restart, along with its one hardcoded demo login.

In short: today the node side of self-hosting Envoir is a working reference/demo of the protocol
engine, not yet a persistent personal mailbox you can rely on across restarts.

## DNS: publishing your `_dmtap` record (spec §3.2)

The DMTAP naming spec (`../../dmtap/03-naming.md` §3.2) defines the discovery record a resolver
looks up for `abc@def.com`:

```
abc._dmtap.def.com.  IN  TXT  "v=dmtap1; suite=1; ik=<base64url IK>; id=<hash of Identity §1.3>;
                               kt=<KT log URL>; keypkgs=<KeyPackage bundle locator §5.3>"
_dmtap.def.com.      IN  SVCB 1 . ( ... )     ; optional service params, KT anchors
def.com.             IN  MX   ...             ; only if a legacy gateway serves the domain (§7)
```

**Honest seam:** nothing in this workspace generates or publishes this record for you today. The
`dmtap-naming` crate (`../crates/dmtap-naming`) is a library implementing KT-verified
*resolution* — parsing/verifying these records once they exist — with no publish-side tooling and
no CLI binary of its own. `envoir-node init` prints identity key material as **hex**, not the
**base64url** the spec's TXT format calls for (`ik=<base64url IK>`), so today you'd construct this
record by hand from `init`'s output (converting encodings yourself) and add it to your zone
through your own DNS provider/registrar; there is no key-transparency (KT) log integration wired
up either — see spec §3.5 for what a real KT log needs to provide. If you also run the legacy
gateway (env-oir/envoir-gateway repo), see that repo's docs for the `MX` / SPF / delegated-DKIM-
selector / DMARC records its §7.3 legacy-mail path assumes.

## Known limitations / seams (summary)

| Area | Status |
|---|---|
| Node identity persistence | Not implemented in the CLI (`init` prints to stdout only) |
| Node outbound-queue durability | Library-level (`FileJournal`) exists, not wired to any subcommand |
| Node long-running daemon | `run` is a one-shot in-memory demo, not a service; `serve-mail` is the only blocking subcommand, and it's a demo mail server |
| Node bind address | Hard-coded to `127.0.0.1`, not configurable, not reliably reachable via Docker port publishing |
| Node auth | One hardcoded demo credential in `serve-mail`; no real user/multi-account model |
| `_dmtap` DNS record | Spec-defined, not automated; no publish tooling, no KT log wired up |
| Build reproducibility | No `Cargo.lock` committed; builder image pinned instead (see Prerequisites) |
| Security review | None yet — pre-alpha |
| Legacy SMTP gateway | Split out to the env-oir/envoir-gateway repo — not built or deployed from this scaffold |

## Reference

- Root project README: [`../README.md`](../README.md)
- Node crate docs: [`../node/README.md`](../node/README.md)
- Legacy SMTP gateway: the **env-oir/envoir-gateway** repo (its own README + deploy docs)
- Normative spec (sibling repo): [`../../dmtap/`](../../dmtap/) — naming/DNS is §3
  (`03-naming.md`), the gateway is §7 (`07-gateway.md`)
