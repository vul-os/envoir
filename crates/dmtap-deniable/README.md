# dmtap-deniable

DMTAP optional deniable 1:1 mode (spec §5.2.1) — X3DH handshake over a dedicated IK-certified X25519 idk, a Double Ratchet, and shared-key-MAC (AEAD-tag) authentication for cryptographic repudiation

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

DMTAP optional **deniable 1:1 mode** — spec §5.2.1.

## Dependencies

* `dmtap-core`
* `x25519-dalek`
* `hkdf`
* `sha2`
* `chacha20poly1305`
* `rand_core`
* `thiserror`

## Running its tests

```sh
cargo test -p dmtap-deniable
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
