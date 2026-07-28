# dmtap-namechain-rpc

Real network-backed DMTAP name-chain resolvers (spec §3.12.5): ENS (.eth) over Ethereum JSON-RPC (EIP-137 namehash, eth_call, structural CCIP-Read/ENSIP-10) and SNS (.sol) over Solana JSON-RPC (self-derived Bonfida name-registry PDA). Implements dmtap-naming's NameChainClient trait; network sits behind an injectable HttpTransport so the pure logic is unit-tested offline

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

Real, **network-backed** DMTAP name-chain resolvers — spec §3.12.5.

## Dependencies

* `dmtap-naming`
* `dmtap-core`
* `sha3`
* `sha2`
* `bs58`
* `curve25519-dalek`
* `serde_json`
* `hex`
* `base64`
* `thiserror`
* `ureq`

## Running its tests

```sh
cargo test -p dmtap-namechain-rpc
```

## Publishing

This crate carries complete publishable metadata (description, license, repository,
homepage, keywords, readme). Publishing to crates.io is nevertheless **blocked upstream**: it
depends on `kotva-core`, which is a git dependency and is not on crates.io, and cargo refuses to
publish a crate with a version-less dependency. `kotva-core` has to be published first.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
