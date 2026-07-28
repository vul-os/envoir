# integration

Cross-component end-to-end integration tests for the Envoir DMTAP reference stack — wiring the real node, mail, gateway, p2p, naming, and deniable crates together (legacy↔DMTAP, DMTAP↔DMTAP over TCP, DMTAP↔DMTAP over real libp2p, adversarial, KT-verified resolution, deniable repudiation)

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

Cross-component integration tests for the Envoir DMTAP reference stack.

## Running its tests

```sh
cargo test -p integration
```

## Publishing

This crate is `publish = false`: it is a harness/test crate, not a library anyone should
depend on.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
