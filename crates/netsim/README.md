# netsim

Mixnet anonymity simulator — a deterministic, seeded MODEL of DMTAP's Sphinx/Loopix mixing mechanism (§4.4, §16.3) that empirically measures the sender→receiver correlation resistance and anonymity-set entropy the spec claims. Not the wire format; not the real Sphinx client.

Part of the [envoir](https://github.com/vul-os/envoir) workspace — the node-only reference
implementation of DMTAP (Decentralized Message Transfer & Access Protocol). The **specification**
lives in the sibling [KOTVA](https://github.com/vul-os/kotva) repo, and so does the substrate it is
built on (`kotva-core`, `kotva-mail`, `kotva-sync`), consumed here under the `dmtap_*` Rust paths
via a cargo dependency-rename.

## What it is

# netsim — DMTAP mixnet anonymity simulator

## Dependencies

* `rand`
* `rand_chacha`
* `rand_distr`

## Running its tests

```sh
cargo test -p netsim
```

## Publishing

This crate is `publish = false`: it is a harness/test crate, not a library anyone should
depend on.

## License

MIT (see the workspace `LICENSE-MIT`; the workspace as a whole is `MIT OR Apache-2.0`).
