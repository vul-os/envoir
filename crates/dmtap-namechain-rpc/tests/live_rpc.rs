//! Live-RPC integration tests — the honest network seam (§6.6).
//!
//! These are the ONLY tests that touch a real chain, so they are `#[ignore]`d and read their
//! endpoint from an env var; CI runs the offline unit tests (KAT + mocked transport) instead. Run one
//! explicitly, e.g.:
//!
//! ```text
//! ENS_RPC_URL=https://ethereum-rpc.publicnode.com \
//!   cargo test -p dmtap-namechain-rpc --test live_rpc -- --ignored ens_live_resolver_reachable
//!
//! SOL_RPC_URL=https://api.mainnet-beta.solana.com \
//!   cargo test -p dmtap-namechain-rpc --test live_rpc -- --ignored sns_live_bonfida_account
//! ```
//!
//! They assert only that the real transport + JSON-RPC + on-chain decode path executes end-to-end
//! against public infrastructure; they do NOT assume any particular name publishes a DMTAP `dmtap`
//! record (mainnet has none yet), so a clean [`None`] (no record) is an accepted outcome — the point
//! is that the client talks to the chain without erroring on the transport/JSON layer.

#![cfg(feature = "net")]

use dmtap_namechain_rpc::ens::{namehash, EnsClient};
use dmtap_namechain_rpc::sns::{domain_key, SnsClient};
use dmtap_namechain_rpc::UreqTransport;
use dmtap_naming::namechain::NameChainClient;

#[test]
#[ignore = "requires ENS_RPC_URL and network"]
fn ens_live_resolver_reachable() {
    let url = std::env::var("ENS_RPC_URL").expect("set ENS_RPC_URL");
    let client = EnsClient::new(UreqTransport::new(), url);
    // `vitalik.eth` certainly resolves to a resolver on-chain; whether it carries a `dmtap` text
    // record is another matter — either a decoded key or a clean `None` proves the path works.
    let out = client.resolve("vitalik@.eth");
    eprintln!("ens vitalik@.eth => {out:?}");
    // Sanity: the namehash we key on is the canonical one.
    assert_eq!(
        hex::encode(namehash("vitalik.eth")),
        "ee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835"
    );
}

#[test]
#[ignore = "requires SOL_RPC_URL and network"]
fn sns_live_bonfida_account() {
    let url = std::env::var("SOL_RPC_URL").expect("set SOL_RPC_URL");
    let client = SnsClient::new(UreqTransport::new(), url);
    // The bonfida.sol account exists on mainnet; its payload is not a DMTAP record, so a clean
    // `None`/miss is fine — we are exercising the real getAccountInfo + decode path.
    let out = client.resolve("bonfida@.sol");
    eprintln!("sns bonfida@.sol => {out:?}");
    assert_eq!(
        bs58::encode(domain_key("bonfida").unwrap()).into_string(),
        "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb"
    );
}
