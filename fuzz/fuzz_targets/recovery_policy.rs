#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::identity::RecoveryPolicy;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, RecoveryPolicy::from_det_cbor, |o: &RecoveryPolicy| o.det_cbor());
});
