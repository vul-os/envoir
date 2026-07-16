#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::identity::Identity;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, Identity::from_det_cbor, |o: &Identity| o.det_cbor());
});
