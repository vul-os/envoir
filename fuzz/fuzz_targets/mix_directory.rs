#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::mixnet::MixDirectory;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, MixDirectory::from_det_cbor, |o: &MixDirectory| o.det_cbor());
});
