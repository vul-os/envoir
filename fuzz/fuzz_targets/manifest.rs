#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::mote::Manifest;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, Manifest::from_det_cbor, |o: &Manifest| o.det_cbor());
});
