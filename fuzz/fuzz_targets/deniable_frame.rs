#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::deniable::DeniableFrame;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, DeniableFrame::from_det_cbor, |o: &DeniableFrame| o.det_cbor());
});
