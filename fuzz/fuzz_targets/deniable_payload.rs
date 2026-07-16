#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::deniable::DeniablePayload;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, DeniablePayload::from_det_cbor, |o: &DeniablePayload| o.det_cbor());
});
