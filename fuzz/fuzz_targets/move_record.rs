#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::identity::MoveRecord;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, MoveRecord::from_det_cbor, |o: &MoveRecord| o.det_cbor());
});
