#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::mote::Payload;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, Payload::from_det_cbor, |o: &Payload| o.det_cbor());
});
