#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::mote::Envelope;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, Envelope::from_det_cbor, |o: &Envelope| o.det_cbor());
});
