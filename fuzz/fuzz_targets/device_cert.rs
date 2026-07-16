#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::identity::DeviceCert;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, DeviceCert::from_det_cbor, |o: &DeviceCert| o.det_cbor());
});
