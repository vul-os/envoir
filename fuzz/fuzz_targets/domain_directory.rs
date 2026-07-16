#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::directory::DomainDirectory;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, DomainDirectory::from_det_cbor, |o: &DomainDirectory| o.det_cbor());
});
