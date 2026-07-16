#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::mixnet::MixNodeDescriptor;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, MixNodeDescriptor::from_det_cbor, |o: &MixNodeDescriptor| o.det_cbor());
});
