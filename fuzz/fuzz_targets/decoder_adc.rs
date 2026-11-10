#![no_main]
use compcol::Algorithm as _;
use libfuzzer_sys::fuzz_target;

mod common;

// The ADC decoder must not panic on arbitrary input, and must not stall:
// unlike the older `decoder_*` targets, a call that reports no progress
// while it still has input and output room is retried once and then
// treated as a failure (see `common::drive`).
fuzz_target!(|data: &[u8]| {
    common::smoke("adc", <compcol::adc::Adc>::decoder(), data);
});
