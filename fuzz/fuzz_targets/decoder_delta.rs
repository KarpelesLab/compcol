#![no_main]
use compcol::delta::{DecoderConfig, Delta};
use compcol::{Algorithm as _, Decoder as _};
use libfuzzer_sys::fuzz_target;

// Smoke property: the decoder must not panic on arbitrary input.
// libfuzzer feeds us garbage bytes; we drive the decoder over them
// and discard the result. Any panic, abort, or undefined behavior
// trips the harness.
//
// Delta is a byte-differencing filter parameterized by a distance in
// `1..=256`. We derive a small bounded distance from the first input
// byte (defaulting to 1) and treat the remainder as the payload.
fuzz_target!(|data: &[u8]| {
    let (dist, payload) = match data.split_first() {
        Some((&d, rest)) => ((d as usize % 256) + 1, rest),
        None => (1, data),
    };
    let mut dec = Delta::decoder_with(DecoderConfig { dist });
    let mut out = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    let mut steps = 0;
    while consumed < payload.len() {
        match dec.decode(&payload[consumed..], &mut out) {
            Ok((p, _)) => {
                if p.consumed == 0 && p.written == 0 {
                    break;
                }
                consumed += p.consumed;
            }
            Err(_) => return,
        }
        steps += 1;
        if steps > 4096 {
            return;
        }
    }
    let mut steps = 0;
    while let Ok((p, status)) = dec.finish(&mut out) {
        if matches!(status, compcol::Status::StreamEnd) {
            return;
        }
        if p.written == 0 {
            return;
        }
        steps += 1;
        if steps > 4096 {
            return;
        }
    }
});
