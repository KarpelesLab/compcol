#![no_main]
//! Differential target: chunked decode vs one-shot decode.
//!
//! A streaming decoder's result must not depend on how the caller slices
//! the input or how big its output buffer is. The audit of v0.7.8 found
//! that bug class repeatedly (lzw CLEAR, lzx overshoot, zip_shrink), so
//! this target decodes the same bytes twice with a fuzz-chosen decoder:
//!
//!   byte 0     decoder, as an index into `factory::names()`
//!   byte 1, 2  input-chunk / output-buffer size policy for the chunked run
//!   rest       the compressed stream
//!
//! once in one shot (whole input, large output buffer) and once in small
//! pieces, and requires the same outcome class: both `StreamEnd` with
//! identical bytes, or both `Err` (the variants may differ -- a truncated
//! header can surface as `UnexpectedEnd` one way and `Corrupt` the other).
//! When either run was cut short by the driver (step bound, output
//! ceiling) there is no verdict to compare, but what both produced so far
//! must still agree byte for byte.

use compcol::factory;
use libfuzzer_sys::fuzz_target;

mod common;
use common::{Outcome, Sizes};

/// Decoders left out of the comparison, each with the reason. Keep this
/// list honest: an entry is a known divergence to triage, not a fix.
const EXCLUDED: &[&str] = &[
    // Depends on the *input* chunk size: a stream the one-shot run rejects
    // as Corrupt decodes to StreamEnd when fed 1, 2, 3 or 7 bytes at a time
    // (4, 5, 8 and larger chunks agree with one-shot).
    // Reproducer (whole fuzz input, hex): 289595010000000000d307
    "zip-shrink",
];

/// Output kept per run. Past this the run stops with `SinkFull`.
const MAX_OUTPUT: usize = 1 << 20;
/// One-shot output buffer.
const ONESHOT_BUF: usize = 256 * 1024;
const ONESHOT_STEPS: usize = 4096;
const CHUNKED_STEPS: usize = 1 << 16;

fn run(name: &str, label: &str, data: &[u8], sizes: Sizes, steps: usize) -> (Outcome, Vec<u8>) {
    let mut dec = factory::decoder_by_name(name).expect("name comes from factory::names()");
    let mut out = Vec::new();
    let what = format!("{name} ({label})");
    let outcome = common::drive(&what, &mut dec, data, sizes, steps, |chunk| {
        out.extend_from_slice(chunk);
        out.len() <= MAX_OUTPUT
    });
    (outcome, out)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let names = factory::names();
    let name = names[data[0] as usize % names.len()];
    if EXCLUDED.contains(&name) {
        return;
    }
    let sizes = Sizes::from_bytes(data[1], data[2]);
    let (in_max, out_max, varied) = (sizes.in_max, sizes.out_max, sizes.rng.is_some());
    let payload = &data[3..];

    let (one, one_out) = run(
        name,
        "one-shot",
        payload,
        Sizes::fixed(usize::MAX, ONESHOT_BUF),
        ONESHOT_STEPS,
    );
    let (chk, chk_out) = run(name, "chunked", payload, sizes, CHUNKED_STEPS);
    let how =
        format_args!("{name}: chunked (in<={in_max}, out<={out_max}, varied={varied}) vs one-shot")
            .to_string();

    match (&one, &chk) {
        (Outcome::End, Outcome::End) => {
            assert!(
                one_out == chk_out,
                "{how}: both ended cleanly but the output differs \
                 (one-shot {} bytes, chunked {} bytes, first difference at {:?})",
                one_out.len(),
                chk_out.len(),
                one_out.iter().zip(&chk_out).position(|(a, b)| a != b)
            );
        }
        (Outcome::Err(_), Outcome::Err(_)) => {}
        (Outcome::End, Outcome::Err(e)) => {
            panic!(
                "{how}: one-shot ended cleanly ({} bytes) but chunked failed with {e:?} \
                 after {} bytes",
                one_out.len(),
                chk_out.len()
            );
        }
        (Outcome::Err(e), Outcome::End) => {
            panic!(
                "{how}: one-shot failed with {e:?} after {} bytes but chunked ended cleanly \
                 ({} bytes)",
                one_out.len(),
                chk_out.len()
            );
        }
        // No verdict from at least one side.
        (Outcome::Err(_), _) | (_, Outcome::Err(_)) => {}
        _ => {
            let n = one_out.len().min(chk_out.len());
            assert!(
                one_out[..n] == chk_out[..n],
                "{how}: outputs diverge at {:?} within the common {n}-byte prefix \
                 (one-shot {one:?}, chunked {chk:?})",
                one_out.iter().zip(&chk_out).position(|(a, b)| a != b)
            );
            // A clean end on one side bounds what the other may produce.
            if matches!(one, Outcome::End) {
                assert!(
                    chk_out.len() <= one_out.len(),
                    "{how}: chunked produced {} bytes, more than the one-shot total {}",
                    chk_out.len(),
                    one_out.len()
                );
            }
            if matches!(chk, Outcome::End) {
                assert!(
                    one_out.len() <= chk_out.len(),
                    "{how}: one-shot produced {} bytes, more than the chunked total {}",
                    one_out.len(),
                    chk_out.len()
                );
            }
        }
    }
});
