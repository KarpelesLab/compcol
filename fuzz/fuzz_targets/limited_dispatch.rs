#![no_main]
//! `LimitedDecoder` over every factory decoder.
//!
//! SECURITY.md promises a bomb-bounded decode when the caller supplies an
//! output limit. This target checks the shared layer that implements the
//! promise rather than any one codec:
//!
//!   byte 0     decoder, as an index into `factory::names()`
//!   byte 1     output cap, as an index into `CAPS`
//!   byte 2, 3  input-chunk / output-buffer size policy (`common::Sizes`)
//!   rest       the compressed stream
//!
//! Invariants:
//!   * the bytes handed out never exceed the cap, and agree with
//!     `LimitedDecoder::bytes_written`;
//!   * the run ends in `StreamEnd`, an `Err`, or this driver's step bound --
//!     never by a decoder that stops making progress (`common::drive`
//!     panics on a repeated no-progress call).
//!
//! No decoder is excluded. `ppmd` and `rar3` size a model arena from the
//! stream header (up to 256 MiB, see SECURITY.md) whatever the cap is, but
//! one decoder is alive per input and local runs stayed well under the
//! 2 GiB `-rss_limit_mb` CI uses. If that ever stops being true, drop those
//! names here rather than raising the limit.

use compcol::factory;
use compcol::limit::LimitedDecoder;
use libfuzzer_sys::fuzz_target;

mod common;

/// Output caps: the degenerate ones (0, 1), values straddling the 64 KiB
/// buffer/window size most decoders use, and a few hundred KiB at the top.
const CAPS: [u64; 16] = [
    0, 1, 2, 7, 255, 256, 4096, 32768, 65535, 65536, 65537, 70001, 131072, 262144, 300_000, 400_000,
];

/// Calls per input. Enough to drain the largest cap through small buffers
/// for realistic inputs, small enough that a 1-byte policy stays cheap.
const MAX_STEPS: usize = 1 << 15;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let names = factory::names();
    let name = names[data[0] as usize % names.len()];
    let cap = CAPS[(data[1] & 15) as usize];
    let sizes = common::Sizes::from_bytes(data[2], data[3]);
    let payload = &data[4..];

    let Some(inner) = factory::decoder_by_name(name) else {
        return;
    };
    let mut dec = LimitedDecoder::new(inner, cap);
    let mut total = 0u64;
    let outcome = common::drive(name, &mut dec, payload, sizes, MAX_STEPS, |chunk| {
        total += chunk.len() as u64;
        assert!(
            total <= cap,
            "{name}: LimitedDecoder handed out {total} bytes with a cap of {cap}"
        );
        true
    });
    assert_eq!(
        dec.bytes_written(),
        total,
        "{name}: bytes_written disagrees with the bytes handed out (cap {cap}, {outcome:?})"
    );
});
