//! Integration tests for `compcol::vec::{compress_to_vec, decompress_to_vec, *_with}`.
//!
//! The helpers are alloc-only (no `std`), so this file exercises every
//! feature set that brings in an algorithm. Tests cover round-trips
//! across leveled and non-leveled algorithms, the `_with` config form,
//! and error handling on truncated input.

#![cfg(feature = "alloc")]

fn payload(n: usize) -> Vec<u8> {
    // Mixed corpus: short alphabet noise + repeated phrase. Compresses
    // well enough to exercise the codec; large enough (~96 KiB) to
    // cross brotli/zstd block boundaries.
    let mut out = Vec::with_capacity(n);
    let phrase = b"The_quick_brown_fox_jumps_over_the_lazy_dog. ";
    let mut state: u32 = 0xC0FFEE_u32;
    while out.len() < n {
        for _ in 0..32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push(b"abcdef"[(state as usize) % 6]);
        }
        out.extend_from_slice(phrase);
    }
    out.truncate(n);
    out
}

// ─── rle (no config, no_std friendly) ──────────────────────────────────

#[cfg(feature = "rle")]
mod rle {
    use super::*;
    use compcol::vec::{compress_to_vec, decompress_to_vec};

    #[test]
    fn round_trip_empty() {
        let c = compress_to_vec::<compcol::rle::Rle>(&[]).unwrap();
        let d = decompress_to_vec::<compcol::rle::Rle>(&c).unwrap();
        assert!(d.is_empty());
    }

    #[test]
    fn round_trip_short() {
        let input = b"hello, world\n";
        let c = compress_to_vec::<compcol::rle::Rle>(input).unwrap();
        let d = decompress_to_vec::<compcol::rle::Rle>(&c).unwrap();
        assert_eq!(d, input);
    }

    #[test]
    fn round_trip_large() {
        let input = payload(96 * 1024);
        let c = compress_to_vec::<compcol::rle::Rle>(&input).unwrap();
        let d = decompress_to_vec::<compcol::rle::Rle>(&c).unwrap();
        assert_eq!(d, input);
    }
}

// ─── gzip (leveled, _with form) ─────────────────────────────────────────

#[cfg(feature = "gzip")]
mod gzip {
    use super::*;
    use compcol::gzip::{EncoderConfig, Gzip};
    use compcol::vec::{
        compress_to_vec, compress_to_vec_with, decompress_to_vec, decompress_to_vec_capped,
        decompress_to_vec_capped_with, decompress_to_vec_with,
    };

    #[test]
    fn round_trip_default_config() {
        let input = payload(96 * 1024);
        let c = compress_to_vec::<Gzip>(&input).unwrap();
        let d = decompress_to_vec::<Gzip>(&c).unwrap();
        assert_eq!(d, input);
    }

    #[test]
    fn level_9_is_at_least_as_small_as_level_1() {
        let input = payload(96 * 1024);
        let small = compress_to_vec_with::<Gzip>(&input, EncoderConfig { level: 9 }).unwrap();
        let big = compress_to_vec_with::<Gzip>(&input, EncoderConfig { level: 1 }).unwrap();
        assert!(
            small.len() <= big.len(),
            "level 9 produced {} bytes vs level 1's {}",
            small.len(),
            big.len()
        );
        // Both must roundtrip.
        assert_eq!(decompress_to_vec::<Gzip>(&small).unwrap(), input);
        assert_eq!(decompress_to_vec::<Gzip>(&big).unwrap(), input);
    }

    #[test]
    fn decompress_truncated_input_errors() {
        use compcol::Error;
        let input = payload(8 * 1024);
        let compressed = compress_to_vec::<Gzip>(&input).unwrap();
        // Drop the last 4 bytes (CRC/ISIZE region).
        let truncated = &compressed[..compressed.len() - 4];
        let err = decompress_to_vec::<Gzip>(truncated).unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedEnd | Error::TrailerMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn capped_within_limit_round_trips() {
        let input = payload(64 * 1024);
        let c = compress_to_vec::<Gzip>(&input).unwrap();
        // Cap comfortably above the decoded size: succeeds, matches input.
        let d = decompress_to_vec_capped::<Gzip>(&c, 1 << 20).unwrap();
        assert_eq!(d, input);
    }

    #[test]
    fn capped_over_limit_errors() {
        use compcol::Error;
        let input = payload(64 * 1024);
        let c = compress_to_vec::<Gzip>(&input).unwrap();
        // Cap below the decoded size: must abort with OutputLimitExceeded.
        let err = decompress_to_vec_capped::<Gzip>(&c, 1024).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded), "got {err:?}");
    }

    #[test]
    fn capped_exact_limit_succeeds() {
        let input = payload(8 * 1024);
        let c = compress_to_vec::<Gzip>(&input).unwrap();
        // Exactly the decoded size is allowed.
        let d = decompress_to_vec_capped_with::<Gzip>(&c, (), input.len() as u64).unwrap();
        assert_eq!(d, input);
    }

    #[test]
    fn decompress_to_vec_with_default_decoder_config() {
        let input = b"explicit decoder config";
        let c = compress_to_vec::<Gzip>(input).unwrap();
        // DecoderConfig is `()` for gzip — passing `()` is the explicit
        // way to call the `_with` form even when there's nothing to tune.
        let d = decompress_to_vec_with::<Gzip>(&c, ()).unwrap();
        assert_eq!(d, input);
    }
}

// ─── zstd (leveled, large alphabet) ─────────────────────────────────────

#[cfg(feature = "zstd")]
mod zstd {
    use super::*;
    use compcol::vec::{compress_to_vec, decompress_to_vec};
    use compcol::zstd::Zstd;

    #[test]
    fn round_trip_large() {
        let input = payload(256 * 1024);
        let c = compress_to_vec::<Zstd>(&input).unwrap();
        let d = decompress_to_vec::<Zstd>(&c).unwrap();
        assert_eq!(d, input);
    }
}

// ─── lz4 (no level config) ──────────────────────────────────────────────

#[cfg(feature = "lz4")]
mod lz4 {
    use super::*;
    use compcol::lz4::Lz4;
    use compcol::vec::{compress_to_vec, decompress_to_vec};

    #[test]
    fn round_trip_64k_plus_1() {
        // A size that's awkward for block-based codecs.
        let input = payload(64 * 1024 + 1);
        let c = compress_to_vec::<Lz4>(&input).unwrap();
        let d = decompress_to_vec::<Lz4>(&c).unwrap();
        assert_eq!(d, input);
    }
}

// ─── brotli (regression: > 256 KiB used to fail) ────────────────────────

#[cfg(feature = "brotli")]
mod brotli {
    use super::*;
    use compcol::brotli::Brotli;
    use compcol::vec::{compress_to_vec, decompress_to_vec};

    #[test]
    fn round_trip_above_old_buggy_size() {
        let input = payload(1_000_000);
        let c = compress_to_vec::<Brotli>(&input).unwrap();
        let d = decompress_to_vec::<Brotli>(&c).unwrap();
        assert_eq!(d, input);
    }
}
