//! Integration tests for `compcol::vec::{compress_to_vec, decompress_to_vec, *_with}`.
//!
//! The helpers are alloc-only (no `std`), so this file exercises every
//! feature set that brings in an algorithm. Tests cover round-trips
//! across leveled and non-leveled algorithms, the `_with` config form,
//! and error handling on truncated input.

#![cfg(feature = "alloc")]

// Only used by feature-gated submodules below; a minimal feature set that
// enables `alloc` (e.g. just `bcj` or `delta`) compiles none of them, so the
// helper is legitimately unused in those builds.
#[allow(dead_code)]
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

// ─── lha (lh5 via the one-shot vec helpers) ─────────────────────────────
//
// Only the block-structured static methods (e.g. lh5) work through the
// generic one-shot helpers, which use the default decoder config (no length)
// and rely on `finish()` to terminate. `lh1` is size-terminated and needs
// `DecoderConfig::with_len`, which the generic helpers can't supply — so it
// is exercised in `tests/lha.rs` instead.

#[cfg(feature = "lha")]
mod lha {
    use super::*;
    use compcol::lha::Lh5;
    use compcol::vec::{compress_to_vec, decompress_to_vec};

    #[test]
    fn round_trip_lh5() {
        let input = payload(64 * 1024 + 7);
        let c = compress_to_vec::<Lh5>(&input).unwrap();
        let d = decompress_to_vec::<Lh5>(&c).unwrap();
        assert_eq!(d, input);
    }
}

// ─── drain contract: `OutputFull` after all input was consumed ─────────

/// A decoder that, like bzip2 (whole block) or zstd (whole Compressed_Block),
/// absorbs all of its input in one call and then needs several calls to hand
/// the decoded bytes out. Its `finish` is deliberately strict: it refuses to
/// drain and reports `UnexpectedEnd` if bytes are still pending, so the
/// one-shot helpers must keep calling `decode` while it says `OutputFull` —
/// even after every input byte has been consumed — exactly as the
/// [`compcol::Status::OutputFull`] contract says.
mod drain_contract {
    use compcol::{Algorithm, Decoder, Encoder, Error, Progress, Status};

    #[derive(Default)]
    struct BufferingDecoder {
        pending: Vec<u8>,
        pos: usize,
    }

    impl Decoder for BufferingDecoder {
        fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error> {
            self.pending.extend_from_slice(input);
            let n = (self.pending.len() - self.pos).min(output.len());
            output[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
            self.pos += n;
            let status = if self.pos < self.pending.len() {
                Status::OutputFull
            } else {
                Status::InputEmpty
            };
            Ok((
                Progress {
                    consumed: input.len(),
                    written: n,
                },
                status,
            ))
        }

        fn finish(&mut self, _output: &mut [u8]) -> Result<(Progress, Status), Error> {
            if self.pos < self.pending.len() {
                return Err(Error::UnexpectedEnd);
            }
            Ok((Progress::default(), Status::StreamEnd))
        }

        fn reset(&mut self) {
            *self = Self::default();
        }

        fn discard_output(
            &mut self,
            _input: &[u8],
            _n: usize,
        ) -> Result<(Progress, Status), Error> {
            Err(Error::Unsupported)
        }
    }

    /// Identity encoder so the marker type satisfies `Algorithm`.
    #[derive(Default)]
    struct Identity;

    impl Encoder for Identity {
        fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error> {
            let n = input.len().min(output.len());
            output[..n].copy_from_slice(&input[..n]);
            let status = if n == input.len() {
                Status::InputEmpty
            } else {
                Status::OutputFull
            };
            Ok((
                Progress {
                    consumed: n,
                    written: n,
                },
                status,
            ))
        }

        fn finish(&mut self, _output: &mut [u8]) -> Result<(Progress, Status), Error> {
            Ok((Progress::default(), Status::StreamEnd))
        }

        fn reset(&mut self) {}
    }

    struct Buffering;

    impl Algorithm for Buffering {
        const NAME: &'static str = "buffering-test";
        type Encoder = Identity;
        type Decoder = BufferingDecoder;
        type EncoderConfig = ();
        type DecoderConfig = ();

        fn encoder_with(_: ()) -> Identity {
            Identity
        }
        fn decoder_with(_: ()) -> BufferingDecoder {
            BufferingDecoder::default()
        }
    }

    /// Larger than the helpers' 64 KiB scratch buffer, so the decoder still
    /// holds pending output after swallowing the whole input.
    fn big() -> Vec<u8> {
        (0..300_000u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn decompress_to_vec_drains_after_input_exhausted() {
        let data = big();
        let out = compcol::vec::decompress_to_vec::<Buffering>(&data).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn decompress_to_vec_capped_drains_after_input_exhausted() {
        let data = big();
        let out = compcol::vec::decompress_to_vec_capped::<Buffering>(&data, 1 << 20).unwrap();
        assert_eq!(out, data);
        // The cap still applies on the drain-only calls.
        assert_eq!(
            compcol::vec::decompress_to_vec_capped::<Buffering>(&data, 100_000),
            Err(Error::OutputLimitExceeded)
        );
    }
}
