//! Regression tests for the "no-progress stall" class of bug.
//!
//! A decoder that has reached its terminal state must say so. If it returns
//! `done: false` with nothing consumed and nothing written while the caller
//! still holds input, the `RawDecoder`->`Decoder` bridge maps that to
//! `Status::OutputFull` — "drain and call me again" — even though calling
//! again cannot make progress. A caller looping until `Status::StreamEnd`
//! (`vec::decompress_to_vec` among them) then spins on unchanged state:
//! CPU-bound, no allocation, so neither an output-size cap nor a memory cap
//! can stop it. Only a wall-clock timeout ends it, and nothing outside the
//! decoder can prevent it.
//!
//! Two shapes are checked per codec, because they exercise different paths:
//!
//! 1. **trailing bytes present in the same call** — the terminal state is
//!    reached with input still unread.
//! 2. **trailing bytes arriving in a later call** — the decoder is already
//!    parked in its terminal state when the next slice shows up. This is
//!    what a container does when it hands over the next header after the
//!    payload, and it is the shape that survived the first round of fixes.
//!
//! Each codec below had this verified by reading its `raw_decode`; the tests
//! keep it from regressing.

#![cfg(feature = "alloc")]

#[allow(dead_code)]
fn payload() -> Vec<u8> {
    b"hello hello hello world world 1234567890 abcabcabc".repeat(20)
}

/// Drive `dec` over `encoded` to completion, then assert that the codec
/// neither stalls on trailing bytes supplied in the same call nor on bytes
/// handed over afterwards.
#[allow(dead_code)]
fn assert_no_stall<A: compcol::Algorithm>(name: &str) {
    use compcol::{Decoder as _, Status};

    let plain = payload();
    let encoded = compcol::vec::compress_to_vec::<A>(&plain)
        .unwrap_or_else(|e| panic!("{name}: encode failed: {e:?}"));

    // Shape 1: trailing garbage in the same buffer.
    {
        let mut stream = encoded.clone();
        stream.extend_from_slice(&[0xAA; 32]);
        let mut dec = A::decoder();
        let mut out = vec![0u8; 1 << 16];
        let mut consumed = 0usize;
        let mut total = 0usize;
        for _ in 0..256 {
            let (p, status) = dec.decode(&stream[consumed..], &mut out).unwrap();
            consumed += p.consumed;
            total += p.written;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            // The safety property. `StreamEnd` and `InputEmpty` are both fine
            // terminations — a decoder that buffers input and produces on
            // `finish` legitimately never reports `StreamEnd` from `decode`.
            // What must never happen is `OutputFull` ("call me again") with
            // nothing consumed and nothing written, which cannot terminate.
            assert!(
                !(p.consumed == 0 && p.written == 0 && status == Status::OutputFull),
                "{name}: asked to be called again without making progress \
                 (trailing bytes in the same call)"
            );
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        assert_eq!(total, plain.len(), "{name}: wrong decoded length");
    }

    // Shape 2: the trailing bytes arrive only after the payload is done.
    {
        let mut dec = A::decoder();
        let mut out = vec![0u8; 1 << 16];
        let mut consumed = 0usize;
        for _ in 0..256 {
            let (p, status) = dec.decode(&encoded[consumed..], &mut out).unwrap();
            consumed += p.consumed;
            if matches!(status, Status::StreamEnd) || (p.consumed == 0 && p.written == 0) {
                break;
            }
        }
        let (p, status) = dec.decode(&[0xAA; 32], &mut out).unwrap();
        assert!(
            !(p.consumed == 0 && p.written == 0 && status == Status::OutputFull),
            "{name}: asked to be called again without making progress \
             (trailing bytes delivered after completion)"
        );
    }
}

macro_rules! case {
    ($feat:literal, $test:ident, $ty:path, $name:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $test() {
            assert_no_stall::<$ty>($name);
        }
    };
}

// Codecs whose terminal state reported `done: false`; all fixed.
case!("zstd", zstd_no_stall, compcol::zstd::Zstd, "zstd");
case!("xz", xz_no_stall, compcol::xz::Xz, "xz");
case!("lz4", lz4_no_stall, compcol::lz4::Lz4, "lz4");
case!(
    "lz4",
    lz4_frame_no_stall,
    compcol::lz4::frame::LZ4Frame,
    "lz4frame"
);
case!("lzo", lzo_no_stall, compcol::lzo::Lzo, "lzo");
case!("lzx", lzx_no_stall, compcol::lzx::Lzx, "lzx");
case!(
    "amiga_lzx",
    amiga_lzx_no_stall,
    compcol::amiga_lzx::AmigaLzx,
    "amiga_lzx"
);
// gzip's Done arm swallows trailing input, but the `BetweenMembers` arm that
// hands off to it needs an explicit `continue` — match arms do not fall
// through, so without it the loop's no-progress check returned first.
case!("gzip", gzip_no_stall, compcol::gzip::Gzip, "gzip");
// Fixed earlier alongside the reported DEFLATE/zlib DoS; kept here so the
// whole class is covered in one place.
case!(
    "deflate",
    deflate_no_stall,
    compcol::deflate::Deflate,
    "deflate"
);
case!(
    "deflate64",
    deflate64_no_stall,
    compcol::deflate64::Deflate64,
    "deflate64"
);
case!("zlib", zlib_no_stall, compcol::zlib::Zlib, "zlib");

// Controls: these already reported completion correctly. They guard against a
// future refactor breaking the codecs that were right all along.
case!("bzip2", bzip2_no_stall, compcol::bzip2::Bzip2, "bzip2");
case!("brotli", brotli_no_stall, compcol::brotli::Brotli, "brotli");
case!("lzma", lzma_no_stall, compcol::lzma::Lzma, "lzma");
