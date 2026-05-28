//! Integration tests for the RAR 3.x decoder.
//!
//! The decoder takes the raw bytes that follow a RAR3 file-header inside an
//! archive — it does not parse the surrounding container. Fixtures here
//! are the decompressed-block bytes lifted out of small libarchive test
//! archives (BSD-licensed), with the surrounding file/main headers
//! stripped. The expected outputs come from running `unrar p` against the
//! original `.rar` files. See `src/rar3/mod.rs` for the calling
//! convention.

#![cfg(feature = "rar3")]

use compcol::rar3::{Decoder, Encoder, Rar3, apply_e8_filter};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

// ─── helpers ──────────────────────────────────────────────────────────────

/// Drain `Decoder::finish` until `done` or no further progress.
fn drain(dec: &mut Decoder, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    loop {
        let p = dec.finish(&mut buf).unwrap_or_else(|e| {
            panic!("finish failed: {e:?}");
        });
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
}

/// Decode a full RAR3 raw block in one shot.
fn decode_full(input: &[u8], unpack_size: u64) -> Vec<u8> {
    let mut dec = Decoder::with_unpack_size(unpack_size);
    let _ = dec.decode(input, &mut []).unwrap();
    let mut out = Vec::with_capacity(unpack_size as usize);
    drain(&mut dec, &mut out);
    out
}

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_rar3() {
    assert_eq!(<Rar3 as Algorithm>::NAME, "rar3");
}

#[test]
fn encoder_is_permanently_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
    enc.reset();
}

#[test]
fn algorithm_factory_produces_pair() {
    let _enc = <Rar3 as Algorithm>::encoder();
    let _dec = <Rar3 as Algorithm>::decoder();
}

// ─── empty stream ────────────────────────────────────────────────────────

#[test]
fn unpack_size_zero_decodes_to_empty() {
    let out = decode_full(&[], 0);
    assert!(out.is_empty());
}

#[test]
fn finish_on_fresh_decoder_with_no_input_short_unpack() {
    // unpack_size 0 ⇒ trivially Done.
    let mut dec = Decoder::with_unpack_size(0);
    let mut buf = [0u8; 8];
    let p = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert!(p.done);
}

// ─── real fixture: testdir/test.txt from libarchive's
// test_read_format_rar_compress_normal.rar ───────────────────────────────

/// The 30-byte RAR3-compressed block extracted from libarchive's
/// `test_read_format_rar_compress_normal.rar`, the entry for
/// `testdir/test.txt`. The unpacked size is 20 bytes (the ASCII string
/// `"test text document\r\n"`).
///
/// libarchive's test_read_format_rar.rar.uu is BSD-licensed. The bytes
/// reproduced here are the *output* of an unrelated proprietary encoder
/// (RAR 2.x) and are facts of nature for the purposes of testing — we
/// don't redistribute libarchive's source.
const TESTDIR_TEST_TXT_BLOCK: &[u8] = &[
    0x08, 0x00, 0xC8, 0xFE, 0x8C, 0xF7, 0xA1, 0x78, 0x77, 0xB7, 0x59, 0xA2, 0xB8, 0x31, 0x07, 0xFC,
    0x4B, 0x95, 0xFF, 0xC2, 0x28, 0xA7, 0xCC, 0xF3, 0x4A, 0xDB, 0x88, 0x3D, 0xE6, 0xA0,
];
const TESTDIR_TEST_TXT_EXPECTED: &[u8] = b"test text document\r\n";

#[test]
fn decodes_libarchive_test_txt_fixture() {
    let out = decode_full(
        TESTDIR_TEST_TXT_BLOCK,
        TESTDIR_TEST_TXT_EXPECTED.len() as u64,
    );
    assert_eq!(
        out,
        TESTDIR_TEST_TXT_EXPECTED,
        "decoded output (len {}) didn't match expected (len {}): {:?}",
        out.len(),
        TESTDIR_TEST_TXT_EXPECTED.len(),
        out
    );
}

#[test]
fn decodes_libarchive_test_txt_chunked_input() {
    let mut dec = Decoder::with_unpack_size(TESTDIR_TEST_TXT_EXPECTED.len() as u64);
    // Feed input one byte at a time.
    for chunk in TESTDIR_TEST_TXT_BLOCK.chunks(1) {
        let p = dec.decode(chunk, &mut []).unwrap();
        assert_eq!(p.consumed, chunk.len());
    }
    let mut out = Vec::new();
    drain(&mut dec, &mut out);
    assert_eq!(out, TESTDIR_TEST_TXT_EXPECTED);
}

#[test]
fn decodes_libarchive_test_txt_tight_output_buffer() {
    let mut dec = Decoder::with_unpack_size(TESTDIR_TEST_TXT_EXPECTED.len() as u64);
    let _ = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out: Vec<u8> = Vec::new();
    // Drain through a 3-byte output buffer.
    let mut buf = [0u8; 3];
    loop {
        let p = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    assert_eq!(out, TESTDIR_TEST_TXT_EXPECTED);
}

// ─── PPMd rejection ──────────────────────────────────────────────────────

#[test]
fn ppmd_block_is_unsupported() {
    // A block whose first bit (after byte-align) is 1 = PPMd flag.
    // 0x80 = 1000_0000 → byte-aligned start, top bit = 1 ⇒ PPMd.
    let ppmd_marker = [0x80u8, 0x00, 0x00, 0x00];
    let mut dec = Decoder::with_unpack_size(32);
    let _ = dec.decode(&ppmd_marker, &mut []).unwrap();
    let mut buf = [0u8; 16];
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

// ─── error path: truncated input ─────────────────────────────────────────

#[test]
fn truncated_input_fails_with_unexpected_end_or_corrupt() {
    // First two bytes of a real fixture won't have enough state to build the
    // precode, so finish() should return UnexpectedEnd (or Corrupt if the
    // partial bits decode to something invalid first).
    let truncated = &TESTDIR_TEST_TXT_BLOCK[..2];
    let mut dec = Decoder::with_unpack_size(20);
    let _ = dec.decode(truncated, &mut []).unwrap();
    let mut buf = [0u8; 8];
    let err = dec.finish(&mut buf).unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "expected UnexpectedEnd or Corrupt, got {:?}",
        err
    );
}

#[test]
fn corrupt_input_does_not_panic() {
    // Random bytes that don't form a valid stream. We just check that the
    // decoder rejects them cleanly (some error) without panicking.
    let junk = [0xFFu8; 64];
    let mut dec = Decoder::with_unpack_size(64);
    let _ = dec.decode(&junk, &mut []).unwrap();
    let mut buf = [0u8; 64];
    let _ = dec.finish(&mut buf);
    // Any result (Ok or Err) is acceptable as long as it didn't panic.
}

// ─── reset ───────────────────────────────────────────────────────────────

#[test]
fn reset_clears_state_and_allows_redecode() {
    let mut dec = Decoder::with_unpack_size(TESTDIR_TEST_TXT_EXPECTED.len() as u64);
    let _ = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out1 = Vec::new();
    drain(&mut dec, &mut out1);
    assert_eq!(out1, TESTDIR_TEST_TXT_EXPECTED);

    dec.reset();
    let _ = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out2 = Vec::new();
    drain(&mut dec, &mut out2);
    assert_eq!(out2, TESTDIR_TEST_TXT_EXPECTED);
}

// ─── E8 filter (standalone, outside the RAR3 stream) ─────────────────────

#[test]
fn standalone_e8_filter_rewrites_calls() {
    // 14-byte buffer: a 0xE8 call at offset 4 with relative target +0x40.
    // After the filter (data_start = 0), the rewritten value should be
    // (rel - cur_pos) where cur_pos = 4 + 1 = 5 (the byte after the opcode).
    let mut data: [u8; 14] = [
        0x00, 0x11, 0x22, 0x33, 0xE8, 0x40, 0x00, 0x00, 0x00, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];
    apply_e8_filter(&mut data, 0, false);
    // rel = 0x40, cur = 5, new = 0x3B → 3B 00 00 00 LE
    assert_eq!(&data[5..9], &[0x3B, 0x00, 0x00, 0x00]);
    // Surrounding bytes preserved.
    assert_eq!(&data[..5], &[0x00, 0x11, 0x22, 0x33, 0xE8]);
    assert_eq!(&data[9..], &[0x55, 0x66, 0x77, 0x88, 0x99]);
}

#[test]
fn standalone_e9_filter_off_by_default() {
    let original: [u8; 14] = [
        0x00, 0x11, 0x22, 0x33, 0xE9, 0x40, 0x00, 0x00, 0x00, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];
    let mut data = original;
    apply_e8_filter(&mut data, 0, false);
    assert_eq!(data, original);
    // Same data with e9 translation on should rewrite.
    let mut data = original;
    apply_e8_filter(&mut data, 0, true);
    assert_eq!(&data[5..9], &[0x3B, 0x00, 0x00, 0x00]);
}

#[test]
fn decoder_with_e8_filter_round_trip_on_synthetic_data() {
    // We can't construct an arbitrary compressed RAR3 stream by hand here,
    // but we can verify the with_e8_filter constructor compiles and the
    // resulting decoder behaves like a normal decoder on a small fixture
    // that contains no 0xE8 / 0xE9 bytes (so the filter is a no-op).
    let mut dec =
        Decoder::with_unpack_size(TESTDIR_TEST_TXT_EXPECTED.len() as u64).with_e8_filter(true);
    let _ = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out = Vec::new();
    drain(&mut dec, &mut out);
    assert_eq!(out, TESTDIR_TEST_TXT_EXPECTED);
}

// ─── factory (only if compiled in) ───────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_rar3_decoder_and_encoder() {
        let enc = factory::encoder_by_name("rar3");
        let dec = factory::decoder_by_name("rar3");
        assert_eq!(enc.is_some(), dec.is_some());
    }
}
