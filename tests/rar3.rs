//! Integration tests for the RAR 3.x decoder.
//!
//! The decoder takes the raw bytes that follow a RAR3 file-header inside an
//! archive — it does not parse the surrounding container. Fixtures here
//! are the decompressed-block bytes lifted out of small libarchive test
//! archives (BSD-licensed), with the surrounding file/main headers
//! stripped. The expected outputs come from running `unrar p` against the
//! original `.rar` files. See `src/rar3/mod.rs` for the calling
//! convention.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.

#![cfg(feature = "rar3")]

use compcol::rar3::{Decoder, Encoder, Rar3, apply_e8_filter};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── helpers ──────────────────────────────────────────────────────────────

/// Drain `Decoder::finish` until `StreamEnd` (or no further progress).
fn drain(dec: &mut Decoder, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap_or_else(|e| {
            panic!("finish failed: {e:?}");
        });
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
}

/// Decode a full RAR3 raw block in one shot: feed all input via `decode`,
/// then drain via `finish`.
fn decode_full(input: &[u8], unpack_size: u64) -> Vec<u8> {
    let mut dec = Decoder::with_unpack_size(unpack_size);
    let (_p, _status) = dec.decode(input, &mut []).unwrap();
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
fn rar3_algorithm_factory_produces_codec() {
    let _enc = <Rar3 as Algorithm>::encoder();
    let _dec = <Rar3 as Algorithm>::decoder();
}

// ─── encoder is permanently unsupported ──────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        enc.encode(b"hello", &mut out).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn encoder_reset_is_a_no_op() {
    // Encoder is stateless; reset must not panic.
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

// ─── empty stream ────────────────────────────────────────────────────────

#[test]
fn unpack_size_zero_decodes_to_empty() {
    let out = decode_full(&[], 0);
    assert!(out.is_empty());
}

#[test]
fn finish_on_fresh_decoder_with_zero_unpack_returns_stream_end() {
    // unpack_size 0 ⇒ trivially Done after the first finish.
    let mut dec = Decoder::with_unpack_size(0);
    let mut buf = [0u8; 8];
    let (p, status) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert!(
        matches!(status, Status::StreamEnd),
        "expected StreamEnd on empty finish, got {status:?}",
    );
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
        let (p, status) = dec.decode(chunk, &mut []).unwrap();
        assert_eq!(p.consumed, chunk.len());
        // After feeding input fully and asking for no output, the decoder
        // is still buffering — InputEmpty is the expected status.
        assert!(
            matches!(status, Status::InputEmpty),
            "expected InputEmpty after feeding 1 byte, got {status:?}",
        );
    }
    let mut out = Vec::new();
    drain(&mut dec, &mut out);
    assert_eq!(out, TESTDIR_TEST_TXT_EXPECTED);
}

#[test]
fn decodes_libarchive_test_txt_tight_output_buffer() {
    let mut dec = Decoder::with_unpack_size(TESTDIR_TEST_TXT_EXPECTED.len() as u64);
    let (_p, _status) = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out: Vec<u8> = Vec::new();
    // Drain through a 3-byte output buffer.
    let mut buf = [0u8; 3];
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    assert_eq!(out, TESTDIR_TEST_TXT_EXPECTED);
}

// ─── PPMd continuation without a live model ──────────────────────────────

#[test]
fn ppmd_continuation_without_model_is_corrupt() {
    // Top bit set ⇒ PPMd block; the next 7 flag bits are 0, so flag 0x20
    // (fresh model + memory/order) is clear. That marks a continuation
    // reusing a live model from an earlier block or solid member — which a
    // standalone first block can't have, so the stream is malformed. (A
    // real, self-contained PPMd block decodes — see `ppmd_block_decodes`;
    // a real continuation across a solid group decodes — see the solid
    // fixtures.)
    let ppmd_marker = [0x80u8, 0x00, 0x00, 0x00];
    let mut dec = Decoder::with_unpack_size(32);
    let (_p, _status) = dec.decode(&ppmd_marker, &mut []).unwrap();
    let mut buf = [0u8; 16];
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

// ─── error path: malformed inputs ────────────────────────────────────────

#[test]
fn truncated_input_fails_with_unexpected_end_or_corrupt() {
    // First two bytes of a real fixture won't have enough state to build the
    // precode, so finish() should return UnexpectedEnd (or Corrupt if the
    // partial bits decode to something invalid first).
    let truncated = &TESTDIR_TEST_TXT_BLOCK[..2];
    let mut dec = Decoder::with_unpack_size(20);
    let (_p, _status) = dec.decode(truncated, &mut []).unwrap();
    let mut buf = [0u8; 8];
    let err = dec.finish(&mut buf).unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "expected UnexpectedEnd or Corrupt, got {err:?}",
    );
}

#[test]
fn corrupt_input_does_not_panic() {
    // Random bytes that don't form a valid stream. We just check that the
    // decoder rejects them cleanly (some error) without panicking.
    let junk = [0xFFu8; 64];
    let mut dec = Decoder::with_unpack_size(64);
    let (_p, _status) = dec.decode(&junk, &mut []).unwrap();
    let mut buf = [0u8; 64];
    let _ = dec.finish(&mut buf);
    // Any result (Ok or Err) is acceptable as long as it didn't panic.
}

// ─── reset ───────────────────────────────────────────────────────────────

#[test]
fn reset_clears_state_and_allows_redecode() {
    let mut dec = Decoder::with_unpack_size(TESTDIR_TEST_TXT_EXPECTED.len() as u64);
    let (_p, _status) = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out1 = Vec::new();
    drain(&mut dec, &mut out1);
    assert_eq!(out1, TESTDIR_TEST_TXT_EXPECTED);

    dec.reset();
    let (_p, _status) = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
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
    let (_p, _status) = dec.decode(TESTDIR_TEST_TXT_BLOCK, &mut []).unwrap();
    let mut out = Vec::new();
    drain(&mut dec, &mut out);
    assert_eq!(out, TESTDIR_TEST_TXT_EXPECTED);
}

// ─── In-band standard filters (real-archive fixtures) ────────────────────
//
// Payloads lifted out of archives created with RARLAB `rar` 6.24 (the last
// encoder able to write RAR4) over synthetic content: the fixture bytes are
// exactly what follows the RAR4 file header. The expected CRC-32 is the
// archive's own FILE_CRC header field (CRC-32 of the uncompressed file,
// written by the encoder); extraction was additionally cross-checked
// byte-identical against WinRAR `UnRAR.exe` 7.23 by the differential
// harness. Each stream opens with a main-symbol-257 declaration carrying a
// standard RarVM program that the decoder must recognize and run natively.

/// gradient.bmp — Delta filter, 3 channels, window 49152 of 49206 bytes.
static FILTER_DELTA_BMP: &[u8] = include_bytes!("fixtures/rar3/filter_delta_gradient_bmp.bin");
/// ramp.wav — Delta filter, 2 channels (rar 6.24 uses Delta for WAV, not
/// the legacy audio predictor), window 16384 of 16428 bytes.
static FILTER_DELTA_WAV: &[u8] = include_bytes!("fixtures/rar3/filter_delta_ramp_wav.bin");
/// calls.bin at -m5 — Delta filter, 12 channels.
static FILTER_DELTA12_CALLS: &[u8] = include_bytes!("fixtures/rar3/m5_calls_delta12.bin");
/// x86slice.bin — x86 E8 (call-only) filter over the whole 32 KiB.
static FILTER_X86_SLICE: &[u8] = include_bytes!("fixtures/rar3/filter_x86_slice.bin");

/// Bitwise CRC-32 (IEEE, reflected 0xEDB88320) — small and table-free;
/// test-only, so speed is irrelevant.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn decode_and_check_crc(block: &[u8], unpack_size: u64, want_crc: u32) -> Vec<u8> {
    let out = decode_full(block, unpack_size);
    assert_eq!(out.len() as u64, unpack_size, "unpacked size mismatch");
    assert_eq!(
        crc32(&out),
        want_crc,
        "decoded bytes differ from the archive's FILE_CRC"
    );
    out
}

#[test]
fn inband_delta_filter_bmp_three_channels() {
    let out = decode_and_check_crc(FILTER_DELTA_BMP, 49206, 0x2347_E5ED);
    // Spot-check: it really is the bitmap (BMP magic survives filtering).
    assert_eq!(&out[..2], b"BM");
}

#[test]
fn inband_delta_filter_wav_two_channels() {
    let out = decode_and_check_crc(FILTER_DELTA_WAV, 16428, 0x0E8F_2810);
    assert_eq!(&out[..4], b"RIFF");
}

#[test]
fn inband_delta_filter_twelve_channels() {
    decode_and_check_crc(FILTER_DELTA12_CALLS, 6146, 0x6C08_D7DF);
}

#[test]
fn inband_x86_e8_filter() {
    decode_and_check_crc(FILTER_X86_SLICE, 32768, 0x6188_0029);
}

/// A stream that declares a filter window it never finishes producing is
/// malformed: returning the raw pre-filter bytes as a success would be
/// wrong output. (unrar emits the raw bytes and relies on the container
/// CRC to flag the file; this crate surfaces the error directly.)
#[test]
fn unfinished_filter_window_is_corrupt() {
    // The delta fixture declares a 49152-byte window up front; capping the
    // unpack size below that truncates the window.
    let mut dec = Decoder::with_unpack_size(1000);
    let (_p, _s) = dec.decode(FILTER_DELTA_BMP, &mut []).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(dec.finish(&mut buf).unwrap_err(), Error::Corrupt);
}

// ─── PPMd-II variant H block (real-archive fixture) ──────────────────────
//
// The raw v29 payload of `notes.txt` from a `rar 6.24 -mct+` (forced
// text/PPMd) archive — a self-contained PPMd block (bit-0 of the block
// header set) that decodes to 20001 bytes. Expected CRC-32 is the archive's
// own FILE_CRC; extraction was cross-checked byte-identical against UnRAR
// 7.23. This exercises the RAR range decoder plus the full PPMII model
// (context tree, escapes, SEE, rescale) through the rar3 entry point.
static PPMD_NOTES: &[u8] = include_bytes!("fixtures/rar3/ppmd_notes.bin");

#[test]
fn ppmd_block_decodes() {
    decode_and_check_crc(PPMD_NOTES, 20001, 0x0E1A_EC07);
}

/// A truncated PPMd payload must fail, not fabricate output. Once the range
/// coder reads past the end of the compressed block, `read_byte` supplies
/// zeroes and every further symbol is invented; without an overrun check the
/// decoder would still reach the declared 20001-byte size (with a wrong CRC)
/// and report success. Dropping the tail bytes must surface an error instead.
#[test]
fn ppmd_truncated_payload_errors_not_fabricates() {
    let truncated = &PPMD_NOTES[..PPMD_NOTES.len() - 14];
    let mut dec = Decoder::with_unpack_size(20001);
    // Buffer-then-decode: the failure surfaces on the first finish/drain.
    let _ = dec.decode(truncated, &mut []);
    let mut buf = [0u8; 4096];
    let mut err = None;
    let mut produced = 0usize;
    loop {
        match dec.finish(&mut buf) {
            Ok((p, status)) => {
                produced += p.written;
                if matches!(status, Status::StreamEnd) || p.written == 0 {
                    break;
                }
            }
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    assert!(
        matches!(err, Some(Error::UnexpectedEnd) | Some(Error::Corrupt)),
        "truncated PPMd should error (got err={err:?}, produced={produced} bytes)"
    );
}

// ─── Solid groups (real-archive fixtures) ─────────────────────────────────
//
// Raw v29 member payloads of `rar4_m3_solid.rar` and `rar4_ppmd_solid.rar`
// (RARLAB `rar 6.24 -s`), in archive order. Members of a solid group share
// one compression history: the LZ window, code tables, offset history,
// filter programs and any live PPMd model carry from member to member,
// while each payload is its own byte-aligned stream. Expected CRC-32s are
// the archives' own FILE_CRC fields; extraction was cross-checked
// byte-identical against UnRAR 7.23 by the differential harness.
//
// The m3 group exercises every member-boundary shape rar 6.24 emits:
// members that open with their own block header (fresh or `keep_table`
// delta-coded), members that continue the previous member's stream with no
// header at all (photo.jpg, ramp.wav — announced by the previous member's
// end marker), in-band filters inside a solid stream, and LZ matches
// reaching across member boundaries. The PPMd group exercises model
// persistence: prose.txt's header has no reset flag and reuses notes.txt's
// live model (with a freshly initialised range coder).

/// (payload, unpacked size, FILE_CRC) for each member, in archive order.
static SOLID_M3_GROUP: &[(&[u8], u64, u32)] = &[
    (
        include_bytes!("fixtures/rar3/solid_m3_calls.bin"),
        6146,
        0x6C08_D7DF,
    ),
    (
        include_bytes!("fixtures/rar3/solid_m3_x86slice.bin"),
        32768,
        0x6188_0029,
    ),
    (
        include_bytes!("fixtures/rar3/solid_m3_gradient.bin"),
        49206,
        0x2347_E5ED,
    ),
    (
        include_bytes!("fixtures/rar3/solid_m3_photo.bin"),
        8198,
        0x8420_E285,
    ),
    (
        include_bytes!("fixtures/rar3/solid_m3_notes.bin"),
        20001,
        0x0E1A_EC07,
    ),
    (
        include_bytes!("fixtures/rar3/solid_m3_ramp.bin"),
        16428,
        0x0E8F_2810,
    ),
];

/// prose.txt — the second member of `rar4_ppmd_solid.rar`; its first member
/// is the same payload as `PPMD_NOTES`.
static SOLID_PPMD_PROSE: &[u8] = include_bytes!("fixtures/rar3/solid_ppmd_prose.bin");

/// Decode a whole solid group member-by-member, asserting each member's
/// size and FILE_CRC.
fn decode_solid_group(members: &[(&[u8], u64, u32)]) {
    let mut dec = Decoder::with_unpack_size(members[0].1).with_solid();
    for (i, &(payload, unp, want_crc)) in members.iter().enumerate() {
        if i > 0 {
            dec.begin_solid_member(unp).unwrap();
        }
        let (_p, _s) = dec.decode(payload, &mut []).unwrap();
        let mut out = Vec::with_capacity(unp as usize);
        drain(&mut dec, &mut out);
        assert_eq!(out.len() as u64, unp, "member {i}: unpacked size mismatch");
        assert_eq!(
            crc32(&out),
            want_crc,
            "member {i}: decoded bytes differ from the archive's FILE_CRC"
        );
    }
}

#[test]
fn solid_lz_group_decodes() {
    decode_solid_group(SOLID_M3_GROUP);
}

#[test]
fn solid_ppmd_group_decodes() {
    decode_solid_group(&[
        (PPMD_NOTES, 20001, 0x0E1A_EC07),
        (SOLID_PPMD_PROSE, 236737, 0x028E_1AC1),
    ]);
}

/// Feeding a solid continuation without its group head must fail closed:
/// prose.txt's block header reuses a live PPMd model that a fresh decoder
/// doesn't have.
#[test]
fn solid_ppmd_continuation_without_head_fails() {
    let mut dec = Decoder::with_unpack_size(236737).with_solid();
    let (_p, _s) = dec.decode(SOLID_PPMD_PROSE, &mut []).unwrap();
    let mut buf = [0u8; 4096];
    assert_eq!(dec.finish(&mut buf).unwrap_err(), Error::Corrupt);
}

/// A truncated member inside a solid group is a hard error — the shared
/// history would silently desync every member after it.
#[test]
fn solid_truncated_member_poisons_group() {
    let mut dec = Decoder::with_unpack_size(6146).with_solid();
    let head = SOLID_M3_GROUP[0].0;
    let (_p, _s) = dec.decode(&head[..head.len() / 2], &mut []).unwrap();
    let mut buf = [0u8; 4096];
    assert!(matches!(
        dec.finish(&mut buf).unwrap_err(),
        Error::UnexpectedEnd | Error::Corrupt
    ));
    // The group is poisoned: the next member can't be started.
    assert!(dec.begin_solid_member(32768).is_err());
}

/// `begin_solid_member` is only valid on a solid decoder whose current
/// member has fully drained.
#[test]
fn begin_solid_member_misuse_is_rejected() {
    // Not a solid decoder.
    let mut dec = Decoder::with_unpack_size(4);
    assert_eq!(dec.begin_solid_member(4).unwrap_err(), Error::Unsupported);
    // Solid, but the current member hasn't been decoded yet.
    let mut dec = Decoder::with_unpack_size(6146).with_solid();
    assert_eq!(dec.begin_solid_member(4).unwrap_err(), Error::Unsupported);
}

// ─── factory (only if compiled in) ───────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Error;
    use compcol::factory;

    #[test]
    fn lookup_rar3_encoder_and_decoder() {
        assert!(factory::encoder_by_name("rar3").is_some());
        assert!(factory::decoder_by_name("rar3").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-rar3").is_none());
        assert!(factory::decoder_by_name("not-a-real-rar3").is_none());
    }

    #[test]
    fn names_contains_rar3() {
        assert!(factory::names().contains(&"rar3"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        let mut enc = factory::encoder_by_name("rar3").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }
}
