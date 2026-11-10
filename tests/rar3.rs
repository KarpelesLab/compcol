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

// ─── regression: low-distance repeat state must reset per LZ block ──────

/// The 490-byte packed run of `lowdist-reset.bin` from libarchive's
/// `test_read_format_rar3_lowdist_reset.rar` (method 0x35, version 29,
/// not solid, 64 bytes unpacked, FILE_CRC 0x6FF838DC).
///
/// As with the other libarchive-derived fixtures here, these bytes are the
/// output of an unrelated proprietary encoder rather than any part of
/// libarchive's own source, and the file's stored CRC is what the
/// assertion below checks against — the expected plaintext is a property of
/// the archive, not of libarchive's reader.
///
/// The archive packs its member as two LZ blocks. The second block's header
/// starts a new table domain, but `parse_block_header` used to carry
/// `last_low_offset` / `num_low_offset_repeats` across it, so the first
/// low-distance match after the boundary added a stale addend and every
/// byte from offset 46 on was wrong — decoding to the right *length* with
/// the wrong *contents*, which is exactly the failure mode a length check
/// can't catch. Reported as #126.
static LOWDIST_RESET: &[u8] = include_bytes!("fixtures/rar3/lowdist_reset.bin");

const LOWDIST_RESET_UNPACK: u64 = 64;
const LOWDIST_RESET_CRC: u32 = 0x6FF8_38DC;

#[rustfmt::skip]
const LOWDIST_RESET_EXPECTED: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0d, 0x0e,
    0x0f, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
];

#[test]
fn lowdist_repeat_state_resets_across_lz_blocks() {
    let out = decode_full(LOWDIST_RESET, LOWDIST_RESET_UNPACK);
    assert_eq!(out.len() as u64, LOWDIST_RESET_UNPACK);
    assert_eq!(
        out, LOWDIST_RESET_EXPECTED,
        "decoded bytes diverge from the archive's contents"
    );
    // The archive's own FILE_CRC is the ground truth here: it is what makes
    // the expected bytes above verifiable independently of any other reader.
    assert_eq!(
        crc32(&out),
        LOWDIST_RESET_CRC,
        "decoded bytes don't match the archive's stored FILE_CRC"
    );
}

/// The same stream fed one byte at a time — the block boundary that carries
/// the low-distance reset then lands mid-call, so this covers the resumable
/// path as well as the single-shot one.
#[test]
fn lowdist_repeat_state_resets_when_fed_bytewise() {
    let mut dec = Decoder::with_unpack_size(LOWDIST_RESET_UNPACK);
    for chunk in LOWDIST_RESET.chunks(1) {
        dec.decode(chunk, &mut []).unwrap();
    }
    let mut out = Vec::with_capacity(LOWDIST_RESET_UNPACK as usize);
    drain(&mut dec, &mut out);
    assert_eq!(crc32(&out), LOWDIST_RESET_CRC);
    assert_eq!(out, LOWDIST_RESET_EXPECTED);
}

// ─── Streaming output, output limit, filter-work bound ───────────────────
//
// The fixtures above are all far smaller than the 4 MiB dictionary, so the
// properties below need streams this file builds itself: a minimal RAR3 LZ
// block (hand-assembled code tables over a tiny alphabet) that expands to
// many MiB from a few KiB.

/// MSB-first bit writer.
struct BitW {
    bytes: Vec<u8>,
    nbits: u32,
}

impl BitW {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            nbits: 0,
        }
    }
    fn push(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            if self.nbits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let last = self.bytes.len() - 1;
            self.bytes[last] |= (((value >> i) & 1) as u8) << (7 - (self.nbits % 8));
            self.nbits += 1;
        }
    }
    /// RarVM variable-length number, shortest form.
    fn push_vm(&mut self, v: u32) {
        if v < 16 {
            self.push(0, 2);
            self.push(v, 4);
        } else if v < 256 {
            self.push(1, 2);
            self.push(v, 8);
        } else if v < 0x1_0000 {
            self.push(2, 2);
            self.push(v, 16);
        } else {
            self.push(3, 2);
            self.push(v, 32);
        }
    }
}

/// The 29-byte standard Delta program as rar 6.24 emits it (lifted from
/// `filter_delta_gradient_bmp.bin`; byte 0 is the XOR checksum).
const DELTA_PROG: [u8; 29] = [
    0x2F, 0x01, 0x9A, 0x41, 0x80, 0xEC, 0x27, 0x48, 0x2F, 0x09, 0x76, 0x6D, 0xD3, 0xEA, 0x41, 0x5B,
    0x59, 0x44, 0xE8, 0x17, 0x5C, 0xE1, 0x6C, 0x91, 0x4C, 0x4E, 0x3F, 0x77, 0x00,
];

/// One step of a synthetic LZ stream.
#[derive(Clone, Copy)]
enum Op {
    /// A literal; must be one of [`SYN_LITERALS`].
    Lit(u8),
    /// A 258-byte match at distance 1 (repeats the previous byte).
    Run,
    /// Main symbol 258: repeat the last match (needs a prior `Run`).
    Rep,
    /// A Delta filter declaration over `[pos + start, pos + start + len)`.
    Delta { start: u32, len: u32, channels: u32 },
}

const SYN_LITERALS: [u8; 4] = [0x00, 0x01, 0x41, 0xE8];

/// What a synthetic stream decodes to.
struct Synthetic {
    stream: Vec<u8>,
    /// Output before any filter runs.
    raw: Vec<u8>,
    /// Declared filter windows `(start, len, channels)`, in order.
    filters: Vec<(usize, usize, usize)>,
}

impl Synthetic {
    /// Expected output: the declared Delta filters applied in order.
    fn filtered(&self) -> Vec<u8> {
        let mut out = self.raw.clone();
        for &(start, len, channels) in &self.filters {
            let src = out[start..start + len].to_vec();
            let mut sp = 0;
            for ch in 0..channels {
                let mut prev = 0u8;
                let mut i = ch;
                while i < len {
                    prev = prev.wrapping_sub(src[sp]);
                    out[start + i] = prev;
                    sp += 1;
                    i += channels;
                }
            }
        }
        out
    }
}

/// Assemble a single-block RAR3 LZ stream running `ops`, ending with the
/// end-of-data marker.
fn build_lz_stream(ops: &[Op]) -> Synthetic {
    build_lz_block(ops, false)
}

/// Assemble a RAR3 LZ block running `ops`. It ends with the end-of-data
/// marker, or — with `then_new_table` — with the "new tables follow"
/// marker, after which the caller appends the next block's header.
///
/// Main code: eight 3-bit symbols — the four literals, 256 (end), 257
/// (filter), 258 (repeat match), 298 (longest length slot); canonical codes
/// are assigned in symbol order. Offset code: symbols 0 and 1, one bit each.
fn build_lz_block(ops: &[Op], then_new_table: bool) -> Synthetic {
    const MAIN: [usize; 8] = [0x00, 0x01, 0x41, 0xE8, 256, 257, 258, 298];
    let main_code = |sym: usize| MAIN.iter().position(|&s| s == sym).unwrap() as u32;

    let mut lengths = [0u8; 299 + 60 + 17 + 28];
    for &s in &MAIN {
        lengths[s] = 3;
    }
    lengths[299] = 1;
    lengths[300] = 1;

    let mut w = BitW::new();
    w.push(0, 1); // LZ block
    w.push(0, 1); // fresh tables
    // Precode: symbols 0, 1, 3 and 19 with 2-bit codes (00, 01, 10, 11).
    for sym in 0..20 {
        w.push(if matches!(sym, 0 | 1 | 3 | 19) { 2 } else { 0 }, 4);
    }
    let mut i = 0;
    while i < lengths.len() {
        match lengths[i] {
            0 => {
                let run = lengths[i..].iter().take_while(|&&l| l == 0).count();
                if run >= 11 {
                    let n = run.min(138);
                    w.push(0b11, 2);
                    w.push(n as u32 - 11, 7);
                    i += n;
                } else {
                    w.push(0b00, 2);
                    i += 1;
                }
            }
            1 => {
                w.push(0b01, 2);
                i += 1;
            }
            _ => {
                w.push(0b10, 2);
                i += 1;
            }
        }
    }

    let mut raw: Vec<u8> = Vec::new();
    let mut filters = Vec::new();
    let mut program_declared = false;
    for &op in ops {
        match op {
            Op::Lit(b) => {
                assert!(SYN_LITERALS.contains(&b));
                w.push(main_code(b as usize), 3);
                raw.push(b);
            }
            Op::Run => {
                w.push(main_code(298), 3);
                w.push(31, 5); // length slot 27: 224 + 3 + 31 = 258
                w.push(0, 1); // offset symbol 0: distance 1
                let b = raw.last().copied().unwrap_or(0);
                raw.resize(raw.len() + 258, b);
            }
            Op::Rep => {
                w.push(main_code(258), 3);
                let b = raw.last().copied().unwrap_or(0);
                raw.resize(raw.len() + 258, b);
            }
            Op::Delta {
                start,
                len,
                channels,
            } => {
                let mut p = BitW::new();
                let mut flags = 0x30; // explicit length + registers
                if !program_declared {
                    flags |= 0x80;
                    p.push_vm(0); // reset, slot 0
                }
                p.push_vm(start);
                p.push_vm(len);
                p.push(0x01, 7); // register mask: r0
                p.push_vm(channels);
                if !program_declared {
                    p.push_vm(DELTA_PROG.len() as u32);
                    for &b in &DELTA_PROG {
                        p.push(b as u32, 8);
                    }
                    program_declared = true;
                }
                w.push(main_code(257), 3);
                let n = p.bytes.len() as u32;
                if n <= 6 {
                    w.push(flags | (n - 1), 8);
                } else {
                    w.push(flags | 6, 8);
                    w.push(n - 7, 8);
                }
                for &b in &p.bytes {
                    w.push(b as u32, 8);
                }
                filters.push((raw.len() + start as usize, len as usize, channels as usize));
            }
        }
    }
    w.push(main_code(256), 3);
    if then_new_table {
        w.push(1, 1); // the next block's header follows, byte-aligned
    } else {
        w.push(0, 2); // no new table; next member starts with its own header
    }
    Synthetic {
        stream: w.bytes,
        raw,
        filters,
    }
}

/// `blocks` repetitions of "a literal, then `reps + 1` 258-byte runs of it".
fn run_ops(blocks: usize, reps: usize) -> Vec<Op> {
    let mut ops = Vec::new();
    for b in 0..blocks {
        ops.push(Op::Lit(SYN_LITERALS[(b * 7 + b / 3) % 4]));
        ops.push(Op::Run);
        ops.extend(std::iter::repeat_n(Op::Rep, reps));
    }
    ops
}

/// Feed `input` in `in_chunk`-byte pieces, then drain through an
/// `out_chunk`-byte buffer. Returns the bytes delivered, the terminal error
/// if any, and the largest [`Decoder::buffered_output`] seen between calls.
fn decode_chunked(
    mut dec: Decoder,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> (Vec<u8>, Option<Error>, usize) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut peak = 0;
    for chunk in input.chunks(in_chunk.clamp(1, input.len().max(1))) {
        let mut off = 0;
        while off < chunk.len() {
            match dec.decode(&chunk[off..], &mut buf) {
                Ok((p, _)) => {
                    off += p.consumed;
                    out.extend_from_slice(&buf[..p.written]);
                    assert!(p.consumed + p.written > 0, "decode made no progress");
                }
                Err(e) => return (out, Some(e), peak),
            }
            peak = peak.max(dec.buffered_output());
        }
    }
    loop {
        match dec.finish(&mut buf) {
            Ok((p, status)) => {
                out.extend_from_slice(&buf[..p.written]);
                peak = peak.max(dec.buffered_output());
                if matches!(status, Status::StreamEnd) {
                    return (out, None, peak);
                }
                assert!(p.written > 0, "finish made no progress");
            }
            Err(e) => return (out, Some(e), peak),
        }
    }
}

/// Every non-solid fixture with its declared size and FILE_CRC.
fn single_fixtures() -> Vec<(&'static [u8], u64, u32)> {
    vec![
        (
            TESTDIR_TEST_TXT_BLOCK,
            TESTDIR_TEST_TXT_EXPECTED.len() as u64,
            crc32(TESTDIR_TEST_TXT_EXPECTED),
        ),
        (FILTER_DELTA_BMP, 49206, 0x2347_E5ED),
        (FILTER_DELTA_WAV, 16428, 0x0E8F_2810),
        (FILTER_DELTA12_CALLS, 6146, 0x6C08_D7DF),
        (FILTER_X86_SLICE, 32768, 0x6188_0029),
        (PPMD_NOTES, 20001, 0x0E1A_EC07),
        (LOWDIST_RESET, LOWDIST_RESET_UNPACK, LOWDIST_RESET_CRC),
    ]
}

/// One-shot, 1-byte input and 1-byte output decodes of every fixture are
/// byte-identical (and match the archive's FILE_CRC).
#[test]
fn chunking_differential_on_every_fixture() {
    for (i, (block, unp, crc)) in single_fixtures().into_iter().enumerate() {
        let shapes = [(usize::MAX, 1 << 16), (1, 1 << 16), (usize::MAX, 1), (1, 1)];
        for (in_chunk, out_chunk) in shapes {
            let (out, err, _) =
                decode_chunked(Decoder::with_unpack_size(unp), block, in_chunk, out_chunk);
            assert_eq!(err, None, "fixture {i} ({in_chunk}/{out_chunk})");
            assert_eq!(
                out.len() as u64,
                unp,
                "fixture {i} ({in_chunk}/{out_chunk})"
            );
            assert_eq!(crc32(&out), crc, "fixture {i} ({in_chunk}/{out_chunk})");
        }
    }
}

/// The same differential over the solid groups, member by member.
#[test]
fn chunking_differential_on_solid_groups() {
    let ppmd_group: &[(&[u8], u64, u32)] = &[
        (PPMD_NOTES, 20001, 0x0E1A_EC07),
        (SOLID_PPMD_PROSE, 236737, 0x028E_1AC1),
    ];
    for group in [SOLID_M3_GROUP, ppmd_group] {
        for (in_chunk, out_chunk) in [(1usize, 1usize << 16), (usize::MAX, 1), (3, 5)] {
            let mut dec = Decoder::with_unpack_size(group[0].1).with_solid();
            for (i, &(payload, unp, want_crc)) in group.iter().enumerate() {
                if i > 0 {
                    dec.begin_solid_member(unp).unwrap();
                }
                let mut out = Vec::new();
                let mut buf = vec![0u8; out_chunk];
                for chunk in payload.chunks(in_chunk.min(payload.len())) {
                    let (p, _) = dec.decode(chunk, &mut buf).unwrap();
                    assert_eq!(p.consumed, chunk.len());
                    out.extend_from_slice(&buf[..p.written]);
                }
                loop {
                    let (p, status) = dec.finish(&mut buf).unwrap();
                    out.extend_from_slice(&buf[..p.written]);
                    if matches!(status, Status::StreamEnd) {
                        break;
                    }
                    assert!(p.written > 0);
                }
                assert_eq!(out.len() as u64, unp, "member {i}");
                assert_eq!(crc32(&out), want_crc, "member {i}");
            }
        }
    }
}

/// Truncated non-solid streams keep their behaviour whatever the chunking:
/// the same bytes come out and the same verdict (short output or an error)
/// is reached with 1-byte buffers as with a one-shot decode.
#[test]
fn chunking_differential_on_truncated_fixtures() {
    for (i, (block, unp, _)) in single_fixtures().into_iter().enumerate() {
        for cut in [block.len() / 4, block.len() / 2, block.len() - 3] {
            let cut = &block[..cut];
            let one = decode_chunked(Decoder::with_unpack_size(unp), cut, usize::MAX, 4096);
            let byte = decode_chunked(Decoder::with_unpack_size(unp), cut, 1, 1);
            assert_eq!(one.0, byte.0, "fixture {i} cut {}", cut.len());
            assert_eq!(one.1, byte.1, "fixture {i} cut {}", cut.len());
            assert!(one.0.len() as u64 <= unp);
        }
    }
}

/// Corrupted streams reach the same verdict, with the same bytes delivered
/// first, whatever the chunking (and never panic).
#[test]
fn chunking_differential_on_corrupted_fixtures() {
    let mut seed = 0x9E37_79B9u32;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for (i, (block, unp, _)) in single_fixtures().into_iter().enumerate() {
        for round in 0..12 {
            let mut bad = block.to_vec();
            for _ in 0..1 + round % 3 {
                let at = next() as usize % bad.len();
                bad[at] ^= 1 << (next() % 8);
            }
            let one = decode_chunked(Decoder::with_unpack_size(unp), &bad, usize::MAX, 4096);
            let small = decode_chunked(Decoder::with_unpack_size(unp), &bad, 5, 3);
            assert!(one.0 == small.0, "fixture {i} round {round}: bytes differ");
            assert_eq!(one.1, small.1, "fixture {i} round {round}");
        }
    }
}

/// A truncated LZ stream (non-solid) still hands back the bytes decoded
/// before the input ran out, as a short success.
#[test]
fn truncated_lz_stream_returns_short_output() {
    let syn = build_lz_stream(&run_ops(40, 3));
    let cut = &syn.stream[..syn.stream.len() - 20];
    let (out, err, _) = decode_chunked(Decoder::new(), cut, usize::MAX, 4096);
    assert_eq!(err, None);
    assert!(!out.is_empty() && out.len() < syn.raw.len());
    assert_eq!(out, syn.raw[..out.len()]);
}

/// The synthetic builder agrees with the decoder on a small stream,
/// filters included.
#[test]
fn synthetic_stream_decodes() {
    let mut ops = vec![Op::Delta {
        start: 0,
        len: 3000,
        channels: 3,
    }];
    ops.extend(run_ops(20, 2));
    let syn = build_lz_stream(&ops);
    assert_eq!(
        decode_full(&syn.stream, syn.raw.len() as u64),
        syn.filtered()
    );
    // Without a declared size the end marker stops the decode.
    let (out, err, _) = decode_chunked(Decoder::new(), &syn.stream, 7, 13);
    assert_eq!(err, None);
    assert_eq!(out, syn.filtered());
}

/// Largest amount of output the decoder may hold: the 4 MiB dictionary's
/// worth it lags behind by, plus a filter window's worth of slack.
const BUFFERED_OUTPUT_BOUND: usize = (4 << 20) + (512 << 10);

/// Output buffering is bounded by the dictionary, not by the unpacked
/// size: a ~13 MiB stream never has more than ~4.5 MiB waiting inside the
/// decoder, whatever buffer it is drained through.
#[test]
fn streaming_output_buffering_is_bounded() {
    let syn = build_lz_stream(&run_ops(500, 99));
    assert!(syn.raw.len() > 12 << 20);
    for out_chunk in [1 << 16, 4099] {
        let (out, err, peak) = decode_chunked(
            Decoder::with_unpack_size(syn.raw.len() as u64),
            &syn.stream,
            usize::MAX,
            out_chunk,
        );
        assert_eq!(err, None);
        assert!(out == syn.raw, "output differs (drained by {out_chunk})");
        assert!(
            peak <= BUFFERED_OUTPUT_BOUND,
            "{peak} bytes buffered for a {} byte stream",
            syn.raw.len()
        );
    }
}

/// Filters whose windows sit anywhere relative to the points where the
/// decoder releases output — including straddling them — are applied
/// exactly once, in a stream several dictionaries long, with the standalone
/// E8 pass on top.
#[test]
fn streaming_applies_filters_across_release_points() {
    let mut ops = Vec::new();
    let mut produced = 0usize;
    let mut block = 0usize;
    while produced < 9 << 20 {
        // A filter every ~77 KiB over windows of 1..121 KiB, some starting
        // a little ahead of the current position: neighbours overlap (and
        // must then apply in declaration order), and whichever windows are
        // open when the decoder releases output hold part of it back.
        let ahead = (block * 977) % 5000;
        let len = 1000 + (block * 7919) % 120_000;
        ops.push(Op::Delta {
            start: ahead as u32,
            len: len as u32,
            channels: 1 + (block % 5) as u32,
        });
        ops.extend(run_ops(6, 49));
        produced += 6 * (1 + 50 * 258);
        block += 1;
    }
    // Enough tail for the last window to complete.
    ops.extend(run_ops(12, 49));
    let syn = build_lz_stream(&ops);
    let want = syn.filtered();
    for out_chunk in [1 << 16, 7919] {
        let (out, err, peak) = decode_chunked(
            Decoder::with_unpack_size(syn.raw.len() as u64),
            &syn.stream,
            usize::MAX,
            out_chunk,
        );
        assert_eq!(err, None);
        assert!(
            out == want,
            "filtered output differs (drained by {out_chunk})"
        );
        assert!(peak <= BUFFERED_OUTPUT_BOUND, "{peak} bytes buffered");
    }

    let mut want_e8 = want.clone();
    apply_e8_filter(&mut want_e8, 0, true);
    assert!(want_e8 != want, "the stream should contain E8 call sites");
    let (out, err, _) = decode_chunked(
        Decoder::with_unpack_size(syn.raw.len() as u64).with_e8_filter(true),
        &syn.stream,
        usize::MAX,
        50_001,
    );
    assert_eq!(err, None);
    assert!(
        out == want_e8,
        "E8 post-pass differs from the one-shot filter"
    );
}

/// With an output limit the decoder refuses a stream that decodes to more,
/// before building the excess: a ~13 MiB bomb under a 1 KiB cap fails with
/// at most 1 KiB ever buffered.
#[test]
fn output_limit_refuses_lz_bomb_before_building_it() {
    use compcol::limit::LimitedDecoder;
    let syn = build_lz_stream(&run_ops(500, 99));
    for declared in [u64::MAX, syn.raw.len() as u64] {
        let mut dec = LimitedDecoder::new(Decoder::with_unpack_size(declared), 1024);
        dec.decode(&syn.stream, &mut []).unwrap();
        let mut buf = [0u8; 4096];
        let mut delivered = 0usize;
        let err = loop {
            match dec.finish(&mut buf) {
                Ok((p, status)) => {
                    delivered += p.written;
                    assert!(dec.get_ref().buffered_output() <= 1024);
                    assert!(!matches!(status, Status::StreamEnd), "bomb decoded");
                    assert!(p.written > 0);
                }
                Err(e) => break e,
            }
        };
        assert_eq!(err, Error::OutputLimitExceeded);
        assert!(delivered <= 1024);
        assert!(dec.get_ref().buffered_output() <= 1024);
    }
}

/// The limit is exact — a stream of exactly the limit decodes, one byte
/// less refuses it — covers PPMd blocks, and survives a reset.
#[test]
fn output_limit_is_exact_and_covers_ppmd() {
    let mut buf = [0u8; 4096];

    // No declared size: the stream's own end marker lands on the limit.
    let syn = build_lz_stream(&run_ops(30, 2));
    let mut dec = Decoder::new();
    dec.set_output_limit(syn.raw.len() as u64);
    let (out, err, _) = decode_chunked(dec, &syn.stream, usize::MAX, 4096);
    assert_eq!(err, None);
    assert_eq!(out, syn.raw);
    let mut dec = Decoder::new();
    dec.set_output_limit(syn.raw.len() as u64 - 1);
    let (_, err, _) = decode_chunked(dec, &syn.stream, usize::MAX, 4096);
    assert_eq!(err, Some(Error::OutputLimitExceeded));

    for (block, unp, crc) in [
        (PPMD_NOTES, 20001u64, 0x0E1A_EC07u32),
        (FILTER_X86_SLICE, 32768, 0x6188_0029),
    ] {
        let mut dec = Decoder::with_unpack_size(unp);
        dec.set_output_limit(unp - 1);
        dec.decode(block, &mut []).unwrap();
        assert_eq!(
            dec.finish(&mut buf).unwrap_err(),
            Error::OutputLimitExceeded
        );
        assert!((dec.buffered_output() as u64) < unp);

        // A declared size within the limit is never refused, and the limit
        // is configuration: it survives a reset.
        let mut dec = Decoder::with_unpack_size(unp);
        dec.set_output_limit(unp);
        for _ in 0..2 {
            dec.decode(block, &mut []).unwrap();
            let mut out = Vec::new();
            drain(&mut dec, &mut out);
            assert_eq!(crc32(&out), crc);
            dec.reset();
        }
        dec.set_output_limit(10);
        dec.reset();
        dec.decode(block, &mut []).unwrap();
        assert_eq!(
            dec.finish(&mut buf).unwrap_err(),
            Error::OutputLimitExceeded
        );
    }
}

/// In a solid group the limit covers the group as a whole: the members
/// together may produce exactly the limit, and one byte less refuses the
/// member that would cross it.
#[test]
fn output_limit_spans_solid_members() {
    let total: u64 = SOLID_M3_GROUP.iter().map(|m| m.1).sum();
    for (limit, fits) in [(total, true), (total - 1, false)] {
        let mut dec = Decoder::with_unpack_size(SOLID_M3_GROUP[0].1).with_solid();
        dec.set_output_limit(limit);
        let mut refused_at = None;
        let mut buf = vec![0u8; 1 << 16];
        'group: for (i, &(payload, unp, _)) in SOLID_M3_GROUP.iter().enumerate() {
            if i > 0 {
                dec.begin_solid_member(unp).unwrap();
            }
            dec.decode(payload, &mut []).unwrap();
            loop {
                match dec.finish(&mut buf) {
                    Ok((_, Status::StreamEnd)) => break,
                    Ok((p, _)) => assert!(p.written > 0),
                    Err(e) => {
                        assert_eq!(e, Error::OutputLimitExceeded);
                        refused_at = Some(i);
                        break 'group;
                    }
                }
            }
        }
        let want = (!fits).then_some(SOLID_M3_GROUP.len() - 1);
        assert_eq!(refused_at, want, "limit {limit}");
    }
}

/// Filter work is bounded by the output produced: thousands of Delta
/// declarations stacked on one window (each a 128 KiB pass for a few bytes
/// of input) are refused instead of run.
#[test]
fn stacked_delta_filters_are_refused() {
    const WINDOW: u32 = 0x20000;
    let mut ops: Vec<Op> = std::iter::repeat_n(
        Op::Delta {
            start: 0,
            len: WINDOW,
            channels: 1024,
        },
        4000,
    )
    .collect();
    ops.extend(run_ops(1, 520));
    let syn = build_lz_stream(&ops);
    assert!(syn.raw.len() > WINDOW as usize);
    let (out, err, _) = decode_chunked(
        Decoder::with_unpack_size(syn.raw.len() as u64),
        &syn.stream,
        usize::MAX,
        4096,
    );
    assert_eq!(err, Some(Error::Corrupt));
    assert!(out.is_empty());

    // A few passes over the same window (what a real encoder's filter
    // stacking amounts to) still decode.
    let mut ops: Vec<Op> = std::iter::repeat_n(
        Op::Delta {
            start: 0,
            len: WINDOW,
            channels: 3,
        },
        4,
    )
    .collect();
    ops.extend(run_ops(1, 520));
    let syn = build_lz_stream(&ops);
    assert!(decode_full(&syn.stream, syn.raw.len() as u64) == syn.filtered());
}

/// A filter window cannot start a whole dictionary (4 MiB) or more ahead:
/// the reference decoder addresses filter blocks inside its window, so no
/// encoder can declare one, and accepting it would let a declaration pin
/// output far behind it.
#[test]
fn filter_start_beyond_dictionary_is_corrupt() {
    let mut ops = vec![Op::Delta {
        start: 4 << 20,
        len: 16,
        channels: 1,
    }];
    ops.extend(run_ops(2, 1));
    let syn = build_lz_stream(&ops);
    let (_, err, _) = decode_chunked(Decoder::new(), &syn.stream, usize::MAX, 4096);
    assert_eq!(err, Some(Error::Corrupt));
}

// ─── Streaming through PPMd blocks ───────────────────────────────────────
//
// The PPMd fixtures are far smaller than the dictionary, so they are
// released in one piece when they end and never make the decoder suspend a
// PPMd block. (The unit tests in `src/rar3/decoder.rs` force a pause at
// every symbol of those fixtures.) A PPMd stream of several MiB is needed
// here, and this crate has no PPMd encoder to make one with: arbitrary
// bytes are not a valid range-coded payload — sooner or later they run into
// an escape sequence or leave the coder's interval. One payload is valid
// at any length, though: all zero bytes. The coder then always lands in the
// first interval, which the model gives to byte 0 from the first symbol on,
// so the block decodes to zeros — it is what an encoder writes for a run of
// zeros, less its final flush — at about 2700 output bytes per payload
// byte.

/// Output bytes a zero-payload PPMd block yields per payload byte, rounded
/// down (2720 measured; the block ends in `UnexpectedEnd` when its payload
/// runs out).
const PPMD_ZEROS_PER_BYTE: usize = 2600;

/// A PPMd block header (fresh model, order 3, 1 MiB, escape byte 0xC8)
/// followed by `payload` zero bytes. Decodes to at least
/// `payload * PPMD_ZEROS_PER_BYTE` zero bytes.
fn ppmd_zero_block(payload: usize) -> Vec<u8> {
    // PPMd flag, model reset (0x20), explicit escape byte (0x40), order - 1.
    let mut block = vec![0x80 | 0x60 | 2, 0, 0xC8];
    block.resize(block.len() + payload, 0);
    block
}

/// A PPMd member is streamed like an LZ one: a 6 MiB PPMd block never has
/// more than the dictionary's worth (plus slack) waiting inside the
/// decoder, whatever buffer it is drained through.
#[test]
fn ppmd_output_buffering_is_bounded() {
    let unp = (6usize << 20) + 12_345;
    let stream = ppmd_zero_block(unp / PPMD_ZEROS_PER_BYTE + 16);
    for out_chunk in [1 << 16, 4099] {
        let (out, err, peak) = decode_chunked(
            Decoder::with_unpack_size(unp as u64),
            &stream,
            usize::MAX,
            out_chunk,
        );
        assert_eq!(err, None);
        assert_eq!(out.len(), unp, "drained by {out_chunk}");
        assert!(out.iter().all(|&b| b == 0), "drained by {out_chunk}");
        assert!(
            peak <= BUFFERED_OUTPUT_BOUND,
            "{peak} bytes buffered for a {unp} byte PPMd block"
        );
    }
}

/// Decode a failing zero-payload stream through two differently sized
/// output buffers and check that the same bytes come out before the same
/// error. Returns how many, and the error.
fn same_failure_for_every_chunking(make: impl Fn() -> Decoder, stream: &[u8]) -> (usize, Error) {
    let (out_a, err_a, peak_a) = decode_chunked(make(), stream, usize::MAX, 1 << 16);
    let (out_b, err_b, peak_b) = decode_chunked(make(), stream, 4096, 4099);
    assert!(out_a == out_b, "delivered bytes differ");
    assert_eq!(err_a, err_b);
    assert!(peak_a.max(peak_b) <= BUFFERED_OUTPUT_BOUND);
    assert!(out_a.iter().all(|&b| b == 0));
    (out_a.len(), err_a.expect("the stream should fail"))
}

/// A PPMd payload that runs out several MiB in fails at the same symbol
/// whatever the chunking: the same bytes are delivered first — everything
/// released before the failure, which for a block longer than the
/// dictionary is no longer nothing — and then the same error.
#[test]
fn truncated_ppmd_block_fails_at_the_same_position() {
    // Runs dry somewhere past 5 MiB, well short of the declared size.
    let stream = ppmd_zero_block((5 << 20) / PPMD_ZEROS_PER_BYTE);
    let (delivered, err) =
        same_failure_for_every_chunking(|| Decoder::with_unpack_size(64 << 20), &stream);
    assert_eq!(err, Error::UnexpectedEnd);
    assert!(delivered > 3 << 20, "only {delivered} bytes delivered");
    assert!(delivered < 6 << 20);
}

/// The output limit is checked symbol by symbol in a PPMd block that has
/// already been suspended and resumed: the bytes released before the limit
/// come out, then `OutputLimitExceeded`, for every chunking.
#[test]
fn output_limit_holds_in_a_resumed_ppmd_block() {
    let limit = (5u64 << 20) + 77;
    let stream = ppmd_zero_block((6 << 20) / PPMD_ZEROS_PER_BYTE);
    let make = || {
        let mut dec = Decoder::new();
        dec.set_output_limit(limit);
        dec
    };
    let (delivered, err) = same_failure_for_every_chunking(make, &stream);
    assert_eq!(err, Error::OutputLimitExceeded);
    assert!(delivered > 3 << 20, "only {delivered} bytes delivered");
    assert!(delivered as u64 <= limit);
}

/// Solid mode keeps its end-of-member policy across pauses: a PPMd member
/// that reaches its declared size after being suspended must still code
/// its end marker through the model, and one that does not is refused.
#[test]
fn solid_ppmd_member_without_end_marker_fails_after_pauses() {
    let unp = (4u64 << 20) + (300 << 10);
    let stream = ppmd_zero_block((5 << 20) / PPMD_ZEROS_PER_BYTE);
    let (delivered, err) =
        same_failure_for_every_chunking(|| Decoder::with_unpack_size(unp).with_solid(), &stream);
    // The symbol after the last byte is another zero, not the escape byte.
    assert_eq!(err, Error::Corrupt);
    assert!(delivered > 3 << 20, "only {delivered} bytes delivered");
    assert!((delivered as u64) < unp);
}

/// An LZ block handing over to a PPMd block mid-member, with a Delta
/// filter window that starts in the LZ block's output, ends in the PPMd
/// block's, and is still incomplete when the decoder first releases output
/// — which it now does from inside the PPMd block. The window is held back
/// across that pause, filtered once it completes, and the rest of the
/// PPMd block streams on.
#[test]
fn lz_block_switching_to_ppmd_streams_across_the_switch() {
    // The first release pass comes once this much has been decoded.
    const FIRST_RELEASE: usize = (4 << 20) - 260;
    const WINDOW: usize = 0x1E000;
    let mut ops = Vec::new();
    let mut produced = 0usize;
    let mut block = 0usize;
    let mut declared = false;
    while produced < FIRST_RELEASE - 50_000 {
        if !declared && produced >= FIRST_RELEASE - 80_000 {
            ops.push(Op::Delta {
                start: 0,
                len: WINDOW as u32,
                channels: 3,
            });
            declared = true;
        }
        ops.push(Op::Lit(SYN_LITERALS[(block * 5 + block / 7) % 4]));
        ops.push(Op::Run);
        produced += 259;
        block += 1;
    }
    let mut syn = build_lz_block(&ops, true);
    let lz_len = syn.raw.len();
    let (window_start, _, _) = syn.filters[0];
    assert!(window_start < lz_len && lz_len < FIRST_RELEASE);
    assert!(FIRST_RELEASE < window_start + WINDOW);

    let ppmd_len = (4 << 20) + (400 << 10);
    syn.stream
        .extend_from_slice(&ppmd_zero_block(ppmd_len / PPMD_ZEROS_PER_BYTE + 16));
    syn.raw.resize(lz_len + ppmd_len, 0);
    let want = syn.filtered();
    // The filter carries the LZ block's bytes into the PPMd block's zeros.
    assert!(want[lz_len..window_start + WINDOW].iter().any(|&b| b != 0));

    for out_chunk in [1 << 16, 4099] {
        let (out, err, peak) = decode_chunked(
            Decoder::with_unpack_size(want.len() as u64),
            &syn.stream,
            usize::MAX,
            out_chunk,
        );
        assert_eq!(err, None);
        assert!(out == want, "output differs (drained by {out_chunk})");
        assert!(peak <= BUFFERED_OUTPUT_BOUND, "{peak} bytes buffered");
    }
}
