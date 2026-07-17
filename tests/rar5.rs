//! Integration tests for the RAR5 decoder.
//!
//! Fixtures here are extracted from RAR5 archives produced by RARLAB's `rar`
//! CLI. The decoder is fed only the *inner compressed-data block* (already
//! peeled out of the archive container), plus the unpack-size and window
//! size taken from the container's file header.
//!
//! ## How fixtures were generated
//!
//! 1. `rar a -ma5 -m5 test.rar input.txt` produces a RAR5 archive.
//! 2. The archive's File header (`type == 2`, sometimes called `kFileHeader`)
//!    carries the unpack-size (vint), the data-CRC, the compression info
//!    (`comp_info` — dictionary-size bits, method, etc.), and finally the
//!    `data_size`-byte compressed payload immediately after the header
//!    block. That payload is what we embed below.
//! 3. For our 128 KiB-window fixtures, `comp_info` bits 10..14 == 0 so
//!    the window is `128 KiB << 0 = 128 KiB`.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.
//! RAR5 is decoder-only — the encoder always returns `Error::Unsupported`.

#![cfg(feature = "rar5")]

use compcol::rar5::{Decoder, Encoder, Rar5};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── fixtures ─────────────────────────────────────────────────────────────

/// Fixture 1 — 200 copies of `'A'` followed by a single `'\n'` (201 bytes).
///
/// Inner compressed-data block as produced by `rar a -ma5 -m3`.
const FIXTURE_AAA: &[u8] = &[
    0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15, 0x00,
];
const FIXTURE_AAA_UNPACK: u64 = 201;

/// Fixture 2 — `('abc' * 100) + '\n'`, 301 bytes. Method `-m5`.
const FIXTURE_ABCABC: &[u8] = &[
    0xc2, 0x88, 0x10, 0x33, 0x23, 0xfc, 0x32, 0xff, 0x32, 0xf0, 0x3f, 0xd5, 0x22, 0x12, 0xca, 0xee,
    0xe3, 0x4f, 0xc0,
];
const FIXTURE_ABCABC_UNPACK: u64 = 301;

/// Fixture 3 — a synthetic 1506-byte payload containing 50 `0xE8` x86-call
/// opcodes (each followed by a 4-byte relative target) interleaved with
/// zero padding. RAR5 auto-detects this content and activates the
/// `X86Call` filter (type 1) during compression; the decoder must apply
/// the inverse transform on the unpacked stream to reconstruct the original
/// bytes verbatim. Method `-m5`.
const FIXTURE_E8: &[u8] = &[
    0xc0, 0xcf, 0x55, 0x03, 0x40, 0x04, 0x23, 0xf7, 0x44, 0x2d, 0x2f, 0x24, 0x69, 0xd6, 0x60, 0x8d,
    0x85, 0x41, 0x82, 0x4e, 0x7d, 0x8b, 0xcc, 0xff, 0x88, 0x38, 0x85, 0x84, 0xaa, 0x38, 0x45, 0x09,
    0x3e, 0x38, 0xa6, 0xa2, 0x72, 0x7a, 0x82, 0x8a, 0x92, 0x9a, 0xa2, 0xaa, 0xb2, 0xba, 0xc2, 0xca,
    0xd2, 0xda, 0xe2, 0xea, 0xf2, 0xfb, 0x03, 0x0b, 0x13, 0x1b, 0x23, 0x2b, 0x33, 0x3b, 0x43, 0x4b,
    0x53, 0x5b, 0x63, 0x6b, 0x73, 0x7b, 0x83, 0x8b, 0x93, 0x9b, 0xa3, 0xab, 0xb3, 0xbb, 0xc3, 0xcb,
    0xd3, 0xdb, 0xe3, 0xec, 0x97, 0xef, 0xee, 0x80,
];
const FIXTURE_E8_UNPACK: u64 = 1506;

// ─── helpers ──────────────────────────────────────────────────────────────

/// Drive a freshly-constructed decoder to completion against a single input
/// slice and return the produced bytes.
fn decode_once(comp: &[u8], unpack: u64, window: usize) -> Result<Vec<u8>, Error> {
    let dec = Decoder::with_unpack_size_and_window(unpack, window);
    drive(dec, comp, unpack)
}

/// Drive an already-configured decoder (e.g. one with file boundaries
/// registered) to completion against a single input slice.
fn drive(mut dec: Decoder, comp: &[u8], unpack: u64) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; unpack as usize];
    let mut total = 0usize;

    // Feed the input once.
    let (p, status) = dec.decode(comp, &mut out[total..])?;
    total += p.written;

    // Drain any remaining buffered output by re-calling decode with no
    // additional input until it stalls.
    if !matches!(status, Status::StreamEnd) {
        loop {
            if total >= out.len() {
                break;
            }
            let (p, status) = dec.decode(&[], &mut out[total..])?;
            total += p.written;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                break;
            }
        }
    }

    // Then finish to flush any tail bytes and observe StreamEnd.
    loop {
        if total >= out.len() {
            // Even if the output buffer is full, finish into a scratch slot
            // to confirm StreamEnd. If extra bytes appear, the unpack-size
            // cap was wrong.
            let mut scratch = [0u8; 16];
            let (pf, status) = dec.finish(&mut scratch)?;
            if pf.written != 0 {
                // Surplus bytes — the test caller's expected length was too
                // short; surface them so the assert can flag the mismatch.
                out.extend_from_slice(&scratch[..pf.written]);
                total += pf.written;
            }
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if pf.written == 0 {
                break;
            }
            continue;
        }
        let (pf, status) = dec.finish(&mut out[total..])?;
        total += pf.written;
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            break;
        }
    }

    out.truncate(total);
    Ok(out)
}

/// Decode the same input fed byte-by-byte, draining through a small output
/// buffer.
fn decode_chunked(
    comp: &[u8],
    unpack: u64,
    window: usize,
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::with_unpack_size_and_window(unpack, window);
    let mut decoded: Vec<u8> = Vec::with_capacity(unpack as usize);
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0usize;

    while i < comp.len() {
        let end = (i + in_chunk).min(comp.len());
        let chunk = &comp[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
        // After feeding, drain whatever is currently producible without
        // additional input.
        loop {
            let (p, status) = dec.decode(&[], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if p.written == 0 {
                break;
            }
        }
    }

    // Finish: drain any tail and observe StreamEnd.
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }

    Ok(decoded)
}

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_rar5() {
    assert_eq!(<Rar5 as Algorithm>::NAME, "rar5");
}

#[test]
fn rar5_algorithm_factory_produces_codec() {
    let _enc = <Rar5 as Algorithm>::encoder();
    let _dec = <Rar5 as Algorithm>::decoder();
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
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

// ─── empty input ─────────────────────────────────────────────────────────

#[test]
fn empty_input_with_zero_unpack_size_finishes_cleanly() {
    let mut dec = Decoder::with_unpack_size_and_window(0, 128 * 1024);
    let mut out = [0u8; 16];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert!(
        matches!(status, Status::StreamEnd),
        "expected StreamEnd on empty finish, got {:?}",
        status
    );
}

// ─── real-world fixtures: byte-identical round-trips ─────────────────────

#[test]
fn decode_aaa_fixture() {
    let out = decode_once(FIXTURE_AAA, FIXTURE_AAA_UNPACK, 128 * 1024).expect("decode");
    let mut expected = vec![b'A'; 200];
    expected.push(b'\n');
    assert_eq!(out, expected);
}

#[test]
fn decode_abcabc_fixture() {
    let out = decode_once(FIXTURE_ABCABC, FIXTURE_ABCABC_UNPACK, 128 * 1024).expect("decode");
    let mut expected = Vec::new();
    for _ in 0..100 {
        expected.extend_from_slice(b"abc");
    }
    expected.push(b'\n');
    assert_eq!(out, expected);
}

#[test]
fn decode_e8_filter_fixture() {
    // Round-trip the E8 fixture; the decoder must apply the inverse of
    // RAR5's x86 call-translation filter and recover the original bytes.
    let out = decode_once(FIXTURE_E8, FIXTURE_E8_UNPACK, 128 * 1024).expect("decode");
    let mut expected = Vec::with_capacity(FIXTURE_E8_UNPACK as usize);
    for i in 0..50u32 {
        expected.extend_from_slice(&[0u8; 20]);
        expected.push(0xE8);
        expected.extend_from_slice(&(0x100u32 + i).to_le_bytes());
    }
    expected.extend_from_slice(&[0x90u8; 256]);
    assert_eq!(out.len(), expected.len());
    assert_eq!(
        out, expected,
        "E8 filter round-trip must match the original input byte-for-byte"
    );
}

// ─── streaming variants ──────────────────────────────────────────────────

#[test]
fn decode_aaa_chunked_one_byte_at_a_time() {
    // Same fixture fed one byte at a time. Verifies that the decoder's
    // internal buffering correctly waits for whole blocks before
    // proceeding.
    let out = decode_chunked(FIXTURE_AAA, FIXTURE_AAA_UNPACK, 128 * 1024, 1, 64).expect("decode");
    let mut expected = vec![b'A'; 200];
    expected.push(b'\n');
    assert_eq!(out, expected);
}

#[test]
fn decode_aaa_with_small_output_buffer() {
    // Drain the decoder through a 32-byte output buffer to verify the
    // streaming back-pressure on the `ready` queue.
    let out = decode_chunked(
        FIXTURE_AAA,
        FIXTURE_AAA_UNPACK,
        128 * 1024,
        FIXTURE_AAA.len(),
        32,
    )
    .expect("decode");
    let mut expected = vec![b'A'; 200];
    expected.push(b'\n');
    assert_eq!(out, expected);
}

// ─── error handling ──────────────────────────────────────────────────────

#[test]
fn truncated_input_returns_error_or_no_output() {
    // Half a header is not enough to do anything; the decoder should keep
    // asking for more input rather than producing output.
    let mut dec = Decoder::with_unpack_size_and_window(201, 128 * 1024);
    let mut out = [0u8; 256];
    let (p, _status) = dec.decode(&FIXTURE_AAA[..1], &mut out).unwrap();
    assert_eq!(
        p.written, 0,
        "no output should be produced from a 1-byte input"
    );
    // finish() on truncated input must surface UnexpectedEnd.
    let mut tail = [0u8; 16];
    let err = dec.finish(&mut tail).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn invalid_block_header_checksum_is_rejected() {
    // Flip a bit in the size field; the header checksum no longer matches.
    let mut bad = FIXTURE_AAA.to_vec();
    bad[2] ^= 0xFF;
    let mut dec = Decoder::with_unpack_size_and_window(201, 128 * 1024);
    let mut out = [0u8; 256];
    let r = dec.decode(&bad, &mut out);
    assert!(matches!(
        r,
        Err(Error::BadHeader) | Err(Error::Corrupt) | Err(Error::InvalidHuffmanTree)
    ));
}

#[test]
fn decoder_does_not_panic_on_garbage() {
    // Fuzz-style smoke check: random-ish bytes should never panic.
    let garbage: Vec<u8> = (0..512u32).map(|i| (i ^ (i >> 3)) as u8).collect();
    let mut dec = Decoder::with_unpack_size_and_window(1024, 128 * 1024);
    let mut out = [0u8; 1024];
    let _ = dec.decode(&garbage, &mut out);
}

// ─── reset behaviour ─────────────────────────────────────────────────────

#[test]
fn reset_clears_state() {
    let mut dec = Decoder::with_unpack_size_and_window(FIXTURE_AAA_UNPACK, 128 * 1024);
    let mut out = vec![0u8; FIXTURE_AAA_UNPACK as usize];
    let (p, _status) = dec.decode(FIXTURE_AAA, &mut out).unwrap();
    let mut total = p.written;
    while total < out.len() {
        let (p, status) = dec.decode(&[], &mut out[total..]).unwrap();
        total += p.written;
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    // Drain finish to reach StreamEnd before reset.
    loop {
        let mut scratch = [0u8; 16];
        let (pf, status) = dec.finish(&mut scratch).unwrap();
        let _ = pf;
        if matches!(status, Status::StreamEnd) || pf.written == 0 {
            break;
        }
    }

    dec.reset();

    // After reset, decoding the same input again should yield the same
    // bytes — no stale window or table state leaking across.
    let mut out2 = vec![0u8; FIXTURE_AAA_UNPACK as usize];
    let (p, _status) = dec.decode(FIXTURE_AAA, &mut out2).unwrap();
    let mut total2 = p.written;
    while total2 < out2.len() {
        let (p, status) = dec.decode(&[], &mut out2[total2..]).unwrap();
        total2 += p.written;
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    let mut expected = vec![b'A'; 200];
    expected.push(b'\n');
    assert_eq!(&out2[..total2], expected.as_slice());
}

// ─── Real-archive fixtures: Delta filter + solid-group boundaries ────────
//
// Packed runs lifted out of archives produced by WinRAR 7.23 (`rar5`
// format, m3, 128 KiB window) over synthetic content — the fixture bytes
// are exactly the member's compressed run following its file header. The
// expected CRC-32s are the archives' own per-file data-CRC header fields;
// extraction is additionally cross-checked byte-identical against
// `UnRAR.exe` 7.23 by the differential harness.

/// gradient.bmp, non-solid — carries a Delta filter (3 channels).
static RAR5_DELTA_GRADIENT: &[u8] = include_bytes!("fixtures/rar5/delta_gradient_bmp.bin");

/// A whole solid group: six members sharing one continuous LZ stream, in
/// this order. x86slice.bin carries x86 E8 filters, gradient.bmp/ramp.wav/
/// calls.bin carry Delta filters.
static RAR5_SOLID_GROUP: &[u8] = include_bytes!("fixtures/rar5/solid_group_m3.bin");

/// (name, start offset in the group's output, unpacked size, CRC-32) per
/// member, from the archive's file headers.
const SOLID_MEMBERS: [(&str, u64, u64, u32); 6] = [
    ("notes.txt", 0, 20001, 0x0E1A_EC07),
    ("calls.bin", 20001, 6146, 0x6C08_D7DF),
    ("x86slice.bin", 26147, 32768, 0x6188_0029),
    ("gradient.bmp", 58915, 49206, 0x2347_E5ED),
    ("ramp.wav", 108121, 16428, 0x0E8F_2810),
    ("photo.jpg", 124549, 8198, 0x8420_E285),
];
const SOLID_TOTAL: u64 = 132_747;
const SOLID_WINDOW: usize = 0x20000;

/// Bitwise CRC-32 (IEEE, reflected 0xEDB88320) — table-free, test-only.
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

#[test]
fn delta_filter_end_to_end() {
    let out = decode_once(RAR5_DELTA_GRADIENT, 49206, 0x20000).unwrap();
    assert_eq!(out.len(), 49206);
    assert_eq!(&out[..2], b"BM", "BMP magic must survive de-filtering");
    assert_eq!(
        crc32(&out),
        0x2347_E5ED,
        "must match the archive's data CRC"
    );
}

#[test]
fn solid_group_with_file_boundaries_end_to_end() {
    let mut dec = Decoder::with_unpack_size_and_window(SOLID_TOTAL, SOLID_WINDOW);
    for (_, start, _, _) in SOLID_MEMBERS {
        dec.add_file_boundary(start);
    }
    let out = drive(dec, RAR5_SOLID_GROUP, SOLID_TOTAL).unwrap();
    assert_eq!(out.len() as u64, SOLID_TOTAL);
    for (name, start, size, want_crc) in SOLID_MEMBERS {
        let member = &out[start as usize..(start + size) as usize];
        assert_eq!(crc32(member), want_crc, "{name} differs from its data CRC");
    }
}

/// Regression guard for the solid x86 position-base bug: without the
/// registered boundaries the E8 transform runs with solid-stream offsets
/// and corrupts the x86 member, while the position-independent Delta
/// members still decode correctly.
#[test]
fn solid_group_without_boundaries_corrupts_only_x86_member() {
    let dec = Decoder::with_unpack_size_and_window(SOLID_TOTAL, SOLID_WINDOW);
    let out = drive(dec, RAR5_SOLID_GROUP, SOLID_TOTAL).unwrap();
    for (name, start, size, want_crc) in SOLID_MEMBERS {
        let got = crc32(&out[start as usize..(start + size) as usize]);
        if name == "x86slice.bin" {
            assert_ne!(got, want_crc, "x86 member should differ without boundaries");
        } else {
            assert_eq!(got, want_crc, "{name} is position-independent");
        }
    }
}

// ─── factory (only if the feature is enabled) ────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Error;
    use compcol::factory;

    #[test]
    fn lookup_rar5_encoder_and_decoder() {
        assert!(factory::encoder_by_name("rar5").is_some());
        assert!(factory::decoder_by_name("rar5").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-rar5").is_none());
        assert!(factory::decoder_by_name("not-a-real-rar5").is_none());
    }

    #[test]
    fn names_contains_rar5() {
        assert!(factory::names().contains(&"rar5"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        let mut enc = factory::encoder_by_name("rar5").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }
}
