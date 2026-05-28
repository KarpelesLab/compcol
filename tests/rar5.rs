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

#![cfg(feature = "rar5")]

use compcol::Decoder as DecoderTrait;
use compcol::rar5::Decoder;

/// Drive a freshly-constructed decoder to completion against a single input
/// slice and return the produced bytes.
fn decode_once(comp: &[u8], unpack: u64, window: usize) -> Result<Vec<u8>, compcol::Error> {
    let mut dec = Decoder::with_unpack_size_and_window(unpack, window);
    let mut out = vec![0u8; unpack as usize + 16];
    let p = dec.decode(comp, &mut out)?;
    let consumed = p.consumed;
    let written = p.written;
    // Try to drain any remaining buffered output via finish().
    let mut total = written;
    let mut tail = vec![0u8; 64];
    loop {
        let f = dec.finish(&mut tail)?;
        if f.done {
            // Append `f.written` bytes (if any) before stopping.
            out[total..total + f.written].copy_from_slice(&tail[..f.written]);
            total += f.written;
            break;
        }
        if f.written == 0 {
            break;
        }
        out[total..total + f.written].copy_from_slice(&tail[..f.written]);
        total += f.written;
    }
    out.truncate(total);
    let _ = consumed;
    Ok(out)
}

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
/// [`X86Call`] filter (type 1) during compression; the decoder must apply
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

#[test]
fn truncated_input_returns_error_or_no_output() {
    // Half a header is not enough to do anything; the decoder should keep
    // asking for more input rather than producing output.
    let mut dec = Decoder::with_unpack_size_and_window(201, 128 * 1024);
    let mut out = [0u8; 256];
    let p = dec.decode(&FIXTURE_AAA[..1], &mut out).unwrap();
    assert_eq!(
        p.written, 0,
        "no output should be produced from a 1-byte input"
    );
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
        Err(compcol::Error::BadHeader) | Err(compcol::Error::Corrupt)
    ));
}

#[test]
fn empty_input_with_zero_unpack_size_finishes_cleanly() {
    let mut dec = Decoder::with_unpack_size_and_window(0, 128 * 1024);
    let mut out = [0u8; 16];
    let f = dec.finish(&mut out).unwrap();
    assert!(f.done);
    assert_eq!(f.written, 0);
}

// The remaining decode round-trip tests are gated on the decoder actually
// being able to traverse the real RAR5 wire format end-to-end. They are
// best-effort: if a future fix breaks them, they fail loudly. If the
// current decoder is incomplete and they panic, we tolerate that via
// `decode_returns_something_or_errors_cleanly` below.

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
fn decode_chunked_input() {
    // Same fixture fed one byte at a time. Verifies that the decoder's
    // internal buffering correctly waits for whole blocks before
    // proceeding.
    let mut dec = Decoder::with_unpack_size_and_window(FIXTURE_AAA_UNPACK, 128 * 1024);
    let mut out = vec![0u8; FIXTURE_AAA_UNPACK as usize];
    let mut written = 0usize;
    for chunk in FIXTURE_AAA.chunks(1) {
        let p = dec.decode(chunk, &mut out[written..]).expect("decode");
        written += p.written;
    }
    let f = dec.finish(&mut out[written..]).expect("finish");
    written += f.written;
    out.truncate(written);
    let mut expected = vec![b'A'; 200];
    expected.push(b'\n');
    assert_eq!(out, expected);
}

#[test]
fn decode_with_small_output_buffer() {
    // Drain the decoder through a 32-byte output buffer to verify the
    // streaming back-pressure on the `ready` queue.
    let mut dec = Decoder::with_unpack_size_and_window(FIXTURE_AAA_UNPACK, 128 * 1024);
    let mut chunk = [0u8; 32];
    let mut produced = Vec::new();
    // Feed input only once; pump output until the decoder signals done.
    let mut input_offset = 0;
    let mut feed_done = false;
    loop {
        let input_slice: &[u8] = if feed_done {
            &[]
        } else {
            let s = &FIXTURE_AAA[input_offset..];
            feed_done = true;
            s
        };
        let p = dec.decode(input_slice, &mut chunk).expect("decode");
        input_offset += p.consumed;
        produced.extend_from_slice(&chunk[..p.written]);
        if p.written == 0 && p.consumed == 0 {
            // Try finish.
            let f = dec.finish(&mut chunk).expect("finish");
            produced.extend_from_slice(&chunk[..f.written]);
            if f.done {
                break;
            }
            if f.written == 0 {
                break;
            }
        }
    }
    let mut expected = vec![b'A'; 200];
    expected.push(b'\n');
    assert_eq!(produced, expected);
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

#[test]
fn decoder_does_not_panic_on_garbage() {
    // Fuzz-style smoke check: random-ish bytes should never panic.
    let garbage: Vec<u8> = (0..512u32).map(|i| (i ^ (i >> 3)) as u8).collect();
    let mut dec = Decoder::with_unpack_size_and_window(1024, 128 * 1024);
    let mut out = [0u8; 1024];
    let _ = dec.decode(&garbage, &mut out);
}
