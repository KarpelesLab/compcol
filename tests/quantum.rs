//! Integration tests for the Quantum decoder.
//!
//! Quantum streams have no in-band length or window-size; both are carried
//! by the container (CAB). Tests here construct the bytes a CAB folder
//! would feed to the decoder. The main real-world fixture is extracted
//! from `cabextract/test/bugs/cve-2010-2801-qtm-flush.cab` in the
//! libmspack repository, which despite its CVE name happens to be a
//! perfectly valid Quantum stream (a 512 KiB run of zero bytes); the CVE
//! is about an output-flush bug, not a malformed stream.

#![cfg(feature = "quantum")]

use compcol::quantum::{Decoder, Encoder, Quantum};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

// ─── helpers ──────────────────────────────────────────────────────────────

/// Decode `input` in one shot with the supplied window size. Returns the
/// full decoded output.
fn decode_oneshot(input: &[u8], window_bits: u32, expected_len: usize) -> Vec<u8> {
    let mut dec = Decoder::with_window_bits(window_bits).expect("valid window bits");
    let mut output = vec![0u8; expected_len];
    let mut total_written = 0usize;
    // Feed all input at once, then drain in repeated decode() calls.
    let p = dec.decode(input, &mut output[total_written..]).unwrap();
    total_written += p.written;
    // After feeding input, repeatedly call decode with an empty input
    // until the decoder has nothing more to produce.
    while total_written < expected_len {
        let p = dec.decode(&[], &mut output[total_written..]).unwrap();
        total_written += p.written;
        if p.written == 0 {
            break;
        }
    }
    // Call finish to allow EOF padding to flush the final renorm bits.
    while total_written < expected_len {
        let p = dec.finish(&mut output[total_written..]).unwrap();
        total_written += p.written;
        if p.written == 0 {
            break;
        }
    }
    output.truncate(total_written);
    output
}

/// Decode `input` chunked through a tight output buffer to stress streaming.
/// Stops driving the decoder once `expected_len` bytes have been produced —
/// Quantum has no end-of-stream marker (the CAB container tracks length).
fn decode_chunked(
    input: &[u8],
    window_bits: u32,
    expected_len: usize,
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut dec = Decoder::with_window_bits(window_bits).expect("valid window bits");
    let mut decoded: Vec<u8> = Vec::with_capacity(expected_len);
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0usize;

    while i < input.len() && decoded.len() < expected_len {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() && decoded.len() < expected_len {
            let want = (expected_len - decoded.len()).min(buf.len());
            let p = dec
                .decode(&chunk[consumed_in_chunk..], &mut buf[..want])
                .unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                // No more progress with this chunk; surface more input.
                break;
            }
        }
        i = end;
        // After feeding, drain whatever is currently producible.
        while decoded.len() < expected_len {
            let want = (expected_len - decoded.len()).min(buf.len());
            let p = dec.decode(&[], &mut buf[..want]).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if p.written == 0 {
                break;
            }
        }
    }
    decoded
}

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_quantum() {
    assert_eq!(<Quantum as Algorithm>::NAME, "quantum");
}

#[test]
fn encoder_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        enc.encode(b"hello", &mut out).unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn quantum_algorithm_factory_produces_decoder() {
    let _enc = <Quantum as Algorithm>::encoder();
    let _dec = <Quantum as Algorithm>::decoder();
}

// ─── window-bits validation ───────────────────────────────────────────────

#[test]
fn window_bits_below_range_rejected() {
    assert_eq!(Decoder::with_window_bits(9).err(), Some(Error::BadHeader));
    assert_eq!(Decoder::with_window_bits(0).err(), Some(Error::BadHeader));
}

#[test]
fn window_bits_above_range_rejected() {
    assert_eq!(Decoder::with_window_bits(22).err(), Some(Error::BadHeader));
    assert_eq!(Decoder::with_window_bits(100).err(), Some(Error::BadHeader));
}

#[test]
fn window_bits_in_range_accepted() {
    for wb in 10..=21 {
        assert!(Decoder::with_window_bits(wb).is_ok(), "window_bits={wb}");
    }
}

// ─── empty input ─────────────────────────────────────────────────────────

#[test]
fn empty_input_finish_is_done() {
    let mut dec = Decoder::new();
    let mut out = [0u8; 8];
    let p = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert!(p.done);
}

// ─── real-world fixture: cve-2010-2801-qtm-flush.cab ─────────────────────

/// The Quantum stream embedded in libmspack's
/// `cve-2010-2801-qtm-flush.cab`, with a `0xFF` byte appended after each
/// CFDATA block (this is the per-block trailer that cabd.c synthesises
/// to let the Quantum decoder realign at block boundaries).
///
/// `window_bits = 18` (256 KiB window).
///
/// Decodes to **524 159 zero bytes**.
const CVE_2010_2801_INPUT: &[u8] = &[
    0xFF, 0x6D, 0xDA, 0x34, 0x62, 0x1A, 0x9B, 0xA9, 0x92, 0x04, 0xD2, 0x80, 0x00, 0x20, 0xFF, 0x69,
    0x33, 0x90, 0x00, 0x06, 0x00, 0xFF, 0x62, 0x63, 0x00, 0x00, 0x60, 0xFF, 0x5D, 0x88, 0x00, 0x00,
    0xC0, 0xFF, 0x69, 0x54, 0x00, 0x01, 0x80, 0xFF, 0x63, 0x96, 0x00, 0x00, 0xC0, 0xFF, 0x6A, 0x28,
    0x00, 0x01, 0x80, 0xFF, 0x64, 0xF0, 0x00, 0x01, 0x80, 0xFF, 0x6B, 0x14, 0x00, 0x01, 0x80, 0xFF,
    0x94, 0x46, 0x00, 0x00, 0xC0, 0xFF, 0xF9, 0x30, 0x00, 0x03, 0x00, 0xFF, 0xF9, 0x8B, 0x80, 0x00,
    0x30, 0xFF, 0xF3, 0x48, 0x00, 0x01, 0x80, 0xFF, 0xF8, 0xE1, 0x00, 0x00, 0x30, 0xFF, 0xF2, 0xFA,
    0x00, 0x00, 0x60, 0xFF, 0xFA, 0xCE, 0x00, 0x00, 0xC0, 0xFF,
];

const CVE_2010_2801_EXPECTED_LEN: usize = 524_159;

#[test]
fn cve_2010_2801_single_frame_oneshot() {
    // Decode just the first 32 KiB frame (one block + 0xFF trailer).
    // The first block is 14 bytes from the CAB plus the synthesised 0xFF.
    let single = &CVE_2010_2801_INPUT[..15];
    let out = decode_oneshot(single, 18, 32_768);
    assert_eq!(out.len(), 32_768, "expected one full frame of output");
    assert!(out.iter().all(|&b| b == 0), "all bytes should be zero");
}

#[test]
fn cve_2010_2801_full_oneshot() {
    let out = decode_oneshot(CVE_2010_2801_INPUT, 18, CVE_2010_2801_EXPECTED_LEN);
    assert_eq!(out.len(), CVE_2010_2801_EXPECTED_LEN);
    assert!(
        out.iter().all(|&b| b == 0),
        "expected 524159 zero bytes, found non-zero at index {}",
        out.iter().position(|&b| b != 0).unwrap_or(0)
    );
}

#[test]
fn cve_2010_2801_chunked_streaming() {
    // Feed input one byte at a time, drain into a small output buffer.
    let decoded = decode_chunked(CVE_2010_2801_INPUT, 18, CVE_2010_2801_EXPECTED_LEN, 1, 4096);
    assert_eq!(decoded.len(), CVE_2010_2801_EXPECTED_LEN);
    assert!(decoded.iter().all(|&b| b == 0));
}

#[test]
fn cve_2010_2801_tiny_output_buffer() {
    let decoded = decode_chunked(CVE_2010_2801_INPUT, 18, CVE_2010_2801_EXPECTED_LEN, 16, 1);
    assert_eq!(decoded.len(), CVE_2010_2801_EXPECTED_LEN);
    assert!(decoded.iter().all(|&b| b == 0));
}

// ─── real-world fixture: mszip_lzx_qtm.cab (qtm.txt) ─────────────────────

/// Quantum stream from `libmspack/test/test_files/cabd/mszip_lzx_qtm.cab`,
/// folder 2 (the Quantum folder). Single CFDATA block, 48 bytes plus the
/// 0xFF trailer cabd appends.
///
/// `window_bits = 18`.
///
/// Decodes to the ASCII string `"If you can read this, the Quantum
/// decompressor is working!\n"` (59 bytes).
const QTM_TXT_INPUT: &[u8] = &[
    0xD6, 0x06, 0x69, 0x0B, 0xCB, 0x47, 0xF0, 0x2C, 0x2A, 0x3A, 0x8F, 0x2C, 0xAB, 0xBB, 0x3C, 0xB9,
    0x33, 0x01, 0x8B, 0xD8, 0x58, 0x4B, 0x7B, 0x01, 0xBA, 0x6F, 0x6D, 0x51, 0x6E, 0x3A, 0xC3, 0x67,
    0x42, 0x4B, 0xEB, 0x02, 0x36, 0x43, 0xD6, 0x66, 0x56, 0xCA, 0x9E, 0x72, 0xCC, 0x30, 0x00, 0x00,
    0xFF,
];

const QTM_TXT_EXPECTED: &[u8] = b"If you can read this, the Quantum decompressor is working!\n";

#[test]
fn qtm_txt_oneshot() {
    let out = decode_oneshot(QTM_TXT_INPUT, 18, QTM_TXT_EXPECTED.len());
    assert_eq!(out, QTM_TXT_EXPECTED, "decoded text mismatch");
}

#[test]
fn qtm_txt_chunked_one_byte_at_a_time() {
    // Drive byte by byte. We stop driving once we've collected
    // `QTM_TXT_EXPECTED.len()` bytes — Quantum has no in-band length so the
    // caller (here, our test code; in real use, the CAB container) is
    // responsible for stopping at the expected output length.
    let out = decode_chunked(QTM_TXT_INPUT, 18, QTM_TXT_EXPECTED.len(), 1, 1);
    assert_eq!(out, QTM_TXT_EXPECTED);
}

// ─── error handling ───────────────────────────────────────────────────────

#[test]
fn truncated_input_does_not_panic() {
    // Truncate the first block's 14-byte payload so the decoder runs out of
    // bits mid-frame. The decoder should leave its state intact and return
    // with no panic; finish() should observe that nothing more is coming.
    let truncated = &CVE_2010_2801_INPUT[..5];
    let mut dec = Decoder::with_window_bits(18).unwrap();
    let mut out = vec![0u8; 32_768];
    // First decode: feed the truncated input.
    let p1 = dec.decode(truncated, &mut out).unwrap();
    // It may or may not produce output before stalling; key thing is no panic.
    let _ = p1;
    // Subsequent finish should not error catastrophically. It may report
    // done==true with written < expected (we accept this: caller's CAB
    // container detects truncation by counting output bytes).
    let mut tail = vec![0u8; 1024];
    let _ = dec.finish(&mut tail);
}

#[test]
fn corrupt_trailer_byte_rejected_in_full_stream() {
    // The cve-2010-2801 stream decodes through 15 inter-frame trailers
    // (each a 0xFF byte cabd injects between CFDATA blocks). If we corrupt
    // one of the trailer bytes to something that is neither 0x00 padding
    // nor 0xFF, the decoder should return Error::Corrupt when it tries to
    // realign at that frame boundary.
    let mut input = CVE_2010_2801_INPUT.to_vec();
    // The trailer of the first block sits at index 14 (the 0xFF), but the
    // bit-aligned trailer scan reads the *next byte after the bit-aligned
    // frame body*. In this fixture the byte at offset 14 is the synthetic
    // 0xFF appended by cabd; the bit reader sees it as the next byte after
    // realignment.
    input[14] = 0x42; // arbitrary non-zero, non-0xFF byte
    let mut dec = Decoder::with_window_bits(18).unwrap();
    let mut out = vec![0u8; CVE_2010_2801_EXPECTED_LEN];
    let r = dec.decode(&input, &mut out);
    // Either decode or a subsequent finish must report Corrupt.
    let err = match r {
        Ok(_) => {
            let mut more = vec![0u8; 16];
            // Drain & finish to give the trailer state a chance to execute.
            loop {
                match dec.decode(&[], &mut more) {
                    Ok(p) if p.written > 0 => continue,
                    Ok(_) => break,
                    Err(e) => return assert_eq!(e, Error::Corrupt),
                }
            }
            dec.finish(&mut more).err()
        }
        Err(e) => Some(e),
    };
    assert_eq!(err, Some(Error::Corrupt));
}

// ─── reset behaviour ──────────────────────────────────────────────────────

#[test]
fn reset_clears_state() {
    let mut dec = Decoder::with_window_bits(18).unwrap();
    let mut out = vec![0u8; 32_768];
    let _ = dec.decode(&CVE_2010_2801_INPUT[..15], &mut out).unwrap();
    // Try to also drain via finish to make sure all 32k zeros come out.
    let _ = dec.finish(&mut out).unwrap();

    dec.reset();

    // After reset, decoding the same input again should yield the same
    // 32 KiB of zeros, with no stale models or window contents leaking in.
    let mut out2 = vec![0u8; 32_768];
    let p = dec.decode(&CVE_2010_2801_INPUT[..15], &mut out2).unwrap();
    let mut total = p.written;
    while total < 32_768 {
        let p = dec.decode(&[], &mut out2[total..]).unwrap();
        if p.written == 0 {
            break;
        }
        total += p.written;
    }
    while total < 32_768 {
        let p = dec.finish(&mut out2[total..]).unwrap();
        if p.written == 0 {
            break;
        }
        total += p.written;
    }
    assert_eq!(total, 32_768);
    assert!(out2.iter().all(|&b| b == 0));
}

// ─── factory (only if the feature is enabled) ─────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_quantum_decoder_and_encoder() {
        // Either both present or both absent; we just check they're reachable
        // by name if the factory feature exposes them.
        let enc = factory::encoder_by_name("quantum");
        let dec = factory::decoder_by_name("quantum");
        // The factory may or may not expose Quantum depending on the
        // build; if it does, both should be Some.
        assert_eq!(enc.is_some(), dec.is_some());
    }
}
