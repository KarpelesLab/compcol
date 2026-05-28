//! Streaming round-trip tests for the Snappy algorithm.
//!
//! Canonical v0.3 port: every call returns `(Progress, Status)` and the
//! loop dispatches on `Status` rather than inferring from byte counts.
//!
//! Snappy is a whole-block codec: the encoder buffers all input on
//! `encode` and only emits compressed bytes from `finish`. The same is
//! true of the decoder. Each `encode` call therefore reports
//! `Status::InputEmpty` (it consumed every byte the caller offered), and
//! `finish` reports `Status::OutputFull` until the buffered block has
//! drained, at which point it reports `Status::StreamEnd`.

#![cfg(feature = "snappy")]

use compcol::snappy::{Decoder, Encoder, Snappy};
use compcol::{Algorithm, Decoder as _, Encoder as _, Status};

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk.max(1)).min(input.len());
        let chunk = &input[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }

    encoded
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < encoded.len() {
        let end = (i + in_chunk.max(1)).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled");
                }
            }
        }
    }

    decoded
}

fn round_trip(input: &[u8]) {
    // Pick chunk sizes scaled to the input to keep tests snappy.
    let chunk_in = (input.len() / 4).max(1);
    let chunk_out = (input.len() / 4).max(16);
    let encoded = encode_chunked(input, chunk_in, chunk_out);
    let decoded = decode_chunked(&encoded, chunk_in, chunk_out);
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert!(decoded == input, "round-trip byte mismatch");
}

#[test]
fn name_is_snappy() {
    assert_eq!(<Snappy as Algorithm>::NAME, "snappy");
}

#[test]
fn empty_round_trip() {
    round_trip(&[]);
}

#[test]
fn single_byte() {
    round_trip(&[0xA5]);
}

#[test]
fn hello_world() {
    round_trip(b"hello world");
}

#[test]
fn long_run_of_one_byte() {
    // 10 KiB of the same byte — should compress to a tiny output via the
    // self-overlapping copy trick.
    let input = vec![0x7Fu8; 10 * 1024];
    round_trip(&input);
}

#[test]
fn ascii_text_over_64_kib() {
    // 65 KiB of ASCII with frequent repetition. Exercises 2-byte offsets
    // (since offsets cross the 32 KiB threshold) and multi-byte literal
    // length encodings if any one literal grows large.
    let phrase = b"The quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(70 * 1024);
    while input.len() < 65 * 1024 {
        input.extend_from_slice(phrase);
    }
    round_trip(&input);
    // The compressed form should be substantially smaller than the input.
    let encoded = encode_chunked(&input, input.len(), input.len() * 2 + 8);
    assert!(
        encoded.len() < input.len() / 2,
        "expected at least 2x compression on repetitive ASCII, got {} -> {}",
        input.len(),
        encoded.len()
    );
}

#[test]
fn mixed_corpus_over_64_kib() {
    // ≥ 64 KiB mixture of repetitive runs and pseudo-random noise — stresses
    // both the matcher (long copies, multi-tag splits) and the literal path
    // (multi-byte literal length encoding when noise stretches don't match).
    let mut input = Vec::with_capacity(80 * 1024);
    let phrase = b"The quick brown fox jumps over the lazy dog. ";
    while input.len() < 32 * 1024 {
        input.extend_from_slice(phrase);
    }
    let mut state: u32 = 0xFEEDFACEu32;
    for _ in 0..16 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    // Add another repetitive section that back-references the first.
    while input.len() < 80 * 1024 {
        input.extend_from_slice(phrase);
    }
    assert!(input.len() >= 64 * 1024);
    round_trip(&input);
}

#[test]
fn pseudo_random_data() {
    // Tiny LCG keeps the test dependency-free and deterministic.
    let mut state: u32 = 0xDECAFBADu32;
    let mut input = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn chunked_one_byte_at_a_time() {
    // The acid test: 1-byte input chunks and 1-byte output buffers on
    // both sides. Even though Snappy's streaming model buffers the whole
    // block internally, the public encode/decode/finish dance must still
    // converge byte-by-byte.
    let mut input = Vec::with_capacity(200);
    for i in 0..200u32 {
        input.push((i * 31) as u8);
    }
    // Add a recognisable repeat so the matcher gets exercised too.
    let tail = input.clone();
    input.extend_from_slice(&tail[..50]);

    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn encode_reports_input_empty() {
    // Snappy buffers the whole input internally during `encode`, so every
    // encode call must report InputEmpty (it accepted every byte) and emit
    // zero output bytes (nothing is committed until `finish`).
    let mut enc = Encoder::new();
    let mut out = [0u8; 32];
    let (p, status) = enc.encode(b"hello", &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
}

#[test]
fn finish_streams_end_marker() {
    // After a single `finish` call with ample buffer, we must observe the
    // `StreamEnd` status — and a subsequent `finish` call should be the
    // documented no-op (`Progress { 0, 0 }`, `StreamEnd`).
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"hello world", &mut out).unwrap();
    let (_p, status) = enc.finish(&mut out).unwrap();
    assert!(matches!(status, Status::StreamEnd));
    let (p2, status2) = enc.finish(&mut out).unwrap();
    assert_eq!(p2.written, 0);
    assert!(matches!(status2, Status::StreamEnd));
}

#[test]
fn finish_drains_across_calls() {
    // Force `finish` to drain in multiple steps by giving it a 1-byte
    // output buffer at a time. Must converge with one final StreamEnd.
    let phrase = b"hello hello hello hello hello hello hello hello";
    let mut enc = Encoder::new();
    let mut tiny = [0u8; 1];
    let (p, status) = enc.encode(phrase, &mut tiny).unwrap();
    assert_eq!(p.consumed, phrase.len());
    assert!(matches!(status, Status::InputEmpty));
    let mut produced = Vec::new();
    loop {
        let (p, status) = enc.finish(&mut tiny).unwrap();
        produced.extend_from_slice(&tiny[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }
    // Decode and check.
    let decoded = decode_chunked(&produced, 1, 1);
    assert_eq!(decoded, phrase);
}

#[test]
fn reset_clears_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"first input data", &mut out).unwrap();
    enc.reset();
    // After reset, only the second input should appear in the output.
    let _ = enc.encode(b"hello", &mut out).unwrap();
    let mut produced = Vec::new();
    loop {
        let (p, status) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }

    let mut dec = Decoder::new();
    let _ = dec.decode(&produced, &mut out).unwrap();
    let mut decoded = Vec::new();
    loop {
        let (p, status) = dec.finish(&mut out).unwrap();
        decoded.extend_from_slice(&out[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled");
                }
            }
        }
    }
    assert_eq!(&decoded, b"hello");
}

#[test]
fn reset_clears_decoder_state() {
    // After reset(), the decoder must forget its previous (already-decoded)
    // input and decode the next stream from scratch.
    let encoded_hello = encode_chunked(b"hello", 32, 32);
    let encoded_world = encode_chunked(b"world", 32, 32);

    let mut dec = Decoder::new();
    let decoded = decode_full(&mut dec, &encoded_hello);
    assert_eq!(&decoded, b"hello");

    dec.reset();
    let decoded = decode_full(&mut dec, &encoded_world);
    assert_eq!(&decoded, b"world");
}

fn decode_full(dec: &mut Decoder, encoded: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    let mut consumed = 0;
    while consumed < encoded.len() {
        let (p, _status) = dec.decode(&encoded[consumed..], &mut out).unwrap();
        consumed += p.consumed;
        // decode emits nothing; just keep feeding.
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    let mut decoded = Vec::new();
    loop {
        let (p, status) = dec.finish(&mut out).unwrap();
        decoded.extend_from_slice(&out[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled");
                }
            }
        }
    }
    decoded
}

#[test]
fn decoder_rejects_truncated_block() {
    // A varint header alone with no payload is not a valid block (length > 0
    // but no tags follow). `finish` should surface an error.
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    // Encode "hi" and then truncate down to just the varint + tag byte
    // (deliberately missing the literal payload).
    let full = encode_chunked(b"hi", 32, 32);
    assert!(full.len() >= 3);
    let truncated = &full[..full.len() - 1];
    let _ = dec.decode(truncated, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    let _ = err; // any decoder error is fine — we just require non-Ok.
}

#[test]
fn decoder_rejects_completely_empty_input() {
    // Calling `finish` with no input bytes ever delivered must fail —
    // the varint header is mandatory.
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.finish(&mut out).unwrap_err();
    let _ = err;
}

#[test]
fn decoder_rejects_corrupt_offset() {
    // Hand-craft a tiny block: varint length = 4, then a "copy with 1-byte
    // offset" tag pointing past the start of the block. Must fail at decode.
    // Tag layout for 01-tag: length-4 in bits 2..=4, offset hi 3 bits in
    // 5..=7. Pick length=4 (so length-4=0), offset=10 (well past 0 bytes
    // emitted) so off_hi=0, low=10.
    let block = [0x04u8, 0b00_000_001u8, 0x0A];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let _ = dec.decode(&block, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    let _ = err;
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("snappy").is_some());
        assert!(factory::decoder_by_name("snappy").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("does-not-exist").is_none());
        assert!(factory::decoder_by_name("does-not-exist").is_none());
    }

    #[test]
    fn names_contains_snappy() {
        assert!(factory::names().contains(&"snappy"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("snappy").unwrap();
        let mut dec = factory::decoder_by_name("snappy").unwrap();
        let input = b"hello hello hello";
        let mut scratch = vec![0u8; 64];
        let (_p, status) = enc.encode(input, &mut scratch).unwrap();
        // Snappy's encode buffers everything; written == 0, status == InputEmpty.
        assert!(matches!(status, Status::InputEmpty));

        let mut encoded = Vec::new();
        loop {
            let (pf, status) = enc.finish(&mut scratch).unwrap();
            encoded.extend_from_slice(&scratch[..pf.written]);
            match status {
                Status::StreamEnd => break,
                Status::OutputFull | Status::InputEmpty => {
                    if pf.written == 0 {
                        panic!("encoder finish stalled");
                    }
                }
            }
        }

        let (_pd, status) = dec.decode(&encoded, &mut scratch).unwrap();
        assert!(matches!(status, Status::InputEmpty));
        let mut decoded = Vec::new();
        loop {
            let (pf, status) = dec.finish(&mut scratch).unwrap();
            decoded.extend_from_slice(&scratch[..pf.written]);
            match status {
                Status::StreamEnd => break,
                Status::OutputFull | Status::InputEmpty => {
                    if pf.written == 0 {
                        panic!("decoder finish stalled");
                    }
                }
            }
        }
        assert_eq!(&decoded, input);
    }
}
