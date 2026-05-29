//! Streaming round-trip tests for the LZNT1 (NTFS native) codec.
//!
//! LZNT1 splits the stream into independent 4 KiB chunks; each chunk
//! either carries its raw bytes or a sequence of LZ77 flag-group
//! tokens. Tests here exercise:
//!
//! - The encoder + decoder round-trip on empty, short, and large inputs.
//! - Hand-crafted small fixtures derived directly from the MS-XCA spec
//!   so the decoder is checked against bytes we computed by hand
//!   (independent of the encoder).
//! - Error paths (truncated stream, bad chunk header signature,
//!   self-overlap with no history, oversize back-reference distance).
//! - The runtime factory and by-name lookup.
//!
//! No external `ntfscompress` tool is available in this build
//! environment, so the decoder-only fixtures are limited to those a
//! human can derive from MS-XCA section 2.5 directly. The round-trip
//! suite below covers the much larger property: "for every input the
//! encoder produces a byte sequence the decoder accepts".

#![cfg(feature = "lznt1")]

use compcol::lznt1::{Decoder, Encoder, EncoderConfig, Lznt1};
use compcol::{Algorithm, Decoder as _, Encoder as _, Status};

// ─── chunked drivers ──────────────────────────────────────────────────────

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

    // Drain any remaining buffered output with empty input.
    loop {
        let (p, status) = dec.decode(&[], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if p.written == 0 || matches!(status, Status::StreamEnd | Status::InputEmpty) {
            break;
        }
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
    let big = input.len().saturating_mul(2).max(2048);
    let encoded = encode_chunked(input, big, big);
    let decoded = decode_chunked(&encoded, big, big);
    assert_eq!(
        decoded.len(),
        input.len(),
        "round-trip length mismatch: in={} out={}",
        input.len(),
        decoded.len()
    );
    assert!(decoded == input, "round-trip content mismatch");
}

// ─── algorithm identity ───────────────────────────────────────────────────

#[test]
fn name_is_lznt1() {
    assert_eq!(<Lznt1 as Algorithm>::NAME, "lznt1");
}

#[test]
fn default_constructors() {
    let _enc: Encoder = <Lznt1 as Algorithm>::encoder();
    let _dec: Decoder = <Lznt1 as Algorithm>::decoder();
    let _enc2 = Encoder::default();
    let _dec2 = Decoder::default();
    let _enc3 = Encoder::with_config(EncoderConfig);
}

// ─── round-trip suite ─────────────────────────────────────────────────────

#[test]
fn empty_input() {
    round_trip(&[]);
}

#[test]
fn single_byte() {
    round_trip(&[0x42]);
}

#[test]
fn hello_world() {
    round_trip(b"hello world");
}

#[test]
fn zeros_1k() {
    round_trip(&[0u8; 1024]);
}

#[test]
fn zeros_64k() {
    round_trip(&[0u8; 64 * 1024]);
}

#[test]
fn ascending_4k() {
    let input: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    round_trip(&input);
}

#[test]
fn at_chunk_boundary_4096() {
    let input: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
    round_trip(&input);
}

#[test]
fn at_chunk_boundary_4097() {
    // Exercise the boundary one byte past CHUNK_SIZE.
    let mut input: Vec<u8> = (0..4096u32).map(|i| ((i * 31) & 0xFF) as u8).collect();
    input.push(0xAA);
    round_trip(&input);
}

#[test]
fn lcg_64k_pseudo_random() {
    // LCG output has effectively no matches; encoder must fall back
    // to uncompressed chunks throughout.
    let mut state: u32 = 0xDEAD_BEEFu32;
    let mut input = Vec::with_capacity(64 * 1024);
    for _ in 0..64 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn mixed_corpus_over_64_kib() {
    let mut input = Vec::with_capacity(80 * 1024);
    let phrase = b"The quick brown fox jumps over the lazy dog. ";
    while input.len() < 24 * 1024 {
        input.extend_from_slice(phrase);
    }
    let mut state: u32 = 0xC0FFEEu32;
    for _ in 0..24 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    while input.len() < 70 * 1024 {
        input.extend_from_slice(phrase);
    }
    assert!(input.len() >= 64 * 1024);
    round_trip(&input);
}

#[test]
fn one_byte_chunked() {
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

// ─── compression effectiveness ────────────────────────────────────────────

#[test]
fn highly_repetitive_input_compresses() {
    // 4096 identical bytes should produce a compressed chunk smaller
    // than 4096 + 2 header bytes.
    let input = vec![0xABu8; 4096];
    let encoded = encode_chunked(&input, 4096, 8192);
    // header(2) + body + trailing zero word (2). Compressed body must
    // be well under 4096 — for a flat run the encoder emits a single
    // literal and a self-overlap back-reference.
    assert!(
        encoded.len() < 64,
        "expected high compression for flat run, got {} bytes",
        encoded.len()
    );
    let decoded = decode_chunked(&encoded, 4096, 8192);
    assert_eq!(decoded, input);
}

#[test]
fn incompressible_falls_back_to_uncompressed() {
    // LCG noise should not compress; encoder should emit an
    // uncompressed chunk (high bit of header = 0).
    let mut state: u32 = 0xDECAFBADu32;
    let mut input = Vec::with_capacity(4096);
    for _ in 0..4096 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    let encoded = encode_chunked(&input, 4096, 8192);
    // Find the first chunk header and verify the compressed flag is 0.
    assert!(encoded.len() >= 2);
    let hdr = u16::from_le_bytes([encoded[0], encoded[1]]);
    assert_eq!(
        hdr & 0x8000,
        0,
        "expected uncompressed chunk for LCG noise, got header {hdr:#06x}"
    );
    // Signature still required.
    assert_eq!((hdr >> 12) & 0x7, 0b011, "signature must be 0b011");
    let decoded = decode_chunked(&encoded, 4096, 8192);
    assert_eq!(decoded, input);
}

// ─── streaming-shape ─────────────────────────────────────────────────────

#[test]
fn encode_reports_input_empty() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 32];
    let (p, status) = enc.encode(b"hello", &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
}

#[test]
fn finish_streams_end_marker() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"hello world", &mut out).unwrap();
    let mut produced = Vec::new();
    loop {
        let (p, status) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }
    // Subsequent finish must be a no-op.
    let (p2, status2) = enc.finish(&mut out).unwrap();
    assert_eq!(p2.written, 0);
    assert!(matches!(status2, Status::StreamEnd));
}

#[test]
fn finish_drains_across_calls() {
    // 1-byte output buffer forces `finish` to make many calls.
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
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }
    let decoded = decode_chunked(&produced, 1, 1);
    assert_eq!(&decoded, phrase);
}

#[test]
fn reset_clears_encoder_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 256];
    let _ = enc
        .encode(b"first run, will be discarded", &mut out)
        .unwrap();
    enc.reset();

    let _ = enc.encode(b"second run", &mut out).unwrap();
    let mut produced = Vec::new();
    loop {
        let (p, status) = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }

    let decoded = decode_chunked(&produced, produced.len(), 256);
    assert_eq!(&decoded, b"second run");
}

#[test]
fn reset_clears_decoder_state() {
    let encoded_hello = encode_chunked(b"hello", 32, 32);
    let encoded_world = encode_chunked(b"world", 32, 32);

    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    let mut consumed = 0;
    let mut decoded = Vec::new();
    while consumed < encoded_hello.len() {
        let (p, _) = dec.decode(&encoded_hello[consumed..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    assert_eq!(&decoded, b"hello");

    dec.reset();

    let mut decoded2 = Vec::new();
    let mut consumed = 0;
    while consumed < encoded_world.len() {
        let (p, _) = dec.decode(&encoded_world[consumed..], &mut buf).unwrap();
        decoded2.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded2.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    assert_eq!(&decoded2, b"world");
}

// ─── hand-crafted decoder fixtures (derived from MS-XCA spec) ─────────────

#[test]
fn decoder_accepts_zero_terminator_only() {
    // A bare two-byte zero word is a legitimate end-of-stream marker.
    let encoded = [0u8, 0u8];
    let decoded = decode_chunked(&encoded, 16, 16);
    assert!(decoded.is_empty());
}

#[test]
fn decoder_uncompressed_chunk_passthrough() {
    // Header: signature 0b011 in bits 14..12, compressed flag = 0,
    // size field = 5 - 1 = 4. So header = 0x3004, little-endian
    // [0x04, 0x30]. Body: "hello".
    let encoded = [0x04, 0x30, b'h', b'e', b'l', b'l', b'o'];
    let decoded = decode_chunked(&encoded, 16, 16);
    assert_eq!(&decoded, b"hello");
}

#[test]
fn decoder_compressed_chunk_literal_then_match() {
    // Build a hand-crafted chunk that emits "ABCABCABCABCABCA" (16
    // bytes total = 3 literals "ABC" + a 13-byte self-overlap match
    // at offset 3).
    //
    // Tokens in the flag group:
    //   bit 0: literal 'A'
    //   bit 1: literal 'B'
    //   bit 2: literal 'C'
    //   bit 3: match (offset=3, length=13)
    // flag = 0b0000_1000 = 0x08
    //
    // Match token: pos_before = 3, split table → offset_bits=12,
    // length_bits=4. off_code = 3-1 = 2, len_code = 13-3 = 10.
    // token = (2 << 4) | 10 = 0x2A = 42 → little-endian [0x2A, 0x00].
    //
    // Compressed body: [flag, 'A', 'B', 'C', token_lo, token_hi]
    //                = [0x08, 0x41, 0x42, 0x43, 0x2A, 0x00]
    // body length = 6. header = 0xB000 | (6-1) = 0xB005, LE [0x05, 0xB0]
    let encoded = [
        0x05, 0xB0, // header (compressed, size 6)
        0x08, // flag byte: bit 3 set
        0x41, 0x42, 0x43, // literals 'A', 'B', 'C'
        0x2A, 0x00, // match token: offset 3, length 13
    ];
    let decoded = decode_chunked(&encoded, 16, 32);
    assert_eq!(&decoded, b"ABCABCABCABCABCA");
}

#[test]
fn decoder_rejects_bad_signature() {
    // Compressed flag = 1, signature = 0b010 (invalid), size = 4.
    // header = 0x8000 | (0b010 << 12) | 3 = 0xA003 → LE [0x03, 0xA0]
    let encoded = [0x03, 0xA0, 0x00, 0x41, 0x42, 0x43];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let res = dec.decode(&encoded, &mut out);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), compcol::Error::BadHeader);
}

#[test]
fn decoder_rejects_match_with_no_history() {
    // Compressed chunk where the first token is a match (no history).
    // flag = 0x01 → first token is a match. token = 0 → would imply
    // offset=1, length=3 but pos=0 → InvalidDistance/Corrupt.
    // body = [flag, token_lo, token_hi] = [0x01, 0x00, 0x00], len=3
    // header = 0xB002 → LE [0x02, 0xB0].
    let encoded = [0x02, 0xB0, 0x01, 0x00, 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let res = dec.decode(&encoded, &mut out);
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        compcol::Error::Corrupt | compcol::Error::InvalidDistance
    ));
}

#[test]
fn decoder_rejects_match_past_history() {
    // 2 literals then a match with offset 5 (past available history).
    // flag = 0b100 = 0x04, tokens: 'A', 'B', match(offset=5, len=3)
    // pos before match = 2, split = (12,4). off_code = 5-1 = 4,
    // len_code = 0. token = (4 << 4) | 0 = 0x40 → LE [0x40, 0x00].
    // body = [0x04, 'A', 'B', 0x40, 0x00], len=5
    // header = 0xB004 → LE [0x04, 0xB0].
    let encoded = [0x04, 0xB0, 0x04, b'A', b'B', 0x40, 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let res = dec.decode(&encoded, &mut out);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), compcol::Error::InvalidDistance);
}

#[test]
fn decoder_rejects_truncated_header() {
    // Single byte in stream — header is not complete; finish must
    // detect the truncated state.
    let encoded = [0x05];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let _ = dec.decode(&encoded, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, compcol::Error::UnexpectedEnd);
}

#[test]
fn decoder_rejects_truncated_body() {
    // Header claims a 5-byte uncompressed body but only 2 follow.
    let encoded = [0x04, 0x30, b'h', b'e'];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let _ = dec.decode(&encoded, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, compcol::Error::UnexpectedEnd);
}

// ─── multi-chunk fixture ─────────────────────────────────────────────────

#[test]
fn decoder_handles_two_uncompressed_chunks() {
    // Two consecutive small uncompressed chunks, then zero terminator.
    let mut encoded = Vec::new();
    // Chunk 1: "ABC" (size 3, header 0x3002)
    encoded.extend_from_slice(&[0x02, 0x30, b'A', b'B', b'C']);
    // Chunk 2: "XYZ"
    encoded.extend_from_slice(&[0x02, 0x30, b'X', b'Y', b'Z']);
    // Terminator
    encoded.extend_from_slice(&[0x00, 0x00]);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(&decoded, b"ABCXYZ");
}

// ─── factory ─────────────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lznt1").is_some());
        assert!(factory::decoder_by_name("lznt1").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("does-not-exist").is_none());
        assert!(factory::decoder_by_name("does-not-exist").is_none());
    }

    #[test]
    fn names_contains_lznt1() {
        assert!(factory::names().contains(&"lznt1"));
    }

    #[test]
    fn extension_is_lznt1() {
        assert_eq!(factory::extension("lznt1"), Some("lznt1"));
    }

    #[test]
    fn boxed_round_trip() {
        let mut enc = factory::encoder_by_name("lznt1").unwrap();
        let mut dec = factory::decoder_by_name("lznt1").unwrap();
        let input = b"hello hello hello hello hello hello";
        let mut scratch = vec![0u8; 256];
        let (_p, status) = enc.encode(input, &mut scratch).unwrap();
        assert!(matches!(status, Status::InputEmpty));

        let mut encoded = Vec::new();
        loop {
            let (pf, status) = enc.finish(&mut scratch).unwrap();
            encoded.extend_from_slice(&scratch[..pf.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if pf.written == 0 {
                panic!("encoder finish stalled");
            }
        }

        let mut decoded = Vec::new();
        let mut i = 0;
        while i < encoded.len() {
            let (pd, _) = dec.decode(&encoded[i..], &mut scratch).unwrap();
            decoded.extend_from_slice(&scratch[..pd.written]);
            i += pd.consumed;
            if pd.consumed == 0 && pd.written == 0 {
                break;
            }
        }
        loop {
            let (pf, status) = dec.finish(&mut scratch).unwrap();
            decoded.extend_from_slice(&scratch[..pf.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if pf.written == 0 {
                panic!("decoder finish stalled");
            }
        }
        assert_eq!(&decoded, input);
    }
}
