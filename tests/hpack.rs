#![cfg(feature = "hpack")]
//! Integration tests for the HPACK module: the public header-codec API, the
//! `Http2Huffman` streaming codec, and factory-by-name lookup.

use compcol::hpack::{HeaderField, Http2Huffman, HpackDecoder, HpackEncoder};
use compcol::{Algorithm, Decoder, Encoder, Status};

/// Drive a streaming encoder to completion over the whole input.
fn run_enc<E: Encoder>(mut enc: E, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256];
    let mut consumed = 0;
    while consumed < data.len() {
        let (p, _) = enc.encode(&data[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, st) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }
    out
}

/// Drive a streaming decoder to completion over the whole input.
fn run_dec<D: Decoder>(mut dec: D, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256];
    let mut consumed = 0;
    while consumed < data.len() {
        let (p, _) = dec.decode(&data[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, st) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }
    out
}

#[test]
fn http2_huffman_codec_round_trips() {
    let inputs: [&[u8]; 4] = [
        b"",
        b"www.example.com",
        b"the quick brown fox jumps over the lazy dog",
        &[0u8, 1, 2, 254, 255, 128, 127],
    ];
    for inp in inputs {
        let encoded = run_enc(Http2Huffman::encoder(), inp);
        let decoded = run_dec(Http2Huffman::decoder(), &encoded);
        assert_eq!(decoded, inp, "round-trip mismatch for {inp:?}");
    }
}

#[test]
fn http2_huffman_known_vector() {
    // RFC 7541 C.4.1 string.
    let encoded = run_enc(Http2Huffman::encoder(), b"www.example.com");
    assert_eq!(
        encoded,
        [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
    );
}

#[cfg(feature = "factory")]
#[test]
fn factory_exposes_h2_huffman() {
    assert!(compcol::factory::encoder_by_name("h2-huffman").is_some());
    assert!(compcol::factory::decoder_by_name("h2-huffman").is_some());
    assert!(compcol::factory::names().contains(&"h2-huffman"));
}

#[test]
fn full_hpack_round_trip_across_blocks() {
    // A single encoder/decoder pair carrying dynamic-table state across two
    // header blocks (a realistic HTTP/2 connection).
    let mut enc = HpackEncoder::new();
    let mut dec = HpackDecoder::new();

    let block_a = [
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/resource"),
        HeaderField::new(b"accept", b"text/html"),
        HeaderField::sensitive(b"authorization", b"Bearer xyz"),
    ];
    let e = enc.encode(&block_a);
    assert_eq!(dec.decode(&e).unwrap(), block_a);

    // Second block reuses fields now in the dynamic table.
    let block_b = [
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/resource"),
        HeaderField::new(b"accept", b"text/html"),
    ];
    let e = enc.encode(&block_b);
    // Reused fields should compress to a few bytes (all indexed).
    assert!(e.len() <= 4, "expected indexed reuse, got {e:?}");
    assert_eq!(dec.decode(&e).unwrap(), block_b);
}

#[test]
fn raw_mode_matches_decoder() {
    let mut enc = HpackEncoder::new();
    enc.set_huffman(false);
    let mut dec = HpackDecoder::new();
    let fields = [
        HeaderField::new(b"x-custom-header", b"some long-ish value 123456"),
        HeaderField::new(b"another", b"\x00\x01\x02 binary-ish"),
    ];
    let block = enc.encode(&fields);
    assert_eq!(dec.decode(&block).unwrap(), fields);
}
