//! Integration coverage for the newly added codecs: the four standalone
//! `Algorithm` primitives reachable through the factory, and the QPACK
//! header-codec module API.

#![cfg(all(
    feature = "factory",
    feature = "huffman",
    feature = "rangecoder",
    feature = "mtf",
    feature = "bwt",
    feature = "qpack"
))]

use compcol::{Decoder, Encoder, Status};

/// Drive a boxed encoder, then a boxed decoder, over `data` and return the
/// decoded output.
fn round_trip_by_name(name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = compcol::factory::encoder_by_name(name).expect("encoder");
    let mut dec = compcol::factory::decoder_by_name(name).expect("decoder");

    let mut encoded = Vec::new();
    let mut buf = vec![0u8; 512];
    let mut pos = 0;
    while pos < data.len() {
        let (p, _) = enc.encode(&data[pos..], &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, st) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }

    let mut decoded = Vec::new();
    let mut pos = 0;
    while pos < encoded.len() {
        let (p, _) = dec.decode(&encoded[pos..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, st) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }
    decoded
}

#[test]
fn factory_round_trips_new_primitives() {
    let corpus: [&[u8]; 4] = [
        b"",
        b"the quick brown fox jumps over the lazy dog",
        &[0u8; 4096],
        b"mississippi banana bandana ananas",
    ];
    for name in ["huffman", "range", "mtf", "bwt"] {
        for data in corpus {
            assert_eq!(
                round_trip_by_name(name, data),
                data,
                "round-trip mismatch for codec {name} on {} bytes",
                data.len()
            );
        }
    }
}

#[test]
fn new_codecs_registered_in_names() {
    let names = compcol::factory::names();
    for n in ["huffman", "range", "mtf", "bwt"] {
        assert!(names.contains(&n), "{n} not registered in factory::names()");
        assert!(
            compcol::factory::extension(n).is_some(),
            "{n} has no extension"
        );
    }
}

#[test]
fn qpack_module_round_trips() {
    use compcol::hpack::HeaderField;
    use compcol::qpack::{QpackDecoder, QpackEncoder};

    let mut enc = QpackEncoder::new();
    let mut dec = QpackDecoder::new();
    let fields = [
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/"),
        HeaderField::new(b"user-agent", b"compcol-test/1.0"),
    ];
    let block = enc.encode_field_section(&fields);
    let out = dec.decode_field_section(&block).unwrap();
    assert_eq!(out, fields);
}
