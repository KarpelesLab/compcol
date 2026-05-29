//! Regression tests for `impl Encoder for Box<dyn Encoder>` and the
//! `Decoder` mirror — together they let the runtime by-name factory
//! plug into the `compcol::io` adapters and any other generic code.

#![cfg(all(feature = "factory", feature = "std", feature = "gzip"))]

use std::io::{Cursor, Read, Write};

use compcol::factory;
use compcol::io::{DecoderReader, EncoderWriter};

#[test]
fn factory_boxes_compose_with_io_adapters() {
    let plain = b"factory + io adapter composition smoke test\n";

    // Box<dyn Encoder> from runtime lookup.
    let enc = factory::encoder_by_name("gzip").expect("gzip available");
    let mut w = EncoderWriter::new(Vec::<u8>::new(), enc);
    w.write_all(plain).unwrap();
    let compressed = w.finish().unwrap();

    // Box<dyn Decoder> the same way.
    let dec = factory::decoder_by_name("gzip").expect("gzip available");
    let mut r = DecoderReader::new(Cursor::new(&compressed), dec);
    let mut decoded = Vec::new();
    r.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, plain);
}

#[test]
fn boxed_encoder_round_trip_via_trait_methods() {
    use compcol::{Decoder as _, Encoder as _, Status};
    let mut enc: Box<dyn compcol::Encoder> = factory::encoder_by_name("gzip").unwrap();
    let mut out = vec![0u8; 4096];
    let mut compressed = Vec::new();
    let plain = b"hello via Box<dyn Encoder>";
    let mut consumed = 0;
    while consumed < plain.len() {
        let (p, st) = enc.encode(&plain[consumed..], &mut out).unwrap();
        compressed.extend_from_slice(&out[..p.written]);
        consumed += p.consumed;
        if matches!(st, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, st) = enc.finish(&mut out).unwrap();
        compressed.extend_from_slice(&out[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }

    let mut dec: Box<dyn compcol::Decoder> = factory::decoder_by_name("gzip").unwrap();
    let mut decoded = Vec::new();
    let mut c2 = 0;
    while c2 < compressed.len() {
        let (p, st) = dec.decode(&compressed[c2..], &mut out).unwrap();
        decoded.extend_from_slice(&out[..p.written]);
        c2 += p.consumed;
        if matches!(st, Status::StreamEnd | Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, st) = dec.finish(&mut out).unwrap();
        decoded.extend_from_slice(&out[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }
    assert_eq!(decoded, plain);
}
