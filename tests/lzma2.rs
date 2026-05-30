//! Public-API tests for the raw LZMA2 decoder (7-Zip coder id 21).
//!
//! The crate-private LZMA payload encoder is exercised by the in-module
//! unit tests (`src/lzma2/mod.rs`), which cover compressed multi-chunk
//! round-trips, dict resets, and 1-byte streaming. Here we validate the
//! public surface: decoding hand-framed *uncompressed* LZMA2 chunks (which
//! need no encoder), self-termination on the `0x00` control byte, the
//! factory wiring, and DoS hygiene on crafted input.

#![cfg(feature = "lzma2")]

use compcol::lzma2::{DecoderConfig, Lzma2};
#[allow(unused_imports)]
use compcol::{Algorithm, Decoder, Encoder, Error, Status};

/// Frame `data` as a single uncompressed dict-reset chunk (control 0x01)
/// followed by the 0x00 end marker. Uncompressed chunks carry the bytes
/// verbatim, so no encoder is needed to build a valid raw LZMA2 stream.
fn uncompressed_stream(data: &[u8]) -> Vec<u8> {
    assert!(!data.is_empty() && data.len() <= 1 << 16);
    let m1 = (data.len() - 1) as u16;
    let mut s = Vec::new();
    s.push(0x01);
    s.push((m1 >> 8) as u8);
    s.push((m1 & 0xFF) as u8);
    s.extend_from_slice(data);
    s.push(0x00);
    s
}

fn decode_all(stream: &[u8], cfg: DecoderConfig, out_cap: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Lzma2::decoder_with(cfg);
    let mut out = vec![0u8; out_cap + 16];
    let mut consumed = 0;
    let mut written = 0;
    loop {
        let (p, st) = dec.decode(&stream[consumed..], &mut out[written..])?;
        consumed += p.consumed;
        written += p.written;
        match st {
            Status::StreamEnd => break,
            Status::InputEmpty if consumed >= stream.len() => {
                dec.finish(&mut out[written..])?;
                break;
            }
            _ => {}
        }
    }
    out.truncate(written);
    Ok(out)
}

#[test]
fn uncompressed_chunk_roundtrip() {
    let data: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
    let stream = uncompressed_stream(&data);
    let got = decode_all(&stream, DecoderConfig::default(), data.len()).unwrap();
    assert_eq!(got, data);
}

#[test]
fn one_byte_streaming() {
    let data = b"streamed one byte at a time through every phase boundary".to_vec();
    let stream = uncompressed_stream(&data);
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let mut produced = Vec::new();
    let mut i = 0;
    let mut ob = [0u8; 1];
    loop {
        let inb = if i < stream.len() {
            &stream[i..i + 1]
        } else {
            &[][..]
        };
        let (p, st) = dec.decode(inb, &mut ob).unwrap();
        i += p.consumed;
        if p.written == 1 {
            produced.push(ob[0]);
        }
        if st == Status::StreamEnd {
            break;
        }
        assert!(
            !(p.consumed == 0 && p.written == 0 && i >= stream.len()),
            "stalled"
        );
    }
    assert_eq!(produced, data);
}

#[test]
fn empty_stream_is_just_end_marker() {
    let got = decode_all(&[0x00], DecoderConfig::default(), 0).unwrap();
    assert!(got.is_empty());
}

#[test]
fn truncated_stream_errors() {
    // Uncompressed chunk header promises 10 bytes but the stream is clipped.
    let stream = vec![0x01u8, 0x00, 0x09, 1, 2, 3];
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let mut out = [0u8; 32];
    let (_p, st) = dec.decode(&stream, &mut out).unwrap();
    assert_ne!(st, Status::StreamEnd);
    // No more input, no end marker → finish reports truncation.
    assert_eq!(dec.finish(&mut out), Err(Error::UnexpectedEnd));
}

#[test]
fn corrupt_control_rejected() {
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let mut out = [0u8; 16];
    // 0x7F is an invalid control byte.
    assert_eq!(dec.decode(&[0x7F], &mut out), Err(Error::Corrupt));
}

#[test]
fn invalid_dict_prop_poisons() {
    let mut dec = Lzma2::decoder_with(DecoderConfig::with_dict_prop(200));
    let mut out = [0u8; 16];
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Corrupt));
}

#[test]
#[cfg(feature = "factory")]
fn factory_wiring() {
    assert!(compcol::factory::names().contains(&"lzma2"));
    assert_eq!(compcol::factory::extension("lzma2"), Some("lzma2"));
    assert!(compcol::factory::decoder_by_name("lzma2").is_some());
    // Encoder resolves but is an Unsupported stub.
    let mut enc = compcol::factory::encoder_by_name("lzma2").expect("encoder present");
    let mut out = [0u8; 16];
    assert_eq!(enc.encode(b"x", &mut out), Err(Error::Unsupported));
}
