//! Public-API tests for the raw LZMA2 codec (7-Zip coder id 21).
//!
//! The in-module unit tests (`src/lzma2/mod.rs`) cover encoder/decoder
//! round-trips, dict resets, fallback, and 1-byte streaming. Here we
//! validate the public surface: encoder→decoder round-trips through the
//! `Lzma2` public types, decoding hand-framed *uncompressed* LZMA2 chunks,
//! self-termination on the `0x00` control byte, cross-validation against the
//! shared `xz` chunk codec, the factory wiring, and DoS hygiene on crafted
//! input.

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
    // The encoder is now a real working encoder: a factory-built encoder
    // round-trips through a factory-built decoder.
    let data = b"factory-routed lzma2 round-trip round-trip round-trip";
    let mut enc = compcol::factory::encoder_by_name("lzma2").expect("encoder present");
    let mut stream = Vec::new();
    let mut obuf = [0u8; 256];
    let (p, _) = enc.encode(data, &mut obuf).unwrap();
    stream.extend_from_slice(&obuf[..p.written]);
    loop {
        let (p, st) = enc.finish(&mut obuf).unwrap();
        stream.extend_from_slice(&obuf[..p.written]);
        if st == Status::StreamEnd {
            break;
        }
    }
    let got = decode_all(&stream, DecoderConfig::default(), data.len()).unwrap();
    assert_eq!(got, data);
}

/// Encode `data` with the public raw LZMA2 [`Lzma2`] encoder, draining
/// `output` in `out_chunk`-sized slices to exercise the streaming API.
fn encode_all(data: &[u8], out_chunk: usize) -> Vec<u8> {
    let mut enc = Lzma2::encoder_with(());
    let mut stream = Vec::new();
    let mut obuf = vec![0u8; out_chunk];
    let mut consumed = 0;
    loop {
        let (p, st) = enc.encode(&data[consumed..], &mut obuf).unwrap();
        stream.extend_from_slice(&obuf[..p.written]);
        consumed += p.consumed;
        match st {
            Status::InputEmpty => break,
            Status::OutputFull => {}
            Status::StreamEnd => unreachable!(),
        }
    }
    loop {
        let (p, st) = enc.finish(&mut obuf).unwrap();
        stream.extend_from_slice(&obuf[..p.written]);
        if st == Status::StreamEnd {
            break;
        }
    }
    stream
}

#[test]
fn encoder_decoder_roundtrip_public() {
    // Cover the required spread of input shapes through the public API.
    let zeros = vec![0u8; 130 * 1024];
    let big: Vec<u8> = (0u32..150_000)
        .map(|i| (i.wrapping_mul(2654435761) >> 19) as u8)
        .collect();
    let mut rnd = vec![0u8; 8192];
    let mut x = 0x9e37_79b9u32;
    for b in rnd.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = (x >> 24) as u8;
    }
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"q".to_vec(),
        b"the quick brown fox jumps over the lazy dog".to_vec(),
        zeros,
        big,
        rnd,
    ];
    for data in &cases {
        for out_chunk in [7usize, 1 << 16] {
            let stream = encode_all(data, out_chunk);
            let got = decode_all(&stream, DecoderConfig::default(), data.len()).unwrap();
            assert_eq!(&got, data, "len={} out_chunk={out_chunk}", data.len());
        }
    }
}

/// Cross-validate framing against the shared `xz` chunk codec: wrap the raw
/// LZMA2 stream this encoder emits inside a minimal `.xz` container and decode
/// it with the public `xz` decoder. Because the `xz` and `lzma2` paths share
/// `lzma2_decoder`, a successful decode proves our chunk framing is exactly
/// what `xz` consumes. We build the container around our own payload rather
/// than re-encoding with `xz`, so this exercises *our* bytes.
#[test]
#[cfg(feature = "xz")]
fn xz_cross_validates_framing() {
    use compcol::xz::Xz;

    fn crc32(data: &[u8]) -> u32 {
        let mut s = 0xFFFF_FFFFu32;
        for &b in data {
            s ^= b as u32;
            for _ in 0..8 {
                s = if s & 1 != 0 {
                    0xEDB8_8320 ^ (s >> 1)
                } else {
                    s >> 1
                };
            }
        }
        s ^ 0xFFFF_FFFF
    }
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8 & 0x7F) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    // Data with both compressible and incompressible regions so the payload
    // contains compressed (0xE0) and uncompressed (0x01) chunks.
    let mut data = vec![0u8; 100 * 1024];
    let mut x = 0x1234_5678u32;
    for (i, b) in data.iter_mut().enumerate() {
        if i % 3 == 0 {
            *b = 0; // compressible runs
        } else {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
    }

    // Our raw LZMA2 payload (chunks + 0x00 end marker), unchanged.
    let payload = encode_all(&data, 1 << 16);

    // ── Stream Header: magic | flags(00,01=CRC32) | CRC32(flags) ──
    let mut xz = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x01];
    xz.extend_from_slice(&crc32(&[0x00, 0x01]).to_le_bytes());

    // ── Block Header: size byte | flags | filter id | props size | dict
    //    flag (0x14 = 4 MiB) | pad to mult-of-4-minus-CRC | CRC32 ──
    let mut bh = vec![0x02u8, 0x00, 0x21, 0x01, 0x14, 0x00, 0x00, 0x00];
    let bh_crc = crc32(&bh).to_le_bytes();
    bh.extend_from_slice(&bh_crc);
    let block_header_len = bh.len() as u64;
    xz.extend_from_slice(&bh);

    // ── Block payload + padding + Check(CRC32 of uncompressed data) ──
    xz.extend_from_slice(&payload);
    let compressed_size = payload.len() as u64;
    let unpadded_no_pad = block_header_len + compressed_size + 4;
    let pad = ((4 - (unpadded_no_pad % 4)) % 4) as usize;
    xz.extend(core::iter::repeat_n(0u8, pad));
    xz.extend_from_slice(&crc32(&data).to_le_bytes());

    // ── Index: 00 | numrec | (unpadded, uncompressed) | pad | CRC32 ──
    let unpadded_size = block_header_len + compressed_size + 4;
    let mut idx = vec![0x00u8];
    varint(1, &mut idx);
    varint(unpadded_size, &mut idx);
    varint(data.len() as u64, &mut idx);
    while idx.len() % 4 != 0 {
        idx.push(0x00);
    }
    let idx_crc = crc32(&idx).to_le_bytes();
    idx.extend_from_slice(&idx_crc);
    let index_size = idx.len() as u32;
    xz.extend_from_slice(&idx);

    // ── Stream Footer: CRC32(body) | backward_size | flags | magic ──
    let mut footer_body = ((index_size / 4) - 1).to_le_bytes().to_vec();
    footer_body.push(0x00);
    footer_body.push(0x01);
    let f_crc = crc32(&footer_body).to_le_bytes();
    xz.extend_from_slice(&f_crc);
    xz.extend_from_slice(&footer_body);
    xz.extend_from_slice(&[0x59, 0x5A]);

    // Decode the whole thing through the public xz decoder.
    let mut dec = Xz::decoder_with(());
    let mut out = vec![0u8; data.len() + 64];
    let mut consumed = 0;
    let mut written = 0;
    loop {
        let (p, st) = dec.decode(&xz[consumed..], &mut out[written..]).unwrap();
        consumed += p.consumed;
        written += p.written;
        match st {
            Status::StreamEnd => break,
            Status::InputEmpty if consumed >= xz.len() => {
                // Whole container consumed; finish surfaces the trailer end.
                let (p, fst) = dec.finish(&mut out[written..]).unwrap();
                written += p.written;
                assert_eq!(fst, Status::StreamEnd, "xz trailer not terminated");
                break;
            }
            _ => assert!(
                !(p.consumed == 0 && p.written == 0),
                "xz decoder stalled — framing mismatch"
            ),
        }
    }
    out.truncate(written);
    assert_eq!(
        out, data,
        "xz cross-decode of our raw LZMA2 framing mismatched"
    );
}
