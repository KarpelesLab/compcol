#![no_main]
//! Round-trip property: for every lossless codec, `decode(encode(x)) == x`.
//!
//! The `decoder_*` targets only prove the decoders don't panic on garbage.
//! This target exercises the **encoders** (and the encoder↔decoder contract)
//! by feeding arbitrary input through `encode` then `decode` and asserting the
//! bytes come back unchanged. Byte 0 selects the codec; the rest is the input.
//!
//! A panic here means either an encoder bug, a decoder bug, or a framing
//! mismatch between the two — all of which are real defects for a lossless
//! codec.

use compcol::{Status, factory};
use libfuzzer_sys::fuzz_target;

/// Codecs with a lossless streaming encoder *and* decoder registered in the
/// factory. (Decode-only formats — ppmd, arsenic, the rar/lha family, etc. —
/// are covered by their own `decoder_*` targets and excluded here.)
const CODECS: &[&str] = &[
    "deflate", "zlib", "gzip", "lz4", "snappy", "lzo", "lzw", "lzss", "lzs", "xpress", "adc",
    "rle", "rle90", "packbits", "bzip2", "zstd", "brotli", "xz", "lzma", "lzma2", "huffman",
    "lznt1", "lz5", "mtf", "bwt", "delta",
];

/// Cap the input so a slow optimal-parse encoder (xz/lzma2) can't turn one
/// fuzz iteration into a multi-second stall; libFuzzer inputs are usually far
/// smaller than this anyway.
const MAX_INPUT: usize = 32 * 1024;

fn encode(name: &str, input: &[u8]) -> Option<Vec<u8>> {
    let mut enc = factory::encoder_by_name(name)?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    let mut steps = 0usize;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).ok()?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        steps += 1;
        if steps > 2_000_000 {
            return None;
        }
        match status {
            Status::InputEmpty | Status::StreamEnd => break,
            Status::OutputFull => {}
        }
    }
    let mut steps = 0usize;
    loop {
        let (p, status) = enc.finish(&mut buf).ok()?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
        steps += 1;
        if steps > 2_000_000 {
            return None;
        }
    }
    Some(out)
}

fn decode(name: &str, encoded: &[u8]) -> Option<Vec<u8>> {
    let mut dec = factory::decoder_by_name(name)?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    let mut steps = 0usize;
    while consumed < encoded.len() {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf).ok()?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        steps += 1;
        if steps > 2_000_000 {
            return None;
        }
        match status {
            Status::InputEmpty | Status::StreamEnd => break,
            Status::OutputFull => {}
        }
    }
    // Drain any decoder-buffered output (e.g. bzip2 holds a whole block).
    let mut steps = 0usize;
    loop {
        let (p, _s) = dec.decode(&[], &mut buf).ok()?;
        out.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
        steps += 1;
        if steps > 2_000_000 {
            return None;
        }
    }
    let mut steps = 0usize;
    loop {
        let (p, status) = dec.finish(&mut buf).ok()?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
        steps += 1;
        if steps > 2_000_000 {
            return None;
        }
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let name = CODECS[data[0] as usize % CODECS.len()];
    let input = &data[1..];
    if input.len() > MAX_INPUT {
        return;
    }

    // Encode may legitimately decline (unsupported config, etc.) → skip.
    let Some(encoded) = encode(name, input) else {
        return;
    };

    match decode(name, &encoded) {
        Some(decoded) => {
            assert!(
                decoded == input,
                "{name}: round-trip mismatch (input {} bytes, decoded {} bytes)",
                input.len(),
                decoded.len(),
            );
        }
        None => panic!(
            "{name}: produced {} encoded bytes that fail to decode (input {} bytes)",
            encoded.len(),
            input.len(),
        ),
    }
});
