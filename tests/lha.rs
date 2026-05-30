#![cfg(feature = "lha")]
//! Streaming round-trip + error-path tests for the LHA/LZH methods.

use compcol::lha::{Lh1, Lh4, Lh5, Lh6, Lh7};
use compcol::{Algorithm, Decoder, Encoder, Error, Status};

/// Encode `data` with `enc`, feeding `in_chunk` bytes at a time and
/// draining into `out_chunk`-sized output buffers, exercising the
/// resumable streaming contract.
fn run_stream<F>(mut step: F, data: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8>
where
    F: FnMut(&[u8], &mut [u8]) -> (compcol::Progress, Status),
{
    // Feed `data` to `step` (an encode or decode closure) in `in_chunk`
    // slices, draining `out_chunk`-sized output buffers each call. `step`
    // owns advancing the codec; we just present input windows.
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut consumed = 0usize;
    while consumed < data.len() {
        let end = (consumed + in_chunk.max(1)).min(data.len());
        loop {
            let (p, status) = step(&data[consumed..end], &mut buf);
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::OutputFull => continue,
                _ => break,
            }
        }
    }
    out
}

fn encode_chunked<E: Encoder>(
    mut enc: E,
    data: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut out = run_stream(
        |inp, buf| enc.encode(inp, buf).unwrap(),
        data,
        in_chunk,
        out_chunk,
    );
    let mut buf = vec![0u8; out_chunk.max(1)];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    out
}

fn decode_chunked<D: Decoder>(
    mut dec: D,
    data: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut out = run_stream(
        |inp, buf| dec.decode(inp, buf).unwrap(),
        data,
        in_chunk,
        out_chunk,
    );
    let mut buf = vec![0u8; out_chunk.max(1)];
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    out
}

fn roundtrip_method<A: Algorithm>(data: &[u8]) {
    // A few chunk-size combinations to exercise resumability.
    for &(ic, oc) in &[(1 << 20, 1 << 20), (1, 1), (7, 3), (64, 16)] {
        let enc = A::encoder();
        let encoded = encode_chunked(enc, data, ic, oc);
        let dec = A::decoder();
        let decoded = decode_chunked(dec, &encoded, ic, oc);
        assert_eq!(
            decoded,
            data,
            "round-trip mismatch for {} (in={}, out={}, len={})",
            A::NAME,
            ic,
            oc,
            data.len()
        );
    }
}

fn sample_inputs() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"hello world".to_vec(),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabc".to_vec(),
    ];
    // Repeated phrase to stress matches and the dictionary.
    let mut big = Vec::new();
    for i in 0..2000u32 {
        big.extend_from_slice(format!("The quick brown fox {} jumps. ", i % 13).as_bytes());
    }
    v.push(big);
    // Pseudo-random but deterministic bytes (low compressibility).
    let mut rng = 0x12345678u32;
    let mut rnd = Vec::with_capacity(5000);
    for _ in 0..5000 {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        rnd.push((rng >> 16) as u8);
    }
    v.push(rnd);
    // All 256 byte values, several times.
    let mut allbytes = Vec::new();
    for _ in 0..40 {
        for b in 0..=255u8 {
            allbytes.push(b);
        }
    }
    v.push(allbytes);
    v
}

#[test]
fn roundtrip_lh5() {
    for data in sample_inputs() {
        roundtrip_method::<Lh5>(&data);
    }
}

#[test]
fn roundtrip_lh4() {
    for data in sample_inputs() {
        roundtrip_method::<Lh4>(&data);
    }
}

#[test]
fn roundtrip_lh6() {
    for data in sample_inputs() {
        roundtrip_method::<Lh6>(&data);
    }
}

#[test]
fn roundtrip_lh7() {
    for data in sample_inputs() {
        roundtrip_method::<Lh7>(&data);
    }
}

#[test]
fn roundtrip_lh1() {
    for data in sample_inputs() {
        roundtrip_method::<Lh1>(&data);
    }
}

#[test]
fn large_window_match_lh7() {
    // A match at a distance only reachable with the 128 KiB lh7 window.
    let mut data = vec![0u8; 100_000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    // Append a copy of the first 5000 bytes so it back-references far.
    let head: Vec<u8> = data[..5000].to_vec();
    data.extend_from_slice(&head);
    roundtrip_method::<Lh7>(&data);
}

// ─── error paths: crafted/truncated input must never panic ───────────────

#[test]
fn truncated_payload_errors_cleanly() {
    // Encode something, then chop the payload and confirm a clean error
    // (not a panic) from finish().
    let data = b"the quick brown fox jumps over the lazy dog, repeatedly!".repeat(20);
    let enc = Lh5::encoder();
    let encoded = encode_chunked(enc, &data, 1 << 16, 1 << 16);
    // Keep the 4-byte length header + a few payload bytes only.
    let truncated = &encoded[..(encoded.len().min(8))];
    let mut dec = Lh5::decoder();
    let mut buf = vec![0u8; 4096];
    let (_p, _s) = dec.decode(truncated, &mut buf).unwrap();
    let res = dec.finish(&mut buf);
    // Either it errors, or (if the few bytes happened to decode short) it
    // returns fewer bytes — but it must not panic and must not over-produce.
    match res {
        Ok((p, _)) => assert!(p.written <= data.len()),
        Err(e) => assert!(matches!(
            e,
            Error::Corrupt
                | Error::UnexpectedEnd
                | Error::InvalidHuffmanTree
                | Error::InvalidDistance
        )),
    }
}

#[test]
fn header_only_then_garbage_errors() {
    // 4-byte length header claiming 1000 bytes, followed by random junk.
    let mut stream = 1000u32.to_le_bytes().to_vec();
    let mut rng = 0xdead_beefu32;
    for _ in 0..200 {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        stream.push((rng >> 16) as u8);
    }
    let decoders: [Box<dyn Decoder>; 3] = [
        Box::new(Lh5::decoder()),
        Box::new(Lh1::decoder()),
        Box::new(Lh6::decoder()),
    ];
    for mut dec in decoders {
        let mut buf = vec![0u8; 8192];
        let _ = dec.decode(&stream, &mut buf);
        // Must not panic; produce no more than the claimed length.
        let mut produced = 0usize;
        while let Ok((p, status)) = dec.finish(&mut buf) {
            produced += p.written;
            assert!(produced <= 1000);
            if matches!(status, Status::StreamEnd) || p.written == 0 {
                break;
            }
        }
    }
}

#[test]
fn empty_input_to_decoder_is_unexpected_end_or_empty() {
    // A decoder given no bytes at all: finish should yield empty output
    // (we treat a totally empty stream as zero-length) without panicking.
    let mut dec = Lh5::decoder();
    let mut buf = vec![0u8; 16];
    let (p, status) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::StreamEnd));
}

#[test]
fn names_registered() {
    #[cfg(feature = "factory")]
    {
        let names = compcol::factory::names();
        for n in ["lh1", "lh4", "lh5", "lh6", "lh7"] {
            assert!(names.contains(&n), "{n} not registered");
            assert!(compcol::factory::encoder_by_name(n).is_some());
            assert!(compcol::factory::decoder_by_name(n).is_some());
        }
    }
}
