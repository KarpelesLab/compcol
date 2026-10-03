//! Tests for the `embed` build of the deflate family: the small
//! `deflate` / `zlib` / `gzip` codecs behind the standard names.
//!
//! Correctness is checked against reference streams from CPython's zlib
//! (`tests/fixtures/embed/`, see `generate.py` there), against hand-made
//! streams for what zlib never produces (a back-reference at exactly 32768,
//! a block whose every two bits stand for 258 bytes), and by round trip in
//! every chunking. Sizes are checked against the ceilings `compcol::embed`
//! documents; the stack is checked by running on a thread that has little.

#![cfg(all(
    feature = "embed",
    feature = "deflate",
    feature = "zlib",
    feature = "gzip"
))]

use compcol::embed::{BLOCK, DECODER_SIZE, ENCODER_SIZE, TABLE, WINDOW};
use compcol::{Algorithm, Decoder, Encoder, Error, Flush, Status, deflate, gzip, zlib};

// ─── reference data, as `generate.py` derives it ────────────────────────

fn text(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 64);
    let mut i = 0;
    while out.len() < n {
        out.extend_from_slice(
            format!("line {i}: the quick brown fox jumps over the lazy dog\n").as_bytes(),
        );
        i += 1;
    }
    out.truncate(n);
    out
}

fn random(n: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn far() -> Vec<u8> {
    let r = random(32000);
    [r.clone(), r].concat()
}

fn far_exact() -> Vec<u8> {
    let mut data: Vec<u8> = (0..=255).collect();
    while data.len() < 256 + 258 * 127 {
        data.push(data[data.len() - 256]);
    }
    for _ in 0..10 {
        data.push(data[data.len() - 32768]);
    }
    data
}

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/embed/", $name)) as &[u8]
    };
}

// ─── drivers ────────────────────────────────────────────────────────────

/// Encodes `input`, fed `in_chunk` bytes at a time into `out_chunk`-byte
/// output buffers, checking every status on the way.
fn encode_chunked<E: Encoder>(
    enc: &mut E,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    for chunk in input.chunks(in_chunk.max(1)) {
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty => assert_eq!(consumed, chunk.len()),
                Status::OutputFull => {}
                Status::StreamEnd => panic!("encode reported StreamEnd"),
            }
        }
    }
    let mut stalls = 0;
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull => {
                stalls += usize::from(p.written == 0);
                assert!(stalls < 4, "finish stalled");
            }
            Status::InputEmpty => panic!("finish reported InputEmpty"),
        }
    }
    encoded
}

/// Decodes `encoded`, fed `in_chunk` bytes at a time into `out_chunk`-byte
/// output buffers. Returns the data and how many input bytes the decoder
/// consumed in all.
fn decode_chunked<D: Decoder>(
    dec: &mut D,
    encoded: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<(Vec<u8>, usize), Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut total_consumed = 0;
    let mut ended = false;
    'feed: for chunk in encoded.chunks(in_chunk.max(1)) {
        let mut consumed = 0;
        loop {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => {
                    ended = true;
                    total_consumed += consumed;
                    break 'feed;
                }
                Status::InputEmpty => break,
                Status::OutputFull => {
                    assert!(p.written > 0 || p.consumed > 0, "decode made no progress");
                }
            }
        }
        total_consumed += consumed;
    }
    let mut stalls = 0;
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull => {
                stalls += usize::from(p.written == 0);
                assert!(stalls < 4, "finish stalled");
            }
            Status::InputEmpty => panic!("finish reported InputEmpty"),
        }
    }
    let _ = ended;
    Ok((out, total_consumed))
}

fn decode_all<A: Algorithm>(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    decode_chunked(&mut A::decoder(), encoded, usize::MAX, 65536).map(|(data, _)| data)
}

fn round_trip<A: Algorithm>(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let encoded = encode_chunked(&mut A::encoder(), input, in_chunk, out_chunk);
    let (back, consumed) =
        decode_chunked(&mut A::decoder(), &encoded, in_chunk, out_chunk).unwrap();
    assert_eq!(
        consumed,
        encoded.len(),
        "decoder did not consume the whole stream"
    );
    assert_eq!(back, input);
    encoded
}

// ─── sizes ──────────────────────────────────────────────────────────────

#[test]
fn struct_sizes_stay_within_the_documented_ceilings() {
    assert!(size_of::<zlib::Decoder>() <= DECODER_SIZE);
    assert!(size_of::<gzip::Decoder>() <= DECODER_SIZE);
    assert!(size_of::<deflate::Decoder>() <= DECODER_SIZE);
    assert!(size_of::<zlib::Encoder>() <= ENCODER_SIZE);
    assert!(size_of::<gzip::Encoder>() <= ENCODER_SIZE);
    assert!(size_of::<deflate::Encoder>() <= ENCODER_SIZE);
    // And they are big, as documented: the window and the buffers are inline.
    assert!(size_of::<zlib::Decoder>() >= WINDOW);
    assert!(size_of::<zlib::Encoder>() >= BLOCK);
}

/// The constructors are `const`: a codec can live in a `static`.
static STATIC_DECODER: std::sync::Mutex<gzip::Decoder> =
    std::sync::Mutex::new(gzip::Decoder::new());
static STATIC_ENCODER: std::sync::Mutex<gzip::Encoder> =
    std::sync::Mutex::new(gzip::Encoder::new());

#[test]
fn codecs_can_be_built_in_statics() {
    let data = text(10_000);
    let encoded = encode_chunked(&mut *STATIC_ENCODER.lock().unwrap(), &data, 1000, 300);
    let (back, _) =
        decode_chunked(&mut *STATIC_DECODER.lock().unwrap(), &encoded, 100, 500).unwrap();
    assert_eq!(back, data);
}

// ─── decoding reference streams ─────────────────────────────────────────

#[test]
fn decodes_zlib_dynamic_fixed_and_stored_blocks() {
    let expected = text(60_000);
    assert_eq!(
        decode_all::<zlib::Zlib>(fixture!("text_l9.zlib")).unwrap(),
        expected
    );
    assert_eq!(
        decode_all::<zlib::Zlib>(fixture!("text_l1.zlib")).unwrap(),
        expected
    );
    assert_eq!(
        decode_all::<zlib::Zlib>(fixture!("text_l0.zlib")).unwrap(),
        expected
    );
}

#[test]
fn decodes_raw_deflate_and_gzip() {
    let expected = text(60_000);
    assert_eq!(
        decode_all::<deflate::Deflate>(fixture!("text_l6.deflate")).unwrap(),
        expected
    );
    assert_eq!(
        decode_all::<gzip::Gzip>(fixture!("text_l6.gz")).unwrap(),
        expected
    );
}

#[test]
fn skips_every_optional_gzip_header_field() {
    assert_eq!(
        decode_all::<gzip::Gzip>(fixture!("text_fancy.gz")).unwrap(),
        text(60_000)
    );
}

#[test]
fn decodes_incompressible_data() {
    assert_eq!(
        decode_all::<zlib::Zlib>(fixture!("random.zlib")).unwrap(),
        random(20_000)
    );
}

#[test]
fn decodes_empty_streams() {
    assert_eq!(
        decode_all::<zlib::Zlib>(fixture!("empty.zlib")).unwrap(),
        b""
    );
    assert_eq!(decode_all::<gzip::Gzip>(fixture!("empty.gz")).unwrap(), b"");
}

#[test]
fn far_back_references_cross_the_ring_window() {
    assert_eq!(
        decode_all::<zlib::Zlib>(fixture!("far.zlib")).unwrap(),
        far()
    );
    assert_eq!(
        decode_all::<deflate::Deflate>(fixture!("far_exact.deflate")).unwrap(),
        far_exact()
    );
}

/// Every chunking of input and output must give the same bytes, including
/// the ones that make the decoder hand data back a byte at a time.
#[test]
fn reference_streams_decode_identically_in_every_chunking() {
    let expected = text(60_000);
    for &(stream, raw) in &[
        (fixture!("text_l9.zlib"), false),
        (fixture!("far_exact.deflate"), true),
    ] {
        let want = if raw { far_exact() } else { expected.clone() };
        for &in_chunk in &[1usize, 2, 7, 26, 27, 28, 100, 4096, usize::MAX] {
            for &out_chunk in &[1usize, 3, 257, 258, 259, 4096, 65536] {
                let got = if raw {
                    decode_chunked(
                        &mut deflate::Deflate::decoder(),
                        stream,
                        in_chunk,
                        out_chunk,
                    )
                } else {
                    decode_chunked(&mut zlib::Zlib::decoder(), stream, in_chunk, out_chunk)
                };
                let (got, consumed) = got.unwrap();
                assert_eq!(consumed, stream.len(), "in {in_chunk} out {out_chunk}");
                assert_eq!(got, want, "in {in_chunk} out {out_chunk}");
            }
        }
    }
}

/// A block whose every two bits stand for 258 bytes: the worst expansion
/// deflate allows, which is what bounds how much input the wrapper feeds
/// `minizlib` per call. Nothing may be lost however small the output.
#[test]
fn maximal_expansion_never_overruns_the_window() {
    let stream = fixture!("bomb.deflate");
    let expected = vec![b'a'; 1 + 258 * 2000];
    for &in_chunk in &[1usize, 27, 64, usize::MAX] {
        for &out_chunk in &[1usize, 100, 32768, 65536, 1 << 20] {
            let (got, _) = decode_chunked(
                &mut deflate::Deflate::decoder(),
                stream,
                in_chunk,
                out_chunk,
            )
            .unwrap();
            assert_eq!(got.len(), expected.len(), "in {in_chunk} out {out_chunk}");
            assert!(got == expected, "in {in_chunk} out {out_chunk}");
        }
    }
}

// ─── round trips ────────────────────────────────────────────────────────

#[test]
fn round_trips_in_every_chunking() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"hello hello hello hello".to_vec(),
        text(BLOCK - 1),
        text(BLOCK),
        text(BLOCK + 1),
        text(3 * BLOCK + 17),
        random(2 * BLOCK + 5),
        [text(20_000), random(3000), text(5000)].concat(),
    ];
    for input in &inputs {
        for &in_chunk in &[1usize, 13, BLOCK - 1, BLOCK, BLOCK + 1, 10_000, usize::MAX] {
            for &out_chunk in &[1usize, 5, 1000, 65536] {
                round_trip::<zlib::Zlib>(input, in_chunk, out_chunk);
                round_trip::<gzip::Gzip>(input, in_chunk, out_chunk);
                round_trip::<deflate::Deflate>(input, in_chunk, out_chunk);
            }
        }
    }
}

/// The stream does not depend on how the input was cut: whole blocks are
/// compressed from the caller's slice, pieces are gathered first, and the
/// two must agree.
#[test]
fn encoded_stream_is_independent_of_input_chunking() {
    let input = [text(20_000), random(3000), text(5000)].concat();
    let whole = encode_chunked(&mut zlib::Zlib::encoder(), &input, usize::MAX, 65536);
    for &in_chunk in &[1usize, 7, BLOCK - 1, BLOCK, BLOCK + 1, 2 * BLOCK + 3] {
        for &out_chunk in &[1usize, 64, 65536] {
            let got = encode_chunked(&mut zlib::Zlib::encoder(), &input, in_chunk, out_chunk);
            let first = got.iter().zip(&whole).position(|(a, b)| a != b);
            assert!(
                got == whole,
                "in {in_chunk} out {out_chunk}: lengths {} vs {}, first difference at {first:?}",
                got.len(),
                whole.len()
            );
        }
    }
}

#[test]
fn compresses_text_and_bounds_incompressible_expansion() {
    let t = text(60_000);
    let encoded = round_trip::<gzip::Gzip>(&t, usize::MAX, 65536);
    assert!(
        encoded.len() * 2 < t.len(),
        "text should compress by half at least: {}",
        encoded.len()
    );
    let r = random(20_000);
    let encoded = round_trip::<zlib::Zlib>(&r, usize::MAX, 65536);
    // Fixed Huffman codes cost at most an eighth, plus per-block overhead.
    assert!(
        encoded.len() < r.len() + r.len() / 8 + 64,
        "{}",
        encoded.len()
    );
}

#[test]
fn containers_carry_the_right_headers_and_trailers() {
    let data = b"hello hello hello hello";
    let z = encode_chunked(&mut zlib::Zlib::encoder(), data, usize::MAX, 64);
    assert_eq!(&z[..2], &[0x78, 0x01]);
    assert_eq!(((z[0] as u32) << 8 | z[1] as u32) % 31, 0);
    let g = encode_chunked(&mut gzip::Gzip::encoder(), data, usize::MAX, 64);
    assert_eq!(&g[..4], &[0x1f, 0x8b, 0x08, 0x00]);
    assert_eq!(&g[g.len() - 4..], &(data.len() as u32).to_le_bytes());
    let d = encode_chunked(&mut deflate::Deflate::encoder(), data, usize::MAX, 64);
    assert!(d.len() + 2 < z.len() && z.len() < g.len());
    assert_eq!(&z[2..z.len() - 4], &d[..]);
}

// ─── errors and edge cases ──────────────────────────────────────────────

#[test]
fn rejects_corrupt_streams_with_the_right_errors() {
    let good = fixture!("text_l9.zlib");

    let mut bad = good.to_vec();
    bad[1] ^= 0x01; // FCHECK fails
    assert_eq!(
        decode_all::<zlib::Zlib>(&bad).unwrap_err(),
        Error::BadHeader
    );

    let mut bad = good.to_vec();
    bad[0] = 0x77; // CM = 7
    bad[1] = 31 - ((0x7700u32) % 31) as u8;
    assert_eq!(
        decode_all::<zlib::Zlib>(&bad).unwrap_err(),
        Error::Unsupported
    );

    let mut bad = good.to_vec();
    bad[1] |= 0x20; // FDICT
    bad[1] = (bad[1] & 0xe0) | ((31 - ((0x7800u32 | (bad[1] & 0xe0) as u32) % 31)) % 31) as u8;
    assert_eq!(
        decode_all::<zlib::Zlib>(&bad).unwrap_err(),
        Error::Unsupported
    );

    let mut bad = good.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 0xff; // Adler-32
    assert_eq!(
        decode_all::<zlib::Zlib>(&bad).unwrap_err(),
        Error::ChecksumMismatch
    );

    let truncated = &good[..good.len() - 10];
    assert_eq!(
        decode_all::<zlib::Zlib>(truncated).unwrap_err(),
        Error::UnexpectedEnd
    );

    // BTYPE = 3 (reserved) in a raw stream.
    assert_eq!(
        decode_all::<deflate::Deflate>(&[0x07, 0x00]).unwrap_err(),
        Error::InvalidBlockType
    );

    let good = fixture!("text_l6.gz");
    let mut bad = good.to_vec();
    bad[1] = 0x8c;
    assert_eq!(
        decode_all::<gzip::Gzip>(&bad).unwrap_err(),
        Error::BadHeader
    );
    let mut bad = good.to_vec();
    let at = bad.len() - 6;
    bad[at] ^= 0x01; // CRC-32
    assert_eq!(
        decode_all::<gzip::Gzip>(&bad).unwrap_err(),
        Error::ChecksumMismatch
    );
    let mut bad = good.to_vec();
    let at = bad.len() - 1;
    bad[at] ^= 0x01; // ISIZE
    assert_eq!(
        decode_all::<gzip::Gzip>(&bad).unwrap_err(),
        Error::TrailerMismatch
    );
    let mut bad = good.to_vec();
    bad[3] |= 0x80; // reserved flag
    assert_eq!(
        decode_all::<gzip::Gzip>(&bad).unwrap_err(),
        Error::Unsupported
    );
    // A stored block whose length check fails.
    assert_eq!(
        decode_all::<deflate::Deflate>(&[0x01, 0x05, 0x00, 0x00, 0x00]).unwrap_err(),
        Error::Corrupt
    );
}

#[test]
fn errors_poison_until_reset() {
    let mut dec = zlib::Zlib::decoder();
    let mut buf = [0u8; 64];
    assert_eq!(
        dec.decode(&[0x78, 0x9d], &mut buf).unwrap_err(),
        Error::BadHeader
    );
    assert_eq!(
        dec.decode(fixture!("text_l9.zlib"), &mut buf).unwrap_err(),
        Error::Corrupt
    );
    dec.reset();
    let (back, _) = decode_chunked(&mut dec, fixture!("text_l9.zlib"), 1000, 1000).unwrap();
    assert_eq!(back, text(60_000));
}

#[test]
fn trailing_bytes_are_left_unconsumed_and_report_stream_end() {
    let stream = [fixture!("text_l1.zlib"), b"TRAILING GARBAGE"].concat();
    let (back, consumed) =
        decode_chunked(&mut zlib::Zlib::decoder(), &stream, usize::MAX, 65536).unwrap();
    assert_eq!(back, text(60_000));
    assert_eq!(consumed, fixture!("text_l1.zlib").len());

    // Once ended, further calls are no-ops reporting StreamEnd. A gzip
    // stream only ends for sure with a byte that does not start another
    // member, or with `finish`: as in the standard build.
    let mut dec = gzip::Gzip::decoder();
    let mut buf = vec![0u8; 65536];
    let (p, status) = dec.decode(fixture!("text_l6.gz"), &mut buf).unwrap();
    assert_eq!(status, Status::InputEmpty);
    assert_eq!(p.consumed, fixture!("text_l6.gz").len());
    let (p, status) = dec.decode(b"more", &mut buf).unwrap();
    assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));
    let (p, status) = dec.decode(b"more", &mut buf).unwrap();
    assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));

    let mut dec = gzip::Gzip::decoder();
    dec.decode(fixture!("text_l6.gz"), &mut buf).unwrap();
    assert_eq!(dec.finish(&mut buf).unwrap().1, Status::StreamEnd);
}

#[test]
fn concatenated_gzip_members_decode_as_one_stream() {
    let one = fixture!("text_l6.gz");
    let two = [one, one, fixture!("empty.gz")].concat();
    for &(in_chunk, out_chunk) in &[(100usize, 1000usize), (1, 1), (usize::MAX, 65536)] {
        let (back, consumed) =
            decode_chunked(&mut gzip::Gzip::decoder(), &two, in_chunk, out_chunk).unwrap();
        assert_eq!(back, [text(60_000), text(60_000)].concat());
        assert_eq!(consumed, two.len());
    }
    // A corrupt second member is an error, not silently the end.
    let mut bad = two.clone();
    bad[one.len() + one.len() - 6] ^= 1;
    assert_eq!(
        decode_chunked(&mut gzip::Gzip::decoder(), &bad, 100, 1000).unwrap_err(),
        Error::ChecksumMismatch
    );
}

#[test]
fn codecs_are_reusable_after_reset() {
    let mut enc = gzip::Gzip::encoder();
    let mut dec = gzip::Gzip::decoder();
    let a = text(10_000);
    let b = random(3000);
    let ea = encode_chunked(&mut enc, &a, 100, 100);
    enc.reset();
    let eb = encode_chunked(&mut enc, &b, 100, 100);
    enc.reset();
    assert_eq!(encode_chunked(&mut enc, &a, 100, 100), ea);
    assert_eq!(decode_chunked(&mut dec, &ea, 100, 100).unwrap().0, a);
    dec.reset();
    assert_eq!(decode_chunked(&mut dec, &eb, 100, 100).unwrap().0, b);

    // Reset mid-stream, both ways.
    let mut buf = [0u8; 64];
    enc.reset();
    enc.encode(&a[..1000], &mut buf).unwrap();
    enc.reset();
    assert_eq!(encode_chunked(&mut enc, &a, 100, 100), ea);
    dec.reset();
    dec.decode(&ea[..100], &mut buf).unwrap();
    dec.reset();
    assert_eq!(decode_chunked(&mut dec, &ea, 100, 100).unwrap().0, a);
}

#[test]
fn finish_before_the_stream_ends_is_unexpected_end() {
    let mut dec = zlib::Zlib::decoder();
    let mut buf = [0u8; 1024];
    let stream = fixture!("text_l9.zlib");
    dec.decode(&stream[..stream.len() / 2], &mut buf).unwrap();
    loop {
        // Drain whatever is pending first; the window may hold more than
        // the buffer takes.
        match dec.decode(&[], &mut buf) {
            Ok((p, _)) if p.written > 0 => continue,
            _ => break,
        }
    }
    assert_eq!(dec.finish(&mut buf).unwrap_err(), Error::UnexpectedEnd);
}

#[test]
fn encode_after_finish_is_an_error() {
    let mut enc = zlib::Zlib::encoder();
    let mut buf = [0u8; 64];
    assert_eq!(enc.finish(&mut buf).unwrap().1, Status::StreamEnd);
    assert!(enc.encode(b"late", &mut buf).is_err());
}

#[test]
fn sync_flush_is_unsupported() {
    let mut enc = zlib::Zlib::encoder();
    let mut buf = [0u8; 64];
    enc.encode(b"some data", &mut buf).unwrap();
    assert_eq!(
        enc.flush(&mut buf, Flush::Sync).unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(
        enc.flush(&mut buf, Flush::Full).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn discard_output_skips_without_delivering() {
    let stream = fixture!("text_l9.zlib");
    let expected = text(60_000);
    let mut dec = zlib::Zlib::decoder();
    let mut consumed = 0;
    let mut skipped = 0;
    while skipped < 50_000 {
        let (p, status) = dec
            .discard_output(&stream[consumed..], 50_000 - skipped)
            .unwrap();
        consumed += p.consumed;
        skipped += p.written;
        assert_ne!(status, Status::StreamEnd);
        assert!(p.consumed > 0 || p.written > 0);
    }
    assert_eq!(skipped, 50_000);
    let mut rest = Vec::new();
    let mut buf = [0u8; 777];
    loop {
        let (p, status) = dec.decode(&stream[consumed..], &mut buf).unwrap();
        consumed += p.consumed;
        rest.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(rest, &expected[50_000..]);
    assert_eq!(consumed, stream.len());
}

#[test]
fn window_size_config_tightens_the_distance_check() {
    let stream = fixture!("far_exact.deflate");
    let strict = deflate::DecoderConfig::default().with_window_size(4096);
    let mut dec = deflate::Deflate::decoder_with(strict);
    assert_eq!(
        decode_chunked(&mut dec, stream, usize::MAX, 65536).unwrap_err(),
        Error::InvalidDistance
    );
    let lax = deflate::DecoderConfig::default().with_window_size(usize::MAX);
    let mut dec = deflate::Deflate::decoder_with(lax);
    assert_eq!(
        decode_chunked(&mut dec, stream, usize::MAX, 65536)
            .unwrap()
            .0,
        far_exact()
    );
}

#[test]
fn level_is_accepted_and_ignored() {
    let data = text(20_000);
    let l1 = encode_chunked(
        &mut zlib::Zlib::encoder_with(zlib::EncoderConfig { level: 1 }),
        &data,
        4096,
        4096,
    );
    let l9 = encode_chunked(
        &mut zlib::Zlib::encoder_with(zlib::EncoderConfig { level: 9 }),
        &data,
        4096,
        4096,
    );
    assert_eq!(l1, l9);
    let g = encode_chunked(
        &mut gzip::Gzip::encoder_with(gzip::EncoderConfig { level: 9 }),
        &data,
        4096,
        4096,
    );
    assert_eq!(decode_all::<gzip::Gzip>(&g).unwrap(), data);
    let cfg = deflate::EncoderConfig::new()
        .with_level(9)
        .with_max_distance(100);
    let d = encode_chunked(&mut deflate::Deflate::encoder_with(cfg), &data, 4096, 4096);
    assert_eq!(decode_all::<deflate::Deflate>(&d).unwrap(), data);
}

// ─── sizes picked at build time ─────────────────────────────────────────

#[test]
fn sized_codecs_take_the_memory_their_sizes_say() {
    assert!(size_of::<gzip::WindowedDecoder<4096>>() <= 4096 + 2048);
    assert!(size_of::<zlib::WindowedDecoder<256>>() <= 256 + 2048);
    assert!(size_of::<deflate::WindowedDecoder<1>>() <= 1 + 2048);
    assert!(size_of::<gzip::BlockEncoder<1024, 256>>() <= 1024 + 2 * 256 + 128);
    assert!(size_of::<zlib::BlockEncoder<32768, 4096>>() <= 32768 + 2 * 4096 + 128);
    // The defaults are the documented constants.
    assert_eq!(
        size_of::<gzip::Decoder>(),
        size_of::<gzip::WindowedDecoder<WINDOW>>()
    );
    assert_eq!(
        size_of::<gzip::Encoder>(),
        size_of::<gzip::BlockEncoder<BLOCK, TABLE>>()
    );
}

/// Sized codecs are `const`-constructible too.
static SMALL_DECODER: std::sync::Mutex<gzip::WindowedDecoder<1024>> =
    std::sync::Mutex::new(gzip::WindowedDecoder::new());
static SMALL_ENCODER: std::sync::Mutex<gzip::BlockEncoder<1024, 256>> =
    std::sync::Mutex::new(gzip::BlockEncoder::new());

#[test]
fn a_small_window_decodes_what_stays_within_it() {
    let data = [text(30_000), random(3000), text(10_000)].concat();
    // Blocks no larger than the window keep every match within it.
    let encoded = encode_chunked(&mut *SMALL_ENCODER.lock().unwrap(), &data, 333, 77);
    for (in_chunk, out_chunk) in [(1, 1), (100, 7), (usize::MAX, 65536)] {
        let mut dec = SMALL_DECODER.lock().unwrap();
        dec.reset();
        let (back, consumed) = decode_chunked(&mut *dec, &encoded, in_chunk, out_chunk).unwrap();
        assert_eq!(back, data);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn a_small_window_rejects_what_reaches_beyond_it() {
    let mut dec = zlib::WindowedDecoder::<4096>::new();
    assert_eq!(
        decode_chunked(&mut dec, fixture!("far.zlib"), 1000, 1000).unwrap_err(),
        Error::InvalidDistance
    );
    // Just within the window decodes; `window_size` still tightens it.
    let stream = fixture!("far_exact.deflate");
    let mut dec = Box::new(deflate::WindowedDecoder::<32768>::new());
    assert_eq!(
        decode_chunked(&mut *dec, stream, 100, 100).unwrap().0,
        far_exact()
    );
    let mut dec = Box::new(deflate::WindowedDecoder::<16384>::new());
    assert_eq!(
        decode_chunked(&mut *dec, stream, 100, 100).unwrap_err(),
        Error::InvalidDistance
    );
    let tight = deflate::DecoderConfig::default().with_window_size(16);
    let encoded = encode_chunked(&mut deflate::Encoder::new(), &text(1000), 1000, 1000);
    let mut dec = deflate::WindowedDecoder::<256>::with_config(tight);
    assert_eq!(
        decode_chunked(&mut dec, &encoded, 1000, 1000).unwrap_err(),
        Error::InvalidDistance
    );
}

#[test]
fn block_and_table_sizes_set_the_ratio() {
    let data = text(200_000);
    let small = encode_chunked(&mut zlib::BlockEncoder::<256, 64>::new(), &data, 5000, 5000);
    let default = encode_chunked(&mut zlib::Encoder::new(), &data, 5000, 5000);
    let big = encode_chunked(
        &mut *Box::new(zlib::BlockEncoder::<32768, 4096>::new()),
        &data,
        5000,
        5000,
    );
    assert!(big.len() < default.len() && default.len() < small.len());
    for encoded in [&small, &default, &big] {
        assert_eq!(decode_all::<zlib::Zlib>(encoded).unwrap(), data);
    }
    // The smallest sizes still make a valid stream, whatever the chunking.
    let one = encode_chunked(
        &mut deflate::BlockEncoder::<1, 1>::new(),
        &data[..3000],
        7,
        3,
    );
    assert_eq!(decode_all::<deflate::Deflate>(&one).unwrap(), &data[..3000]);
}

#[test]
fn blocks_past_32_kib_keep_matches_within_reach() {
    // A repeat 40 000 bytes back is in the block, and out of deflate's
    // reach: the encoder must not use it.
    let data = [random(40_000), random(40_000)].concat();
    let mut enc = Box::new(gzip::BlockEncoder::<65536, 65536>::new());
    let encoded = encode_chunked(&mut *enc, &data, 9999, 4096);
    assert_eq!(decode_all::<gzip::Gzip>(&encoded).unwrap(), data);
}

// ─── one shot ───────────────────────────────────────────────────────────

/// Runs the one-shot functions of a module over `data`, checking them
/// against each other and against the streaming decoder.
macro_rules! one_shot_round_trip {
    ($module:ident, $algorithm:ty, $data:expr, $table:expr) => {{
        let data: &[u8] = $data;
        let mut out = vec![0u8; data.len() * 9 / 8 + 64];
        let n = $module::compress(data, $table, &mut out).unwrap();
        let encoded = &out[..n];
        assert_eq!(decode_all::<$algorithm>(encoded).unwrap(), data);
        let mut back = vec![0u8; data.len()];
        assert_eq!($module::decompress(encoded, &mut back), Ok(data.len()));
        assert_eq!(back, data);
        assert_eq!(
            $module::decompressed_len(encoded, usize::MAX),
            Ok(data.len())
        );
        n
    }};
}

#[test]
fn one_shot_functions_round_trip() {
    let mut table = vec![0u16; 4096];
    for data in [vec![], text(1), text(50_000), random(20_000), far()] {
        one_shot_round_trip!(gzip, gzip::Gzip, &data, &mut table);
        one_shot_round_trip!(zlib, zlib::Zlib, &data, &mut table);
        one_shot_round_trip!(deflate, deflate::Deflate, &data, &mut table);
    }
}

#[test]
fn one_shot_compress_takes_any_table() {
    let data = text(30_000);
    let mut sizes = Vec::new();
    // Not cleared, not a power of two, or nothing at all: all valid.
    for len in [0, 1, 3, 1000, 4096, 70_000] {
        let mut table = vec![0x5a5au16; len];
        sizes.push(one_shot_round_trip!(zlib, zlib::Zlib, &data, &mut table));
    }
    assert!(sizes[0] > data.len(), "no table, no matches: literals only");
    assert!(sizes[4] < sizes[3] && sizes[3] < sizes[0]);
}

#[test]
fn one_shot_compress_is_a_block_encoder_with_one_block() {
    let data = text(60_000);
    let mut table = [0u16; 1024];
    let mut out = vec![0u8; 70_000];
    let n = gzip::compress(&data, &mut table, &mut out).unwrap();
    let mut enc = Box::new(gzip::BlockEncoder::<65536, 1024>::new());
    assert_eq!(&out[..n], encode_chunked(&mut *enc, &data, 1000, 100));
}

#[test]
fn one_shot_decodes_the_reference_streams() {
    let mut out = vec![0u8; 100_000];
    let expected = text(60_000);
    for stream in [
        fixture!("text_l0.zlib"),
        fixture!("text_l1.zlib"),
        fixture!("text_l9.zlib"),
    ] {
        assert_eq!(zlib::decompress(stream, &mut out), Ok(expected.len()));
        assert_eq!(&out[..expected.len()], expected);
        assert_eq!(
            zlib::decompressed_len(stream, usize::MAX),
            Ok(expected.len())
        );
    }
    for stream in [fixture!("text_l6.gz"), fixture!("text_fancy.gz")] {
        assert_eq!(gzip::decompress(stream, &mut out), Ok(expected.len()));
        assert_eq!(&out[..expected.len()], expected);
    }
    let n = deflate::decompress(fixture!("text_l6.deflate"), &mut out).unwrap();
    assert_eq!(&out[..n], expected);
    let n = zlib::decompress(fixture!("far.zlib"), &mut out).unwrap();
    assert_eq!(&out[..n], far());
    let n = deflate::decompress(fixture!("far_exact.deflate"), &mut out).unwrap();
    assert_eq!(&out[..n], far_exact());
    let n = zlib::decompress(fixture!("random.zlib"), &mut out).unwrap();
    assert_eq!(&out[..n], random(20_000));
    assert_eq!(zlib::decompress(fixture!("empty.zlib"), &mut out), Ok(0));
    assert_eq!(gzip::decompress(fixture!("empty.gz"), &mut out), Ok(0));
    let mut out = vec![0u8; 1 + 258 * 2000];
    assert_eq!(
        deflate::decompress(fixture!("bomb.deflate"), &mut out),
        Ok(out.len())
    );
    assert!(out[..].iter().all(|&b| b == out[0]));
}

#[test]
fn one_shot_outputs_are_bounded() {
    let data = text(10_000);
    let mut gz = vec![0u8; 20_000];
    let n = gzip::compress(&data, &mut [0; 1024], &mut gz).unwrap();
    let gz = &gz[..n];
    let mut short = vec![0u8; data.len() - 1];
    assert_eq!(gzip::decompress(gz, &mut short), Err(Error::OutputTooSmall));
    assert_eq!(
        gzip::decompressed_len(gz, data.len() - 1),
        Err(Error::OutputLimitExceeded)
    );
    assert_eq!(gzip::decompressed_len(gz, data.len()), Ok(data.len()));
    // Compressing into one byte too few fails, whatever byte it is.
    for len in [0, 1, 10, n / 2, n - 1] {
        let mut out = vec![0u8; len];
        assert_eq!(
            gzip::compress(&data, &mut [0; 1024], &mut out),
            Err(Error::OutputTooSmall)
        );
    }
    let bomb = fixture!("bomb.deflate");
    assert_eq!(
        deflate::decompressed_len(bomb, 1000),
        Err(Error::OutputLimitExceeded)
    );
    assert_eq!(
        deflate::decompress(bomb, &mut [0; 1000]),
        Err(Error::OutputTooSmall)
    );
}

#[test]
fn one_shot_rejects_corrupt_streams() {
    let data = text(5000);
    let mut buf = vec![0u8; 10_000];
    let mut out = vec![0u8; data.len()];

    let n = zlib::compress(&data, &mut [0; 1024], &mut buf).unwrap();
    let z = &buf[..n];
    for cut in 0..z.len() {
        assert_eq!(
            zlib::decompress(&z[..cut], &mut out),
            Err(Error::UnexpectedEnd)
        );
        assert_eq!(
            zlib::decompressed_len(&z[..cut], usize::MAX),
            Err(Error::UnexpectedEnd)
        );
    }
    let mut bad = z.to_vec();
    bad[1] ^= 1;
    assert_eq!(zlib::decompress(&bad, &mut out), Err(Error::BadHeader));
    let mut bad = z.to_vec();
    bad[0] = 0x77;
    assert_eq!(zlib::decompress(&bad, &mut out), Err(Error::Unsupported));
    let mut bad = z.to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        zlib::decompress(&bad, &mut out),
        Err(Error::ChecksumMismatch)
    );
    // Counting cannot check the data, only the structure.
    assert_eq!(zlib::decompressed_len(&bad, usize::MAX), Ok(data.len()));

    let n = gzip::compress(&data, &mut [0; 1024], &mut buf).unwrap();
    let g = &buf[..n];
    for cut in 0..g.len() {
        assert_eq!(
            gzip::decompress(&g[..cut], &mut out),
            Err(Error::UnexpectedEnd)
        );
    }
    let mut bad = g.to_vec();
    bad[n - 8] ^= 1;
    assert_eq!(
        gzip::decompress(&bad, &mut out),
        Err(Error::ChecksumMismatch)
    );
    let mut bad = g.to_vec();
    bad[n - 4] ^= 1;
    assert_eq!(
        gzip::decompress(&bad, &mut out),
        Err(Error::TrailerMismatch)
    );
    assert_eq!(
        gzip::decompressed_len(&bad, usize::MAX),
        Err(Error::TrailerMismatch)
    );
    let mut bad = g.to_vec();
    bad[0] = 0x1e;
    assert_eq!(gzip::decompress(&bad, &mut out), Err(Error::BadHeader));

    // A block type of 3; and a fixed block that starts with a match, of 3
    // bytes from 1 back, before there is anything to copy from.
    assert_eq!(
        deflate::decompress(&[0x07], &mut out),
        Err(Error::InvalidBlockType)
    );
    assert_eq!(
        deflate::decompress(&[0x03, 0x02, 0x00, 0x00], &mut out),
        Err(Error::InvalidDistance)
    );
    assert_eq!(
        deflate::decompressed_len(&[0x03, 0x02, 0x00, 0x00], usize::MAX),
        Err(Error::InvalidDistance)
    );
}

#[test]
fn one_shot_ignores_what_follows_and_reads_every_gzip_member() {
    let mut a = vec![0u8; 1000];
    let n = gzip::compress(b"first, ", &mut [], &mut a).unwrap();
    a.truncate(n);
    let mut b = vec![0u8; 1000];
    let n = gzip::compress(b"second", &mut [], &mut b).unwrap();
    b.truncate(n);
    let mut out = [0u8; 64];
    let both = [a.clone(), b.clone()].concat();
    assert_eq!(gzip::decompress(&both, &mut out), Ok(13));
    assert_eq!(&out[..13], b"first, second");
    assert_eq!(gzip::decompressed_len(&both, 13), Ok(13));
    // Anything but another member is left alone, as gzip does.
    let padded = [a.clone(), vec![0; 7]].concat();
    assert_eq!(gzip::decompress(&padded, &mut out), Ok(7));
    let mut z = vec![0u8; 1000];
    let n = zlib::compress(b"zlib", &mut [0; 16], &mut z).unwrap();
    z.truncate(n);
    z.extend_from_slice(b"trailing");
    assert_eq!(zlib::decompress(&z, &mut out), Ok(4));
}

// ─── stack ──────────────────────────────────────────────────────────────

/// Both directions run on a thread with the least stack the platform
/// grants: a regression that put a window or a buffer on the stack during a
/// call would overflow it. 16 KiB is glibc's floor, and well above the few
/// hundred bytes a call needs. The codecs are boxed on the main thread: an
/// unoptimised `Box::new(Decoder::new())` builds the 34 KiB struct on the
/// stack first, which is exactly what `const` construction in a `static`
/// is for on a real target (see `codecs_can_be_built_in_statics`).
#[test]
#[cfg(target_os = "linux")]
fn codecs_run_on_a_small_stack() {
    let data = [text(40_000), random(5000), text(20_000)].concat();
    let mut enc = Box::new(gzip::Gzip::encoder());
    let mut dec = Box::new(gzip::Gzip::decoder());
    let mut raw = Box::new(deflate::Deflate::decoder());
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024)
        .spawn(move || {
            let encoded = encode_chunked(&mut *enc, &data, 1000, 300);
            let (back, _) = decode_chunked(&mut *dec, &encoded, 100, 1000).unwrap();
            assert_eq!(back, data);
            let (bomb, _) = decode_chunked(&mut *raw, fixture!("bomb.deflate"), 27, 1).unwrap();
            assert_eq!(bomb.len(), 1 + 258 * 2000);
            // The one-shot functions keep their state on the stack: about
            // 1.3 KiB to decode, the table being the caller's to encode.
            let mut table = vec![0u16; 1024];
            let mut gz = vec![0u8; data.len() * 2];
            let n = gzip::compress(&data, &mut table, &mut gz).unwrap();
            let mut back = vec![0u8; data.len()];
            assert_eq!(gzip::decompress(&gz[..n], &mut back), Ok(data.len()));
            assert_eq!(back, data);
        })
        .unwrap();
    handle.join().expect("the codecs overflowed a 16 KiB stack");
}
