//! Tests for the `embed` build of the deflate family: the `minizlib`-backed
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

use compcol::embed::{BLOCK, DECODER_SIZE, ENCODER_SIZE, WINDOW};
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
            assert_eq!(
                encode_chunked(&mut zlib::Zlib::encoder(), &input, in_chunk, out_chunk),
                whole
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
    bad[0] = 0x79; // CMF/FLG check fails
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
        Error::ChecksumMismatch
    );
}

#[test]
fn errors_poison_until_reset() {
    let mut dec = zlib::Zlib::decoder();
    let mut buf = [0u8; 64];
    assert_eq!(
        dec.decode(&[0x79, 0x9c], &mut buf).unwrap_err(),
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

    // Once ended, further calls are no-ops reporting StreamEnd.
    let mut dec = gzip::Gzip::decoder();
    let mut buf = vec![0u8; 65536];
    let (p, status) = dec.decode(fixture!("text_l6.gz"), &mut buf).unwrap();
    assert_eq!(status, Status::StreamEnd);
    assert_eq!(p.consumed, fixture!("text_l6.gz").len());
    let (p, status) = dec.decode(b"more", &mut buf).unwrap();
    assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));
}

#[test]
fn second_gzip_member_is_not_decoded() {
    let one = fixture!("text_l6.gz");
    let two = [one, one].concat();
    let (back, consumed) = decode_chunked(&mut gzip::Gzip::decoder(), &two, 100, 1000).unwrap();
    assert_eq!(back, text(60_000));
    assert_eq!(consumed, one.len());
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
        })
        .unwrap();
    handle.join().expect("the codecs overflowed a 16 KiB stack");
}
