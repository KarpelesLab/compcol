//! The push decoder and the buffered compressor, given their input in pieces
//! of every kind, and checked against the pull decoder and flate2.

#![cfg(all(feature = "embed", feature = "gzip", feature = "zlib"))]

use std::io::{Read, Write};

use compcol::embed::flate::*;
use flate2::read::GzDecoder;
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::{Compression, GzBuilder};

/// A small deterministic generator, so that failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }

    fn below(&mut self, n: usize) -> usize {
        self.next() as usize % n
    }
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng(1);
    let random: Vec<u8> = (0..40_000).map(|_| rng.next() as u8).collect();
    let text: Vec<u8> = (0..10_000)
        .flat_map(|_| {
            let word = ["alpha", "beta", "gamma", "delta", "epsilon", " ", "\n"][rng.below(7)];
            word.bytes()
        })
        .collect();
    // Matches at the far end of the window.
    let mut distant = random[..32_768].to_vec();
    distant.extend_from_within(..);
    distant.extend_from_within(100..30_000);
    // Few symbols, skewed: long and short Huffman codes.
    let skewed: Vec<u8> = (0..30_000)
        .map(|_| (rng.next() | rng.next() | rng.next()).trailing_ones() as u8)
        .collect();

    vec![
        ("empty", vec![]),
        ("one byte", vec![42]),
        ("short", b"hello hello hello hello".to_vec()),
        ("zeros", vec![0; 100_000]),
        ("random", random),
        ("text", text),
        ("distant", distant),
        ("skewed", skewed),
    ]
}

fn gzip_with(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn zlib_with(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn deflate_with(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// How to cut the input.
#[derive(Clone, Copy, Debug)]
enum Cut {
    Whole,
    Bytes,
    Random(u64),
}

fn pieces(data: &[u8], cut: Cut) -> Vec<&[u8]> {
    match cut {
        Cut::Whole => vec![data],
        Cut::Bytes => data.chunks(1).collect(),
        Cut::Random(seed) => {
            let mut rng = Rng(seed);
            let mut rest = data;
            let mut pieces = Vec::new();
            while !rest.is_empty() {
                // Empty pieces included.
                let max = [1, 4, 16, 5_000][rng.below(4)];
                let (piece, tail) = rest.split_at(rng.below(max + 1).min(rest.len()));
                pieces.push(piece);
                rest = tail;
            }
            pieces
        }
    }
}

/// Pushes `input` through a decompressor, to a buffer of `capacity` bytes.
/// Returns the outcome, the output, and how much of the input was consumed.
fn push<F: Container>(
    input: &[u8],
    cut: Cut,
    capacity: usize,
) -> (Result<u64, Error>, Vec<u8>, usize) {
    let mut out = vec![0; capacity];
    let mut buffer = Buffer::new(&mut out);
    let mut decompressor = Decompressor::<_, F>::new(&mut buffer);
    let mut consumed = 0;
    let mut result = Ok(());
    for piece in pieces(input, cut) {
        match decompressor.write(piece) {
            Ok(len) => {
                consumed += len;
                assert!(len <= piece.len());
                assert!(len == piece.len() || decompressor.is_done());
            }
            Err(error) => {
                // An error sticks.
                assert_eq!(decompressor.write(piece), Err(error));
                result = Err(error);
                break;
            }
        }
    }
    let finished = decompressor.finish();
    let result = result.and(finished);
    let filled = buffer.filled().to_vec();
    if let Ok(len) = result {
        assert_eq!(len, filled.len() as u64);
    }
    (result, filled, consumed)
}

#[test]
fn round_trips() {
    let cuts = [Cut::Whole, Cut::Bytes, Cut::Random(1), Cut::Random(2)];
    for (name, data) in samples() {
        for level in [0, 1, 6, 9] {
            for cut in cuts {
                let context = format!("{name}, level {level}, {cut:?}");
                let gz = gzip_with(&data, level);
                let z = zlib_with(&data, level);
                let raw = deflate_with(&data, level);

                let (result, out, consumed) = push::<Gzip>(&gz, cut, data.len());
                assert_eq!(result, Ok(data.len() as u64), "{context}");
                assert!(out == data, "{context}");
                assert_eq!(consumed, gz.len(), "{context}");

                let (result, out, consumed) = push::<Zlib>(&z, cut, data.len());
                assert_eq!(result, Ok(data.len() as u64), "{context}");
                assert!(out == data, "{context}");
                assert_eq!(consumed, z.len(), "{context}");

                let (result, out, consumed) = push::<Raw>(&raw, cut, data.len());
                assert_eq!(result, Ok(data.len() as u64), "{context}");
                assert!(out == data, "{context}");
                assert_eq!(consumed, raw.len(), "{context}");

                for stream in [&gz, &z] {
                    let (result, out, _) = push::<Detect>(stream, cut, data.len());
                    assert_eq!(result, Ok(data.len() as u64), "{context}");
                    assert!(out == data, "{context}");
                }
            }
        }
    }
}

/// A fixed block, which flate2 only emits for short inputs, and this crate's
/// compressor always.
#[test]
fn fixed_blocks() {
    let (_, data) = samples().swap_remove(5);
    let mut table = [0; 1024];
    let mut packed = vec![0; data.len()];
    let len = gzip(&data, &mut table, Buffer::new(&mut packed)).unwrap() as usize;
    for cut in [Cut::Whole, Cut::Bytes, Cut::Random(3)] {
        let (result, out, consumed) = push::<Gzip>(&packed[..len], cut, data.len());
        assert_eq!(result, Ok(data.len() as u64));
        assert!(out == data);
        assert_eq!(consumed, len);
    }
}

/// Each `write` delivers what it decoded, without waiting for the window of a
/// `Stream` to fill up, and a small window will do as far as the matches go.
#[test]
fn output_follows_input() {
    let data: Vec<u8> = (0..50_000u32).map(|i| ((i * i) >> 7) as u8).collect();
    let gz = gzip_with(&data, 6);
    let mut out = Vec::new();
    let mut window = vec![0; 32_768];
    let mut stream = Stream::new(&mut window, NO_LIMIT, |piece: &[u8]| {
        assert!(!piece.is_empty());
        out.extend_from_slice(piece);
        Ok(())
    });
    {
        let mut decompressor = Decompressor::<_, Gzip>::new(&mut stream);
        for piece in gz.chunks(100) {
            assert_eq!(decompressor.write(piece), Ok(piece.len()));
        }
        assert_eq!(decompressor.finish(), Ok(data.len() as u64));
    }
    assert_eq!(stream.written(), data.len() as u64);
    assert!(out == data);

    // The same, watching the output grow with every piece.
    let seen = std::cell::Cell::new(0);
    let mut window = vec![0; 32_768];
    let stream = Stream::new(&mut window, NO_LIMIT, |piece: &[u8]| {
        seen.set(seen.get() + piece.len());
        Ok(())
    });
    let mut decompressor = Decompressor::<_, Gzip>::new(stream);
    let mut last = 0;
    let mut grew = 0;
    for piece in gz.chunks(100) {
        decompressor.write(piece).unwrap();
        grew += (seen.get() > last) as usize;
        last = seen.get();
    }
    assert!(grew > gz.len() / 100 / 2, "{grew}");
    assert_eq!(decompressor.finish(), Ok(data.len() as u64));
    assert_eq!(seen.get(), data.len());
}

#[test]
fn gzip_header_fields() {
    let data = b"some data, some data, some data";
    for (name, comment, extra) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (true, true, true),
    ] {
        let mut builder = GzBuilder::new().mtime(123_456_789);
        if name {
            builder = builder.filename("a name");
        }
        if comment {
            builder = builder.comment("a comment, with a \x1f in it");
        }
        if extra {
            builder = builder.extra(vec![0x1f; 300]);
        }
        let mut encoder = builder.write(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        let gz = encoder.finish().unwrap();
        for cut in [Cut::Whole, Cut::Bytes, Cut::Random(4)] {
            let (result, out, consumed) = push::<Gzip>(&gz, cut, data.len());
            assert_eq!(result, Ok(data.len() as u64));
            assert_eq!(out, data);
            assert_eq!(consumed, gz.len());
        }
    }

    // A header CRC, which flate2 does not write: FHCRC set by hand.
    let mut gz = gzip_with(data, 6);
    gz[3] |= 2;
    gz.splice(10..10, [0xaa, 0xbb]);
    for cut in [Cut::Whole, Cut::Bytes] {
        let (result, out, _) = push::<Gzip>(&gz, cut, data.len());
        assert_eq!(result, Ok(data.len() as u64));
        assert_eq!(out, data);
    }
}

#[test]
fn gzip_members() {
    let parts: [&[u8]; 3] = [b"first, first, first. ", b"", b"third third third"];
    let whole: Vec<u8> = parts.concat();
    let mut gz = Vec::new();
    for part in parts {
        gz.extend(gzip_with(part, 6));
    }
    for cut in [Cut::Whole, Cut::Bytes, Cut::Random(5)] {
        let (result, out, consumed) = push::<Gzip>(&gz, cut, whole.len());
        assert_eq!(result, Ok(whole.len() as u64), "{cut:?}");
        assert_eq!(out, whole);
        assert_eq!(consumed, gz.len());

        let (result, out, _) = push::<Detect>(&gz, cut, whole.len());
        assert_eq!(result, Ok(whole.len() as u64), "{cut:?}");
        assert_eq!(out, whole);
    }

    // Padding ends the stream: one byte of it is consumed, the rest left.
    let mut padded = gz.clone();
    padded.extend([0; 10]);
    for cut in [Cut::Whole, Cut::Bytes, Cut::Random(6)] {
        let (result, out, consumed) = push::<Gzip>(&padded, cut, whole.len());
        assert_eq!(result, Ok(whole.len() as u64), "{cut:?}");
        assert_eq!(out, whole);
        assert_eq!(consumed, gz.len() + 1);
    }

    // Each member is checked against its own checksum and length.
    let mut bad = gz.clone();
    let at = gzip_with(parts[0], 6).len() - 8;
    bad[at] ^= 1;
    for cut in [Cut::Whole, Cut::Bytes] {
        let (result, _, _) = push::<Gzip>(&bad, cut, whole.len());
        assert_eq!(result, Err(Error::ChecksumMismatch));
    }
}

/// Not a byte is consumed past the end of a stream that says where it ends.
#[test]
fn input_is_left_after_the_stream() {
    let data = b"data data data data";
    for stream in [
        zlib_with(data, 6),
        deflate_with(data, 6),
        deflate_with(data, 0),
    ] {
        let is_zlib = stream[0] == 0x78;
        let mut followed = stream.clone();
        followed.extend(b"what follows");
        for cut in [Cut::Whole, Cut::Bytes, Cut::Random(7)] {
            let (result, out, consumed) = match is_zlib {
                true => push::<Zlib>(&followed, cut, data.len()),
                false => push::<Raw>(&followed, cut, data.len()),
            };
            assert_eq!(result, Ok(data.len() as u64));
            assert_eq!(out, data);
            assert_eq!(consumed, stream.len(), "{cut:?}");
        }
    }
}

#[test]
fn truncation() {
    let mut rng = Rng(6);
    let data: Vec<u8> = (0..3_000).map(|_| b"abcdefgh"[rng.below(8)]).collect();
    for level in [0, 1, 9] {
        let gz = gzip_with(&data, level);
        for len in 0..gz.len() {
            for cut in [Cut::Whole, Cut::Random(len as u64)] {
                let (result, out, consumed) = push::<Gzip>(&gz[..len], cut, data.len());
                assert_eq!(result, Err(Error::UnexpectedEof), "{len} of {}", gz.len());
                // Nothing made up past the end of the input reaches the output.
                assert!(data.starts_with(&out), "{len} of {}", gz.len());
                assert_eq!(consumed, len);
            }
        }
        // All of the data is out before the trailer comes.
        let (_, out, _) = push::<Gzip>(&gz[..gz.len() - 8], Cut::Whole, data.len());
        assert!(out == data);
    }
}

/// Whatever the input and however it is cut, the push decoder agrees with the
/// pull one: same outcome, same output.
#[test]
fn corruption() {
    let mut rng = Rng(7);
    let samples = samples();
    let streams: Vec<Vec<u8>> = samples
        .iter()
        .flat_map(|(_, data)| {
            [
                gzip_with(data, 0),
                gzip_with(data, 1),
                gzip_with(data, 9),
                zlib_with(data, 6),
            ]
        })
        .collect();
    let mut out = vec![0; 1_000_000];
    let mut failures = 0;
    for round in 0..3_000 {
        let mut bad = streams[round % streams.len()].clone();
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(bad.len());
            match rng.below(3) {
                0 => bad[at] ^= 1 << rng.below(8),
                1 => bad[at] = rng.next() as u8,
                _ => bad.truncate(at.max(1)),
            }
        }
        let mut buffer = Buffer::new(&mut out);
        let mut rest = &bad[..];
        let pulled = decompress(&mut rest, &mut buffer);
        let cut = [Cut::Whole, Cut::Random(round as u64)][round % 2];
        let (pushed, pushed_out, consumed) = push::<Detect>(&bad, cut, 1_000_000);
        assert_eq!(pushed, pulled, "round {round}");
        assert!(pushed_out == buffer.filled(), "round {round}");
        if pulled.is_ok() {
            assert_eq!(consumed, bad.len() - rest.len(), "round {round}");
        }
        failures += pulled.is_err() as usize;
    }
    assert!(failures > 2_000, "{failures}");

    // Pure noise, as raw deflate.
    for round in 0..20_000 {
        let noise: Vec<u8> = (0..1 + rng.below(200)).map(|_| rng.next() as u8).collect();
        let mut buffer = Buffer::new(&mut out);
        let pulled = inflate(&noise[..], &mut buffer);
        let cut = [Cut::Whole, Cut::Bytes, Cut::Random(round as u64)][round % 3];
        let (pushed, pushed_out, _) = push::<Raw>(&noise, cut, 1_000_000);
        assert_eq!(pushed, pulled, "round {round}");
        assert!(pushed_out == buffer.filled(), "round {round}");
    }
}

#[test]
fn errors() {
    let data = b"hello hello hello hello";
    let gz = gzip_with(data, 6);

    // Nothing at all.
    assert_eq!(
        push::<Gzip>(&[], Cut::Whole, 0).0,
        Err(Error::UnexpectedEof)
    );
    assert_eq!(push::<Raw>(&[], Cut::Whole, 0).0, Err(Error::UnexpectedEof));

    // The wrong container.
    assert_eq!(
        push::<Zlib>(&gz, Cut::Bytes, 64).0,
        Err(Error::InvalidHeader)
    );
    let z = zlib_with(data, 6);
    assert_eq!(
        push::<Gzip>(&z, Cut::Bytes, 64).0,
        Err(Error::InvalidHeader)
    );

    // An output too small.
    assert_eq!(
        push::<Gzip>(&gz, Cut::Bytes, data.len() - 1).0,
        Err(Error::OutputFull)
    );

    // A wrong checksum, a wrong length.
    for at in [8, 4] {
        let mut bad = gz.clone();
        let at = bad.len() - at;
        bad[at] ^= 1;
        assert_eq!(
            push::<Gzip>(&bad, Cut::Bytes, 64).0,
            Err(Error::ChecksumMismatch)
        );
    }
    let mut bad = z.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        push::<Zlib>(&bad, Cut::Bytes, 64).0,
        Err(Error::ChecksumMismatch)
    );

    // A `Counter` cannot verify checksums, but still can the length.
    let mut bad = gz.clone();
    let at = bad.len() - 8;
    bad[at] ^= 1;
    let mut decompressor = Decompressor::<_, Gzip>::new(Counter::new(NO_LIMIT));
    assert_eq!(decompressor.write(&bad), Ok(bad.len()));
    assert_eq!(decompressor.finish(), Ok(data.len() as u64));
    let at = bad.len() - 4;
    bad[at] ^= 1;
    assert_eq!(decompressor.write(&bad), Err(Error::ChecksumMismatch));
}

/// Once finished, a decompressor takes another stream, to the same output.
#[test]
fn reuse() {
    let mut out = [0; 64];
    let mut buffer = Buffer::new(&mut out);
    let mut decompressor = Decompressor::<_, Gzip>::new(&mut buffer);
    for cut in [1, 3, 100] {
        for piece in gzip_with(b"again ", 6).chunks(cut) {
            decompressor.write(piece).unwrap();
        }
        assert_eq!(decompressor.finish(), Ok(6));
    }
    // After a failure as well.
    assert_eq!(decompressor.write(b"nope"), Err(Error::InvalidHeader));
    assert_eq!(decompressor.finish(), Err(Error::InvalidHeader));
    decompressor.write(&gzip_with(b"again ", 6)[..12]).unwrap();
    assert_eq!(decompressor.finish(), Err(Error::UnexpectedEof));
    decompressor.write(&gzip_with(b"again ", 6)).unwrap();
    assert_eq!(decompressor.finish(), Ok(6));
    assert_eq!(buffer.filled(), b"again again again aagain ");
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    out
}

/// Compresses `data` in pieces through a buffer of `size` bytes.
fn buffered(data: &[u8], cut: Cut, size: usize) -> Vec<u8> {
    let mut table = [0; 1024];
    let mut buffer = vec![0; size];
    let mut packed = vec![0; 3 * data.len() + 4_096];
    let mut compressor =
        BufferedCompressor::<_, Gzip>::new(Buffer::new(&mut packed), &mut table, &mut buffer);
    for piece in pieces(data, cut) {
        compressor.write(piece).unwrap();
    }
    let len = compressor.finish().unwrap() as usize;
    packed.truncate(len);
    packed
}

#[test]
fn buffered_compressor() {
    for (name, data) in samples() {
        for size in [0, 1, 7, 1_000, 32_768, 1 << 20] {
            let whole = buffered(&data, Cut::Whole, size);
            assert!(
                read_all(GzDecoder::new(&whole[..])) == data,
                "{name}, {size}"
            );
            let (result, out, _) = push::<Gzip>(&whole, Cut::Random(8), data.len());
            assert_eq!(result, Ok(data.len() as u64), "{name}, {size}");
            assert!(out == data, "{name}, {size}");

            // With a buffer, how the data is cut makes no difference.
            if size > 0 {
                for cut in [Cut::Bytes, Cut::Random(9), Cut::Random(10)] {
                    assert!(
                        buffered(&data, cut, size) == whole,
                        "{name}, {size}, {cut:?}"
                    );
                }
            }
        }
    }

    // A byte at a time through a buffer is as good as chunks of its size, and
    // a far cry from a byte at a time without one.
    let (_, text) = samples().swap_remove(5);
    let through = buffered(&text, Cut::Bytes, 32_768).len();
    let chunks = {
        let mut table = [0; 1024];
        let mut compressor = Compressor::<_, Gzip>::new(Counter::new(NO_LIMIT), &mut table);
        for chunk in text.chunks(32_768) {
            compressor.write(chunk).unwrap();
        }
        compressor.finish().unwrap() as usize
    };
    assert_eq!(through, chunks);
    assert!(through * 3 < buffered(&text, Cut::Bytes, 0).len());
}
