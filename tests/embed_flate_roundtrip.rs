//! Round trips against flate2, over every input and output kind.

#![cfg(all(feature = "embed", feature = "gzip", feature = "zlib"))]

use std::io::Write;

use compcol::embed::flate::*;
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
    let random: Vec<u8> = (0..100_000).map(|_| rng.next() as u8).collect();
    let text: Vec<u8> = (0..20_000)
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
    let skewed: Vec<u8> = (0..50_000)
        .map(|_| (rng.next() | rng.next() | rng.next()).trailing_ones() as u8)
        .collect();

    vec![
        ("empty", vec![]),
        ("one byte", vec![42]),
        ("short", b"hello hello hello hello".to_vec()),
        ("zeros", vec![0; 300_000]),
        ("random", random),
        ("text", text),
        ("distant", distant),
        ("skewed", skewed),
    ]
}

fn gzip(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn zlib(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn deflate(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Decompresses to a buffer of exactly the right size.
fn to_buffer(
    f: impl Fn(&[u8], Buffer) -> Result<u64, Error>,
    input: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; len];
    let written = f(input, Buffer::new(&mut out))?;
    assert_eq!(written, len as u64);
    Ok(out)
}

/// Decompresses through a window of `window` bytes.
fn to_stream<I: Input>(
    f: impl FnOnce(I, &mut Stream<&mut dyn FnMut(&[u8]) -> Result<(), Error>>) -> Result<u64, Error>,
    input: I,
    window: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut window = vec![0; window];
    let mut sink = |data: &[u8]| {
        assert!(!data.is_empty());
        out.extend_from_slice(data);
        Ok(())
    };
    let mut stream = Stream::new(
        &mut window,
        NO_LIMIT,
        &mut sink as &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    );
    let written = f(input, &mut stream)?;
    assert_eq!(stream.written(), written);
    assert_eq!(written, out.len() as u64);
    Ok(out)
}

/// A `Reader` closure handing out `data` in chunks of random sizes.
fn chunked<'a>(
    data: &'a [u8],
    rng: &'a mut Rng,
) -> impl FnMut(&mut [u8]) -> Result<usize, Error> + 'a {
    let mut data = data;
    move |buf| {
        let n = (1 + rng.below(buf.len())).min(data.len());
        let (chunk, rest) = data.split_at(n);
        buf[..n].copy_from_slice(chunk);
        data = rest;
        Ok(n)
    }
}

#[test]
fn round_trips() {
    let mut rng = Rng(2);
    for (name, data) in samples() {
        for level in 0..=9 {
            let what = format!("{name}, level {level}");
            let gz = gzip(&data, level);
            let zl = zlib(&data, level);
            let raw = deflate(&data, level);

            // Buffer in, buffer out.
            assert_eq!(
                to_buffer(|i, o| gunzip(i, o), &gz, data.len()).unwrap(),
                data,
                "{what}"
            );
            assert_eq!(
                to_buffer(|i, o| unzlib(i, o), &zl, data.len()).unwrap(),
                data,
                "{what}"
            );
            assert_eq!(
                to_buffer(|i, o| inflate(i, o), &raw, data.len()).unwrap(),
                data,
                "{what}"
            );
            assert_eq!(
                to_buffer(|i, o| decompress(i, o), &gz, data.len()).unwrap(),
                data,
                "{what}"
            );
            assert_eq!(
                to_buffer(|i, o| decompress(i, o), &zl, data.len()).unwrap(),
                data,
                "{what}"
            );

            // Buffer in, stream out, through a minimal and an odd window.
            assert_eq!(
                to_stream(|i, o| gunzip(i, o), &gz[..], 32_768).unwrap(),
                data,
                "{what}"
            );
            assert_eq!(
                to_stream(|i, o| unzlib(i, o), &zl[..], 40_001).unwrap(),
                data,
                "{what}"
            );
            assert_eq!(
                to_stream(|i, o| inflate(i, o), &raw[..], 1 << 20).unwrap(),
                data,
                "{what}"
            );

            // Stream in, stream out.
            let mut scratch = [0; 61];
            let reader = Reader::new(&mut scratch, chunked(&gz, &mut rng));
            assert_eq!(
                to_stream(|i, o| gunzip(i, o), reader, 32_768).unwrap(),
                data,
                "{what}"
            );
            let reader = Reader::new(&mut scratch[..1], chunked(&zl, &mut rng));
            assert_eq!(
                to_stream(|i, o| unzlib(i, o), reader, 32_768).unwrap(),
                data,
                "{what}"
            );
            let bytes = Bytes(raw.iter().copied());
            assert_eq!(
                to_stream(|i, o| inflate(i, o), bytes, 32_768).unwrap(),
                data,
                "{what}"
            );

            // Lengths.
            assert_eq!(
                gunzip_len(&gz[..], NO_LIMIT).unwrap(),
                data.len() as u64,
                "{what}"
            );
            assert_eq!(
                unzlib_len(&zl[..], NO_LIMIT).unwrap(),
                data.len() as u64,
                "{what}"
            );
            assert_eq!(
                inflate_len(&raw[..], NO_LIMIT).unwrap(),
                data.len() as u64,
                "{what}"
            );
            assert_eq!(
                decompress_len(&gz[..], NO_LIMIT).unwrap(),
                data.len() as u64,
                "{what}"
            );
            assert_eq!(
                decompress_len(Bytes(zl.iter().copied()), NO_LIMIT).unwrap(),
                data.len() as u64,
                "{what}"
            );
            assert_eq!(gzip_size_hint(&gz), Some(data.len() as u32), "{what}");
        }
    }
}

#[test]
fn fixed_block_from_zlib() {
    let text = b"It was the best of times, it was the worst of times, it was the age of wisdom, \
        it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity";
    // zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_FIXED)
    let raw = [
        0xf3, 0x2c, 0x51, 0x28, 0x4f, 0x2c, 0x56, 0x28, 0xc9, 0x48, 0x55, 0x48, 0x4a, 0x2d, 0x2e,
        0x51, 0xc8, 0x4f, 0x53, 0x28, 0xc9, 0xcc, 0x4d, 0x2d, 0xd6, 0x51, 0xc8, 0x44, 0xc8, 0x94,
        0xe7, 0x17, 0xe1, 0x92, 0x4a, 0x4c, 0x4f, 0x05, 0x49, 0x94, 0x67, 0x16, 0xa7, 0xe4, 0xe7,
        0x62, 0x93, 0x49, 0xcb, 0xcf, 0xcf, 0xc9, 0x2c, 0xce, 0xc8, 0x4b, 0x2d, 0x46, 0xd5, 0x98,
        0x5a, 0x90, 0x9f, 0x9c, 0x01, 0x52, 0x90, 0x94, 0x9a, 0x93, 0x99, 0x9a, 0x86, 0x5d, 0x2e,
        0x33, 0x2f, 0xb9, 0x28, 0x35, 0xa5, 0x34, 0x27, 0xb3, 0xa4, 0x12, 0x00,
    ];
    assert_eq!(raw[0] & 7, 0b011, "a final fixed block");
    assert_eq!(
        to_buffer(|i, o| inflate(i, o), &raw, text.len()).unwrap(),
        text
    );
    assert_eq!(
        to_stream(|i, o| inflate(i, o), &raw[..], 32_768).unwrap(),
        text
    );
    assert_eq!(inflate_len(&raw[..], NO_LIMIT).unwrap(), text.len() as u64);
}

#[test]
fn gzip_header_fields() {
    let mut encoder = GzBuilder::new()
        .filename("name.txt")
        .comment("a comment")
        .extra(vec![1, 2, 3, 4, 5])
        .mtime(123_456_789)
        .write(Vec::new(), Compression::default());
    encoder.write_all(b"payload payload payload").unwrap();
    let mut gz = encoder.finish().unwrap();
    assert_eq!(gz[3], 0b11100, "FEXTRA, FNAME and FCOMMENT");
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, 23).unwrap(),
        b"payload payload payload"
    );

    // Add a header CRC, which is skipped without being verified.
    gz[3] |= 0b10;
    let header_len = 10 + 2 + 5 + 9 + 10;
    gz.splice(header_len..header_len, [0xaa, 0xbb]);
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, 23).unwrap(),
        b"payload payload payload"
    );

    gz[3] |= 0x20;
    assert_eq!(
        gunzip_len(&gz[..], NO_LIMIT),
        Err(Error::InvalidHeader),
        "reserved flag"
    );
}

#[test]
fn gzip_members() {
    let mut gz = gzip(b"first,", 6);
    gz.extend(gzip(b"", 6));
    gz.extend(gzip(b"second,", 0));
    gz.extend(gzip(b"third", 9));
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, 18).unwrap(),
        b"first,second,third"
    );
    assert_eq!(
        to_stream(|i, o| gunzip(i, o), &gz[..], 32_768).unwrap(),
        b"first,second,third"
    );
    assert_eq!(gunzip_len(&gz[..], NO_LIMIT).unwrap(), 18);
    assert_eq!(
        gzip_size_hint(&gz),
        Some(5),
        "the hint only knows about the last member"
    );

    // Trailing padding is ignored, a trailing broken member is not.
    gz.extend([0; 7]);
    assert_eq!(gunzip_len(&gz[..], NO_LIMIT).unwrap(), 18);
    gz.truncate(gz.len() - 7);
    gz.extend([0x1f, 0x8c, 8]);
    assert_eq!(gunzip_len(&gz[..], NO_LIMIT), Err(Error::InvalidHeader));
    gz.pop();
    assert_eq!(gunzip_len(&gz[..], NO_LIMIT), Err(Error::UnexpectedEof));
}

#[test]
fn members_check_their_own_data() {
    // Corrupt the first member only: its checksum must not cover the second.
    let first = gzip(b"first member", 6);
    let mut gz = first.clone();
    gz.extend(gzip(b"second member", 6));
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, 25).unwrap(),
        b"first membersecond member"
    );
    let crc = first.len() - 8;
    gz[crc] ^= 1;
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, 25),
        Err(Error::ChecksumMismatch)
    );
    assert_eq!(
        to_stream(|i, o| gunzip(i, o), &gz[..], 32_768),
        Err(Error::ChecksumMismatch)
    );
}

#[test]
fn input_is_left_after_the_stream() {
    let mut data = zlib(b"some data", 6);
    let len = data.len();
    data.extend(b"what follows");
    let mut input = &data[..];
    assert_eq!(unzlib_len(&mut input, NO_LIMIT).unwrap(), 9);
    assert_eq!(input, b"what follows");

    let mut scratch = [0; 8];
    let mut rng = Rng(3);
    let mut reader = Reader::new(&mut scratch, chunked(&data, &mut rng));
    assert_eq!(unzlib_len(&mut reader, NO_LIMIT).unwrap(), 9);
    assert!(data[len..].starts_with(reader.buffered()));

    // Looking for another gzip member takes one more byte.
    let mut data = gzip(b"some data", 6);
    data.extend(b"what follows");
    let mut input = &data[..];
    assert_eq!(gunzip_len(&mut input, NO_LIMIT).unwrap(), 9);
    assert_eq!(input, b"hat follows");
}

#[test]
fn output_is_appended() {
    let mut out = [0; 16];
    let mut buffer = Buffer::new(&mut out);
    assert_eq!(gunzip(&gzip(b"one, ", 6)[..], &mut buffer).unwrap(), 5);
    assert_eq!(unzlib(&zlib(b"two, ", 6)[..], &mut buffer).unwrap(), 5);
    assert_eq!(inflate(&deflate(b"three", 6)[..], &mut buffer).unwrap(), 5);
    assert_eq!(buffer.filled(), b"one, two, three");
    assert_eq!(buffer.written(), 15);
}

#[test]
fn errors() {
    let mut rng = Rng(4);
    let data: Vec<u8> = (0..50_000).map(|_| b"abcdefgh"[rng.below(8)]).collect();
    let gz = gzip(&data, 6);
    let zl = zlib(&data, 6);
    let len = data.len();

    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, len - 1),
        Err(Error::OutputFull)
    );
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &gz, 0),
        Err(Error::OutputFull)
    );
    assert_eq!(
        to_buffer(|i, o| gunzip(i, o), &zl, len),
        Err(Error::InvalidHeader)
    );
    assert_eq!(
        to_buffer(|i, o| unzlib(i, o), &gz, len),
        Err(Error::InvalidHeader)
    );
    assert_eq!(
        to_buffer(|i, o| decompress(i, o), &[], len),
        Err(Error::UnexpectedEof)
    );

    for trailer in 1..=8 {
        let mut bad = gz.clone();
        let at = bad.len() - trailer;
        bad[at] ^= 0x10;
        assert_eq!(
            to_buffer(|i, o| gunzip(i, o), &bad, len),
            Err(Error::ChecksumMismatch)
        );
        // Without the data, only the length can be verified.
        let expected = if trailer <= 4 {
            Err(Error::ChecksumMismatch)
        } else {
            Ok(len as u64)
        };
        assert_eq!(gunzip_len(&bad[..], NO_LIMIT), expected);
    }
    let mut bad = zl.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        to_buffer(|i, o| unzlib(i, o), &bad, len),
        Err(Error::ChecksumMismatch)
    );
    assert_eq!(
        to_stream(|i, o| unzlib(i, o), &bad[..], 32_768),
        Err(Error::ChecksumMismatch)
    );

    // Compression method, preset dictionary, window size.
    let mut bad = gz.clone();
    bad[2] = 7;
    assert_eq!(gunzip_len(&bad[..], NO_LIMIT), Err(Error::Unsupported));
    assert_eq!(
        unzlib_len(&[0x78, 0xbb][..], NO_LIMIT),
        Err(Error::Unsupported)
    );
    assert_eq!(
        unzlib_len(&[0x88, 0x1c][..], NO_LIMIT),
        Err(Error::Unsupported)
    );
    assert_eq!(
        unzlib_len(&[0x78, 0x9d][..], NO_LIMIT),
        Err(Error::InvalidHeader)
    );

    // Block type 3, and a stored block whose length check fails.
    assert_eq!(
        inflate_len(&[0b111][..], NO_LIMIT),
        Err(Error::InvalidBlock)
    );
    assert_eq!(
        inflate_len(&[1, 5, 0, 0xfa, 0xfe][..], NO_LIMIT),
        Err(Error::InvalidBlock)
    );
    // A fixed block starting with a match, which has nothing to refer to.
    let lone_match = [0b0000_0011, 0b0000_0010, 0];
    assert_eq!(
        inflate_len(&lone_match[..], NO_LIMIT),
        Err(Error::InvalidDistance)
    );
    assert_eq!(
        to_buffer(|i, o| inflate(i, o), &lone_match, 9),
        Err(Error::InvalidDistance)
    );
    assert_eq!(
        to_stream(|i, o| inflate(i, o), &lone_match[..], 9),
        Err(Error::InvalidDistance)
    );

    // Callback failures come back as they are.
    let mut scratch = [0; 8];
    let reader = Reader::new(&mut scratch, |_| Err(Error::Io));
    assert_eq!(gunzip_len(reader, NO_LIMIT), Err(Error::Io));
    let reader = Reader::new(&mut scratch, |buf| {
        buf.copy_from_slice(&gz[..buf.len()]);
        Ok(buf.len() + 1)
    });
    assert_eq!(gunzip_len(reader, NO_LIMIT), Err(Error::Io));
    let mut window = [0; 1000];
    let stream = Stream::new(&mut window, NO_LIMIT, |_| Err(Error::Io));
    assert_eq!(gunzip(&gz[..], stream), Err(Error::Io));
}

#[test]
fn small_windows() {
    // Data whose matches are all close by only needs a small window.
    let mut rng = Rng(5);
    let near: Vec<u8> = (0..400)
        .map(|_| rng.next() as u8)
        .collect::<Vec<_>>()
        .repeat(100);
    let gz = gzip(&near, 9);
    assert_eq!(to_stream(|i, o| gunzip(i, o), &gz[..], 400).unwrap(), near);
    assert_eq!(
        to_stream(|i, o| gunzip(i, o), &gz[..], 399),
        Err(Error::WindowTooSmall)
    );
    assert_eq!(
        to_stream(|i, o| gunzip(i, o), &gz[..], 0),
        Err(Error::WindowTooSmall)
    );
    assert_eq!(
        to_stream(|i, o| gunzip(i, o), &gzip(b"", 9)[..], 0).unwrap(),
        b""
    );
}

#[test]
fn truncation() {
    let mut rng = Rng(6);
    let data: Vec<u8> = (0..3_000).map(|_| b"abcdefgh"[rng.below(8)]).collect();
    for level in [0, 1, 9] {
        let gz = gzip(&data, level);
        for len in 0..gz.len() {
            assert_eq!(
                gunzip_len(&gz[..len], NO_LIMIT),
                Err(Error::UnexpectedEof),
                "{len} of {}",
                gz.len()
            );
            assert_eq!(
                to_stream(|i, o| gunzip(i, o), &gz[..len], 32_768),
                Err(Error::UnexpectedEof)
            );

            // Nothing made up past the end of the input reaches the output,
            // and an input that has ended is left alone.
            let mut out = vec![0; data.len()];
            let mut buffer = Buffer::new(&mut out);
            let mut rest = &gz[..len];
            let mut ended = false;
            let mut scratch = [0; 16];
            let reader = Reader::new(&mut scratch, |buf| {
                assert!(!ended, "read again after the end");
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                rest = &rest[n..];
                ended = n == 0;
                Ok(n)
            });
            assert_eq!(gunzip(reader, &mut buffer), Err(Error::UnexpectedEof));
            assert!(data.starts_with(buffer.filled()), "{len} of {}", gz.len());
        }
    }
}

/// Whatever the input, decoding terminates without panicking and without
/// producing more than the output can hold.
#[test]
fn corruption() {
    let mut rng = Rng(7);
    let samples = samples();
    let streams: Vec<Vec<u8>> = samples
        .iter()
        .flat_map(|(_, data)| [gzip(data, 0), gzip(data, 1), gzip(data, 9), zlib(data, 6)])
        .collect();
    let mut out = vec![0; 4_000_000];
    let mut window = vec![0; 32_768];
    let mut failures = 0;
    for round in 0..4_000 {
        let mut bad = streams[round % streams.len()].clone();
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(bad.len());
            match rng.below(3) {
                0 => bad[at] ^= 1 << rng.below(8),
                1 => bad[at] = rng.next() as u8,
                _ => bad.truncate(at.max(1)),
            }
        }
        let buffered = decompress(&bad[..], Buffer::new(&mut out));
        let mut streamed_len = 0;
        let streamed = decompress(
            &bad[..],
            Stream::new(&mut window, NO_LIMIT, |data| {
                streamed_len += data.len();
                Ok(())
            }),
        );
        assert_ne!(buffered, Err(Error::OutputFull), "round {round}");
        assert_eq!(buffered, streamed, "round {round}");
        if let Ok(len) = streamed {
            assert_eq!(len, streamed_len as u64);
        }
        if buffered.is_ok() {
            assert_eq!(
                decompress_len(&bad[..], NO_LIMIT),
                buffered,
                "round {round}"
            );
        }
        failures += buffered.is_err() as usize;
    }
    assert!(failures > 3_000, "{failures}");

    // Pure noise, as raw deflate.
    for _ in 0..20_000 {
        let noise: Vec<u8> = (0..1 + rng.below(200)).map(|_| rng.next() as u8).collect();
        let buffered = inflate(&noise[..], Buffer::new(&mut out));
        if let Ok(len) = buffered {
            assert_eq!(inflate_len(&noise[..], NO_LIMIT), Ok(len));
        }
    }
}

/// A `Stream`, a `Counter` and the length functions stop at their maximum
/// length, exactly.
#[test]
fn max_len() {
    let mut rng = Rng(8);
    let data: Vec<u8> = (0..70_000).map(|_| b"abcdefgh"[rng.below(8)]).collect();
    let len = data.len() as u64;
    let stream_to = |input: &[u8], max_len: u64| {
        let mut out = Vec::new();
        let mut window = vec![0; 32_768];
        let result = decompress(
            input,
            Stream::new(&mut window, max_len, |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            }),
        );
        (result, out)
    };

    for level in [0, 1, 9] {
        for input in [gzip(&data, level), zlib(&data, level)] {
            for max_len in [NO_LIMIT, len + 1, len] {
                assert_eq!(decompress_len(&input[..], max_len), Ok(len));
                assert_eq!(stream_to(&input, max_len), (Ok(len), data.clone()));
            }
            for max_len in [len - 1, 40_000, 32_768, 1, 0] {
                assert_eq!(decompress_len(&input[..], max_len), Err(Error::OutputFull));
                // Nothing past the limit reaches the callback.
                let (result, out) = stream_to(&input, max_len);
                assert_eq!(result, Err(Error::OutputFull));
                assert!(out.len() as u64 <= max_len);
                assert!(data.starts_with(&out));
            }
        }
    }

    // Empty streams fit in no space at all.
    assert_eq!(gunzip_len(&gzip(b"", 6)[..], 0), Ok(0));
    assert_eq!(stream_to(&gzip(b"", 6), 0), (Ok(0), vec![]));

    // The limit of a lent output covers everything it receives.
    let mut counter = Counter::new(10);
    assert_eq!(gunzip(&gzip(b"123456", 6)[..], &mut counter), Ok(6));
    assert_eq!(
        gunzip(&gzip(b"78901", 6)[..], &mut counter),
        Err(Error::OutputFull)
    );

    // A decompression bomb: 1 GiB of zeros. Stopped right away, and countable
    // for who insists.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    for _ in 0..1024 {
        encoder.write_all(&[0; 1 << 20]).unwrap();
    }
    let bomb = encoder.finish().unwrap();
    assert!(bomb.len() < 2 << 20);
    assert_eq!(gunzip_len(&bomb[..], 1 << 20), Err(Error::OutputFull));
    assert_eq!(stream_to(&bomb, 1 << 20).0, Err(Error::OutputFull));
    assert_eq!(gunzip_len(&bomb[..], NO_LIMIT), Ok(1 << 30));
}
