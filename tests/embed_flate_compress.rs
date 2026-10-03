//! The compressor, checked against this crate's decompressor and flate2's.

#![cfg(all(feature = "embed", feature = "gzip", feature = "zlib"))]

use std::io::Read;

use compcol::embed::flate::*;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};

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

/// Data made of literals and of copies of every length and distance, the far
/// side of what deflate can express included.
fn stitched(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::new();
    while data.len() < len {
        if data.is_empty() || rng.below(3) == 0 {
            let alphabet = [4, 64, 256][rng.below(3)];
            data.extend((0..1 + rng.below(40)).map(|_| rng.below(alphabet) as u8));
        } else {
            let dist = 1 + rng.below(data.len().min(33_000));
            let from = data.len() - dist;
            for i in 0..3 + rng.below(300) {
                data.push(data[from + i]);
            }
        }
    }
    data
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng(1);
    let random: Vec<u8> = (0..70_000).map(|_| rng.next() as u8).collect();
    let text: Vec<u8> = (0..20_000)
        .flat_map(|_| {
            ["alpha", "beta", "gamma", "delta", "epsilon", " ", "\n"][rng.below(7)].bytes()
        })
        .collect();
    // Matches exactly at, and just past, the far end of the window.
    let mut distant = random[..32_768].to_vec();
    distant.extend_from_within(..);
    distant.push(0);
    distant.extend_from_within(32_768..);
    vec![
        ("empty", vec![]),
        ("one byte", vec![42]),
        ("two bytes", vec![42, 42]),
        ("three bytes", vec![42, 42, 42]),
        ("short", b"hello hello hello hello".to_vec()),
        ("every byte", (0..=255).collect()),
        ("zeros", vec![0; 200_000]),
        ("stitched", stitched(&mut rng, 150_000)),
        ("random", random),
        ("text", text),
        ("distant", distant),
    ]
}

fn compress_with(
    f: impl Fn(&[u8], &mut [u16], Buffer) -> Result<u64, Error>,
    data: &[u8],
    table: &mut [u16],
) -> Vec<u8> {
    // Fixed codes never take more than nine bits for a byte.
    let mut out = vec![0; data.len() + data.len() / 8 + 64];
    let len = f(data, table, Buffer::new(&mut out)).unwrap() as usize;
    out.truncate(len);
    out
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    out
}

fn unpack(f: impl Fn(&[u8], Buffer) -> Result<u64, Error>, packed: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    assert_eq!(f(packed, Buffer::new(&mut out)), Ok(len as u64));
    out
}

#[test]
fn round_trips() {
    let mut rng = Rng(2);
    for (name, data) in samples() {
        for table_len in [0, 1, 2, 3, 100, 4096, 65_536, 100_000] {
            let what = format!("{name}, table of {table_len}");
            // The table need not be cleared.
            let mut table: Vec<u16> = (0..table_len).map(|_| rng.next() as u16).collect();

            let gz = compress_with(|d, t, o| gzip(d, t, o), &data, &mut table);
            assert_eq!(unpack(|i, o| gunzip(i, o), &gz, data.len()), data, "{what}");
            assert_eq!(read_all(GzDecoder::new(&gz[..])), data, "{what}");
            assert_eq!(gzip_size_hint(&gz), Some(data.len() as u32), "{what}");

            let zl = compress_with(|d, t, o| zlib(d, t, o), &data, &mut table);
            assert_eq!(unpack(|i, o| unzlib(i, o), &zl, data.len()), data, "{what}");
            assert_eq!(read_all(ZlibDecoder::new(&zl[..])), data, "{what}");

            let raw = compress_with(|d, t, o| deflate(d, t, o), &data, &mut table);
            assert_eq!(
                unpack(|i, o| inflate(i, o), &raw, data.len()),
                data,
                "{what}"
            );
            assert_eq!(read_all(DeflateDecoder::new(&raw[..])), data, "{what}");

            // The containers only add their header and trailer.
            assert_eq!(gz.len(), raw.len() + 18, "{what}");
            assert_eq!(zl.len(), raw.len() + 6, "{what}");
        }
    }
}

#[test]
fn it_compresses() {
    let samples = samples();
    let ratio = |name: &str, table_len: usize| {
        let data = &samples.iter().find(|(n, _)| *n == name).unwrap().1;
        let mut table = vec![0; table_len];
        let len = compress_with(|d, t, o| deflate(d, t, o), data, &mut table).len();
        len as f64 / data.len() as f64
    };
    // Twenty bits for each match of 258 bytes.
    assert!(ratio("zeros", 1) < 0.01);
    assert!(ratio("text", 4096) < 0.45);
    // A third of it is a copy from 32768 bytes back, the rest is out of reach.
    assert!(ratio("distant", 65_536) < 0.72);
    assert!(ratio("distant", 65_536) > 0.69);
    assert!(ratio("stitched", 4096) < 0.60);
    // A larger table finds more; none only gets the Huffman coding, and what
    // cannot be compressed grows by an eighth at worst.
    assert!(ratio("text", 4096) < ratio("text", 16));
    assert!(ratio("text", 16) < ratio("text", 0));
    assert!(ratio("text", 0) < 1.001);
    assert!(ratio("random", 4096) < 1.13);
}

/// Chunks of any size, to every kind of output, give streams of the same
/// length that decompress to the same data.
#[test]
fn chunks_and_outputs() {
    let mut rng = Rng(3);
    let data = stitched(&mut rng, 100_000);
    let mut table = vec![0; 1024];

    for max_chunk in [1, 7, 1000, 40_000, 1 << 20] {
        let mut chunks = Vec::new();
        let mut rest = &data[..];
        while !rest.is_empty() {
            let (chunk, tail) = rest.split_at((1 + rng.below(max_chunk)).min(rest.len()));
            chunks.push(chunk);
            rest = tail;
        }

        // A chunk of one byte takes about twenty bits.
        let mut buffered = vec![0; 4 * data.len()];
        let mut compressor = Compressor::<_, Gzip>::new(Buffer::new(&mut buffered), &mut table);
        for chunk in &chunks {
            compressor.write(chunk).unwrap();
            compressor.write(&[]).unwrap();
        }
        let len = compressor.finish().unwrap();
        buffered.truncate(len as usize);
        assert_eq!(unpack(|i, o| gunzip(i, o), &buffered, data.len()), data);
        assert_eq!(read_all(GzDecoder::new(&buffered[..])), data);

        let mut streamed = Vec::new();
        let mut scratch = [0; 100];
        let output = Stream::new(&mut scratch, NO_LIMIT, |bytes| {
            streamed.extend_from_slice(bytes);
            Ok(())
        });
        let mut compressor = Compressor::<_, Gzip>::new(output, &mut table);
        for chunk in &chunks {
            compressor.write(chunk).unwrap();
        }
        assert_eq!(compressor.finish(), Ok(len));
        // The table differs from one run to the next, not the result's length.
        assert_eq!(streamed.len() as u64, len);
        assert_eq!(unpack(|i, o| gunzip(i, o), &streamed, data.len()), data);

        let mut compressor = Compressor::<_, Gzip>::new(Counter::new(NO_LIMIT), &mut table);
        for chunk in &chunks {
            compressor.write(chunk).unwrap();
        }
        assert_eq!(compressor.finish(), Ok(len));
    }
}

#[test]
fn output_is_appended_and_bounded() {
    let mut table = [0; 64];
    let mut out = [0; 200];
    let mut buffer = Buffer::new(&mut out);
    let first = gzip(b"first member, ", &mut table, &mut buffer).unwrap();
    let second = gzip(b"second member", &mut table, &mut buffer).unwrap();
    assert_eq!(buffer.written(), first + second);
    assert_eq!(
        read_all(flate2::read::MultiGzDecoder::new(buffer.filled())),
        b"first member, second member"
    );
    assert_eq!(gunzip_len(buffer.filled(), NO_LIMIT), Ok(27));

    // One compressor, several streams.
    let mut compressor = Compressor::<_, Zlib>::new(Buffer::new(&mut out), &mut table);
    let mut lens = [0; 3];
    for (len, data) in lens.iter_mut().zip([&b"one"[..], b"", b"three"]) {
        compressor.write(data).unwrap();
        *len = compressor.finish().unwrap() as usize;
    }
    let (one, rest) = out.split_at(lens[0]);
    let (two, three) = rest.split_at(lens[1]);
    assert_eq!(read_all(ZlibDecoder::new(one)), b"one");
    assert_eq!(read_all(ZlibDecoder::new(two)), b"");
    assert_eq!(read_all(ZlibDecoder::new(&three[..lens[2]])), b"three");

    let data = [7; 1000];
    let len = gzip(&data, &mut table, Counter::new(NO_LIMIT)).unwrap();
    assert_eq!(gzip(&data, &mut table, Counter::new(len)), Ok(len));
    assert_eq!(
        gzip(&data, &mut table, Counter::new(len - 1)),
        Err(Error::OutputFull)
    );
    let mut small = vec![0; len as usize - 1];
    assert_eq!(
        gzip(&data, &mut table, Buffer::new(&mut small)),
        Err(Error::OutputFull)
    );
    assert_eq!(
        gzip(&data, &mut table, Buffer::new(&mut [])),
        Err(Error::OutputFull)
    );
    let mut scratch = [0; 8];
    let failing = Stream::new(&mut scratch, NO_LIMIT, |_| Err(Error::Io));
    assert_eq!(gzip(&data, &mut table, failing), Err(Error::Io));
}
