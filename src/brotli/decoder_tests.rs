//! Decoder unit tests that need to look inside the decoder (work
//! counters, internal state) and so cannot live in `tests/brotli.rs`.
//! The streams are written by hand, bit by bit, per RFC 7932.

use alloc::vec;
use alloc::vec::Vec;

use super::Decoder;
use crate::traits::{RawDecoder, RawEncoder, RawProgress};

/// LSB-first bit writer for hand-built streams.
struct Bw {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bw {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }

    fn put(&mut self, v: u32, bits: u32) {
        self.acc |= (v as u64) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }

    /// Simple prefix code with one symbol (zero bits per use).
    fn simple1(&mut self, sym: u32, alpha_bits: u32) {
        self.put(1, 2); // simple
        self.put(0, 2); // NSYM - 1
        self.put(sym, alpha_bits);
    }

    /// NBLTYPES / NTREES value 256.
    fn n256(&mut self) {
        self.put(1, 1);
        self.put(7, 3);
        self.put(127, 7);
    }

    /// Complex prefix code giving every symbol length `l` (until the code
    /// space is full): `l` is the only code-length symbol, so the code
    /// lengths themselves take no bits.
    fn complex_all(&mut self, l: usize) {
        self.put(0, 2); // HSKIP = 0
        for &o in super::CODE_LENGTH_ORDER.iter() {
            if o == l {
                self.put(0b0111, 4); // code length 1
            } else {
                self.put(0, 2); // code length 0
            }
        }
    }

    /// Block-type group with 256 types: type and count codes of one
    /// symbol each, first block count 1.
    fn group256(&mut self) {
        self.n256();
        self.simple1(0, 9);
        self.simple1(0, 5);
        self.put(0, 2); // block count extra bits
    }

    /// `code`, a `len`-bit prefix code word, MSB first.
    fn code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.put((code >> i) & 1, 1);
        }
    }
}

/// A stream of one compressed meta-block (decoding to `A`) whose header
/// is about as heavy as headers get — 256 block types per category, two
/// 256-tree context maps with inverse move-to-front, 768 complex prefix
/// codes — followed by the empty last meta-block.
fn heavy_header_stream() -> Vec<u8> {
    let mut w = Bw::new();
    w.put(0, 1); // WBITS = 16
    w.put(0, 1); // ISLAST
    w.put(0, 2); // MNIBBLES = 4
    w.put(0, 16); // MLEN - 1
    w.put(0, 1); // ISUNCOMPRESSED
    w.group256();
    w.group256();
    w.group256();
    w.put(0, 2); // NPOSTFIX
    w.put(0, 4); // NDIRECT
    for _ in 0..256 {
        w.put(0, 2); // CMODE
    }
    for _ in 0..2 {
        // Context map: 256 trees, no RLE, every entry 255, IMTF.
        w.n256();
        w.put(0, 1);
        w.simple1(255, 8);
        w.put(1, 1);
    }
    for _ in 0..256 {
        w.complex_all(8); // literals
    }
    for _ in 0..256 {
        w.complex_all(9); // insert-and-copy
    }
    for _ in 0..256 {
        w.complex_all(6); // distances
    }
    w.code(136, 9); // insert 1, copy 2 (not reached)
    w.code(0x41, 8);
    w.put(3, 2); // ISLAST, ISLASTEMPTY
    w.finish()
}

/// A stream decoding to `ABABAB` through a two-tree literal context map
/// whose body takes several bytes (single zeros, a value, a zero run).
fn context_map_stream() -> Vec<u8> {
    let mut w = Bw::new();
    w.put(0, 1); // WBITS = 16
    w.put(0, 1); // ISLAST
    w.put(0, 2); // MNIBBLES = 4
    w.put(5, 16); // MLEN - 1
    w.put(0, 1); // ISUNCOMPRESSED
    w.put(0, 3); // NBLTYPES L/I/D = 1
    w.put(0, 2); // NPOSTFIX
    w.put(0, 4); // NDIRECT
    w.put(0, 2); // CMODE = LSB6
    w.put(1, 1); // NTREESL = 2
    w.put(0, 3);
    // Context map: RLEMAX = 5, so symbols 0 (zero), 1..=5 (zero runs),
    // 6 (tree 1). Simple code over {0: 1 bit, 5: 2 bits, 6: 2 bits}.
    w.put(1, 1);
    w.put(4, 4);
    w.put(1, 2); // simple
    w.put(2, 2); // NSYM = 3
    w.put(0, 3);
    w.put(5, 3);
    w.put(6, 3);
    // Contexts 0 and 2 (start, after `B`) use tree 0, context 1 (after
    // `A`) tree 1: entries 0 1 0, 29 more zeros, then a run of 32.
    w.code(0b0, 1);
    w.code(0b11, 2);
    for _ in 0..30 {
        w.code(0b0, 1);
    }
    w.code(0b10, 2);
    w.put(0, 5); // run = 32 + 0
    w.put(0, 1); // no IMTF
    w.put(0, 1); // NTREESD = 1
    w.simple1(0x41, 8);
    w.simple1(0x42, 8);
    w.simple1(176, 10); // insert 6 (+1 extra bit), copy 2 (not reached)
    w.simple1(0, 6);
    w.put(0, 1); // insert extra bit
    w.put(3, 2); // ISLAST, ISLASTEMPTY
    w.finish()
}

/// A stream expanding to `1 + blocks * mlen` bytes of `A`: a one-literal
/// meta-block, then `blocks` meta-blocks made only of zero-bit "copy 8
/// from distance 1" commands. `wbits` is 16 or 24; `mlen` takes 6 nibbles.
fn splat_stream(wbits: u32, blocks: usize, mlen: u32) -> Vec<u8> {
    assert!(mlen > 1 << 20 && mlen <= 1 << 24);
    let mut w = Bw::new();
    match wbits {
        16 => w.put(0, 1),
        24 => {
            w.put(1, 1);
            w.put(7, 3);
        }
        _ => unreachable!(),
    }
    // Meta-block of MLEN = 1: the literal `A`.
    w.put(0, 1); // ISLAST
    w.put(0, 2); // MNIBBLES = 4
    w.put(0, 16); // MLEN - 1
    w.put(0, 1); // ISUNCOMPRESSED
    w.put(0, 3); // NBLTYPES L/I/D = 1
    w.put(0, 2); // NPOSTFIX
    w.put(0, 4); // NDIRECT
    w.put(0, 2); // CMODE
    w.put(0, 1); // NTREESL = 1
    w.put(0, 1); // NTREESD = 1
    w.simple1(0x41, 8);
    w.simple1(136, 10); // insert 1, copy 2 (not reached)
    w.simple1(0, 6);
    for _ in 0..blocks {
        w.put(0, 1); // ISLAST
        w.put(2, 2); // MNIBBLES = 6
        w.put(mlen - 1, 24);
        w.put(0, 1); // ISUNCOMPRESSED
        w.put(0, 3); // NBLTYPES L/I/D = 1
        w.put(0, 2); // NPOSTFIX
        w.put(1, 4); // NDIRECT = 1
        w.put(0, 2); // CMODE
        w.put(0, 1); // NTREESL = 1
        w.put(0, 1); // NTREESD = 1
        w.simple1(0x41, 8);
        w.simple1(134, 10); // insert 0, copy 8, explicit distance
        w.simple1(16, 7); // direct distance 1
    }
    w.put(3, 2); // ISLAST, ISLASTEMPTY
    w.finish()
}

/// Decode `data` handing it over `in_chunk` bytes at a time and reading
/// through an `out_chunk`-byte buffer, then finish.
fn decode_with(dec: &mut Decoder, data: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    for chunk in data.chunks(in_chunk) {
        let mut rest = chunk;
        loop {
            let RawProgress {
                consumed,
                written,
                done,
            } = dec.raw_decode(rest, &mut buf).unwrap();
            out.extend_from_slice(&buf[..written]);
            rest = &rest[consumed..];
            if done || (rest.is_empty() && written < buf.len()) {
                break;
            }
        }
    }
    loop {
        let p = dec.raw_finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        assert!(p.written > 0, "finish stalled");
    }
    out
}

fn encode(input: &[u8], quality: u8) -> Vec<u8> {
    let mut enc = super::Encoder::with_config(super::EncoderConfig { quality });
    let mut encoded = vec![0u8; input.len() + 1024];
    let mut len = enc.raw_encode(input, &mut encoded).unwrap().written;
    loop {
        let p = enc.raw_finish(&mut encoded[len..]).unwrap();
        len += p.written;
        if p.done {
            break;
        }
    }
    encoded.truncate(len);
    encoded
}

fn text(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| b"etaoin shrdlu"[(i.wrapping_mul(2_654_435_761) >> 20) as usize % 13])
        .collect()
}

#[test]
fn small_reads_do_not_shift_the_history_every_call() {
    // 2 MiB + 17 bytes out of a 64 KiB window, read 256 bytes at a time.
    // Dropping exactly the bytes just read after every call shifts the
    // whole window (and whatever is still queued) each time: gigabytes
    // of memmove here. With hysteresis each byte is moved O(1) times.
    let mlen = (1u32 << 20) + 8;
    let data = splat_stream(16, 2, mlen);
    let total = 1 + 2 * mlen as usize;
    let mut dec = Decoder::new();
    let out = decode_with(&mut dec, &data, usize::MAX, 256);
    assert_eq!(out.len(), total);
    assert!(out.iter().all(|&b| b == 0x41));
    assert!(
        dec.out_moved <= 2 * total as u64,
        "compact_out moved {} bytes for {} bytes of output",
        dec.out_moved,
        total
    );
    // The history kept stays bounded: about twice the window.
    assert!(dec.out.len() <= 2 * (1 << 16) + 256, "{}", dec.out.len());
}

#[test]
fn back_references_survive_history_compaction() {
    // Distances up to the whole window must stay reachable whatever the
    // read size, i.e. wherever compaction happens to fall.
    let input = text(400_000);
    let encoded = encode(&input, 5);
    for out_chunk in [1 << 20, 4096, 613, 61] {
        let mut dec = Decoder::new();
        let out = decode_with(&mut dec, &encoded, 1000, out_chunk);
        assert!(out == input, "out_chunk {out_chunk}");
    }
}

#[test]
fn header_arriving_in_pieces_is_not_reparsed() {
    // The tables of a compressed meta-block can run to kilobytes (here
    // 3.9 KB: 776 prefix codes and two context maps). When they arrive
    // over many calls, each call must only pay for what is new, not
    // parse everything again from the meta-block's start.
    let data = heavy_header_stream();
    let mut dec = Decoder::new();
    assert_eq!(decode_with(&mut dec, &data, usize::MAX, 4096), b"A");
    let codes = dec.prefix_codes_read;
    assert_eq!(codes, 3 * 2 + 2 + 3 * 256);

    for in_chunk in [1usize, 7, 256] {
        let mut dec = Decoder::new();
        assert_eq!(decode_with(&mut dec, &data, in_chunk, 4096), b"A");
        // At most one code is cut short (and read again) per call.
        let calls = data.len().div_ceil(in_chunk) as u64 + 1;
        assert!(
            dec.prefix_codes_read <= codes + calls,
            "in_chunk {in_chunk}: {} prefix codes read for a header of {codes}",
            dec.prefix_codes_read
        );
    }
}

#[test]
fn header_resumes_at_any_split() {
    // Wherever the input is cut — inside a prefix code, a context map's
    // body, between any two header fields — the result is the same, and
    // a stream that stops there is reported as truncated.
    for (data, want) in [
        (context_map_stream(), &b"ABABAB"[..]),
        (encode(&text(3000), 11), &text(3000)[..]),
        (encode(&text(3000), 5), &text(3000)[..]),
    ] {
        let mut dec = Decoder::new();
        assert_eq!(decode_with(&mut dec, &data, usize::MAX, 4096), want);
        for in_chunk in [1, 2, 3, 5] {
            let mut dec = Decoder::new();
            assert_eq!(decode_with(&mut dec, &data, in_chunk, 4096), want);
        }
        let mut buf = vec![0u8; want.len() + 1];
        for cut in 0..data.len() {
            let mut dec = Decoder::new();
            let a = dec.raw_decode(&data[..cut], &mut buf).unwrap();
            assert_eq!(a.consumed, cut);
            let b = dec.raw_decode(&data[cut..], &mut buf[a.written..]).unwrap();
            assert!(b.done, "cut {cut}");
            assert_eq!(&buf[..a.written + b.written], want, "cut {cut}");

            let mut dec = Decoder::new();
            let a = dec.raw_decode(&data[..cut], &mut buf).unwrap();
            assert!(!a.done);
            assert_eq!(
                dec.raw_finish(&mut buf[a.written..]),
                Err(crate::error::Error::UnexpectedEnd),
                "cut {cut}"
            );
        }
    }
}
