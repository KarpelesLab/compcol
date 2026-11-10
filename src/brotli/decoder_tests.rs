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
