//! zlib-`inflate`-style controls of the deflate-family decoders: exact
//! consumed counts at the end of a stream, the "need dictionary" signal and
//! stopping at block boundaries (`Z_BLOCK`).
//!
//! Fixtures come from CPython's zlib (zlib 1.2.12); block boundaries are
//! checked against a small independent bit-level parser below. One test
//! cross-checks many fresh streams from the system `python3` and skips
//! when it is missing.

// The `embed` build has none of these controls.
#![cfg(all(
    feature = "deflate",
    feature = "zlib",
    feature = "gzip",
    not(feature = "embed")
))]

use compcol::{Decoder, Encoder, Error, Status, deflate, gzip, zlib};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `text * 3 + 40 random bytes + text[:50] + "tail"`, compressed by
/// `compressobj(6, DEFLATED, wbits)` with `Z_BLOCK`, `Z_SYNC_FLUSH`,
/// `Z_FULL_FLUSH` and `Z_PARTIAL_FLUSH` flushes between the parts.
const PLAIN: &str = "74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b2074686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b2074686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b20a54dca182530bb1d6d132cded6237b2ed91e3f721fcb1971174494d6493c9d5c3460be31201e69fe74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b2074686520717461696c";
const RAW: &str = "2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379b4510cd052df5312aa06bb65738575ee5d53aed6bb29675f247f5ab250dc65ca354f9bb9312609fb0c15e432ff01000000ffff000000ffff2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379850001569298990300";
const ZLIB: &str = "789c2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379b4510cd052df5312aa06bb65738575ee5d53aed6bb29675f247f5ab250dc65ca354f9bb9312609fb0c15e432ff01000000ffff000000ffff2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379850001569298990300d4745481";
const GZIP: &str = "1f8b08000000000000132ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379b4510cd052df5312aa06bb65738575ee5d53aed6bb29675f247f5ab250dc65ca354f9bb9312609fb0c15e432ff01000000ffff000000ffff2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379850001569298990300e4b1c59fe5000000";
/// `text * 3 + "abcabcabc"` with `Z_FIXED`, a `Z_BLOCK` flush in between.
const FIXED_PLAIN: &str = "74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b2074686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b2074686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f673b20616263616263616263";
const FIXED: &str = "2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a75b8379b4510c58625232040100";
/// zlib stream with a preset dictionary (`zdict=DICT`).
const ZDICT: &str = "78bb613c0ffa4366a3ab413302005d660ffa";
const DICT: &[u8] = b"the quick brown fox jumps over the lazy dog";
const DICT_PLAIN: &[u8] = b"the lazy dog jumps over the quick brown fox";
const DICT_ID: u32 = 0x613c0ffa;

const GARBAGE: &[u8] = b"\x00\x01garbage after the stream\xff";

// ─── driving helpers ─────────────────────────────────────────────────────

/// Decode `input` handing over at most `step` bytes per call (0 = all at
/// once) into `out_len`-byte buffers, until `StreamEnd`. Returns the output
/// and the total reported as consumed.
fn drive<D: Decoder>(dec: &mut D, input: &[u8], step: usize, out_len: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_len];
    let mut pos = 0;
    for _ in 0..10_000_000 {
        let end = if step == 0 {
            input.len()
        } else {
            (pos + step).min(input.len())
        };
        let (p, status) = dec.decode(&input[pos..end], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        assert!(pos <= end);
        match status {
            Status::StreamEnd => return (out, pos),
            Status::InputEmpty if end == input.len() => loop {
                let (p, status) = dec.finish(&mut buf).unwrap();
                out.extend_from_slice(&buf[..p.written]);
                if status == Status::StreamEnd {
                    return (out, pos);
                }
                assert!(p.written > 0, "finish stalled");
            },
            _ => {}
        }
    }
    panic!("decoder made no progress");
}

const STEPS: [usize; 4] = [0, 1, 2, 7];
const OUT_LENS: [usize; 3] = [1, 5, 4096];

fn check_exact<D: Decoder>(mut make: impl FnMut() -> D, stream: &[u8], tail: &[u8], plain: &[u8]) {
    let mut input = stream.to_vec();
    input.extend_from_slice(tail);
    for step in STEPS {
        for out_len in OUT_LENS {
            let mut dec = make();
            let (out, consumed) = drive(&mut dec, &input, step, out_len);
            assert_eq!(out, plain, "step {step} out {out_len}");
            assert_eq!(consumed, stream.len(), "step {step} out {out_len}");
        }
    }
}

// ─── independent block parser ────────────────────────────────────────────

/// A block end found by [`parse_blocks`]: bit offset just past the block,
/// decoded bytes so far, and whether it was the final block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockEnd {
    bit: usize,
    out: usize,
    last: bool,
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> u32 {
        let b = (self.data[self.pos / 8] >> (self.pos % 8)) & 1;
        self.pos += 1;
        b as u32
    }
    fn bits(&mut self, n: u32) -> u32 {
        (0..n).fold(0, |v, i| v | (self.bit() << i))
    }
}

/// Canonical Huffman code as counts per length plus symbols in code order
/// (the layout of zlib's `puff.c`).
struct Huff {
    count: [u16; 16],
    symbol: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Self {
        let mut count = [0u16; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut symbol = Vec::new();
        for len in 1..16 {
            for (s, &l) in lengths.iter().enumerate() {
                if l as usize == len {
                    symbol.push(s as u16);
                }
            }
        }
        Self { count, symbol }
    }

    fn decode(&self, b: &mut Bits) -> u16 {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.bit() as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return self.symbol[(index + code - first) as usize];
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        panic!("bad code");
    }
}

const LBASE: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DEXT: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Walk the raw deflate data starting at bit `start` and list every block
/// end. Only lengths are tracked, not the decoded bytes.
fn parse_blocks(data: &[u8], start_bit: usize) -> Vec<BlockEnd> {
    let mut b = Bits {
        data,
        pos: start_bit,
    };
    let mut out = 0usize;
    let mut ends = Vec::new();
    loop {
        let last = b.bit() == 1;
        match b.bits(2) {
            0 => {
                b.pos = b.pos.div_ceil(8) * 8;
                let len = b.bits(16) as usize;
                b.bits(16);
                b.pos += 8 * len;
                out += len;
            }
            t @ (1 | 2) => {
                let (lit, dist) = if t == 1 {
                    let mut l = [8u8; 288];
                    l[144..256].fill(9);
                    l[256..280].fill(7);
                    (Huff::new(&l), Huff::new(&[5u8; 30]))
                } else {
                    let nlen = b.bits(5) as usize + 257;
                    let ndist = b.bits(5) as usize + 1;
                    let ncode = b.bits(4) as usize + 4;
                    const ORDER: [usize; 19] = [
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                    ];
                    let mut cl = [0u8; 19];
                    for &o in &ORDER[..ncode] {
                        cl[o] = b.bits(3) as u8;
                    }
                    let clh = Huff::new(&cl);
                    let mut lens = Vec::new();
                    while lens.len() < nlen + ndist {
                        match clh.decode(&mut b) {
                            s @ 0..=15 => lens.push(s as u8),
                            16 => {
                                let p = *lens.last().unwrap();
                                for _ in 0..3 + b.bits(2) {
                                    lens.push(p);
                                }
                            }
                            17 => lens.extend(std::iter::repeat_n(0, 3 + b.bits(3) as usize)),
                            _ => lens.extend(std::iter::repeat_n(0, 11 + b.bits(7) as usize)),
                        }
                    }
                    (Huff::new(&lens[..nlen]), Huff::new(&lens[nlen..]))
                };
                loop {
                    let s = lit.decode(&mut b) as usize;
                    if s < 256 {
                        out += 1;
                    } else if s == 256 {
                        break;
                    } else {
                        let i = s - 257;
                        out += LBASE[i] + b.bits(LEXT[i]) as usize;
                        let d = dist.decode(&mut b) as usize;
                        b.bits(DEXT[d]);
                    }
                }
            }
            _ => panic!("reserved block type"),
        }
        ends.push(BlockEnd {
            bit: b.pos,
            out,
            last,
        });
        if last {
            return ends;
        }
    }
}

/// A `decode_block` method.
type DecodeBlock<D> = fn(&mut D, &[u8], &mut [u8]) -> Result<(compcol::Progress, Status), Error>;

/// Decode with `decode_block`, recording every stop as (bit offset in
/// `input`, bytes decoded so far). Returns the stops, the output and the
/// consumed total. `decode_block`, `at_block_boundary` and `unused_bits`
/// are passed in so the same driver serves the three decoders.
fn drive_blocks<D: Decoder>(
    dec: &mut D,
    decode_block: DecodeBlock<D>,
    boundary: fn(&D) -> (bool, u32),
    input: &[u8],
    step: usize,
    out_len: usize,
) -> (Vec<(usize, usize)>, Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut stops: Vec<(usize, usize)> = Vec::new();
    let mut buf = vec![0u8; out_len];
    let mut pos = 0;
    for _ in 0..10_000_000 {
        let end = if step == 0 {
            input.len()
        } else {
            (pos + step).min(input.len())
        };
        let (p, status) = decode_block(dec, &input[pos..end], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if status == Status::StreamEnd {
            return (stops, out, pos);
        }
        let (at, unused) = boundary(dec);
        if at {
            assert!(unused < 8, "unused bits {unused} at a stop");
            let here = (pos * 8 - unused as usize, out.len());
            if stops.last() != Some(&here) {
                stops.push(here);
            }
        }
        assert!(
            !(status == Status::InputEmpty && end == input.len()),
            "stream did not end"
        );
    }
    panic!("decoder made no progress");
}

fn deflate_block(
    d: &mut deflate::Decoder,
    i: &[u8],
    o: &mut [u8],
) -> Result<(compcol::Progress, Status), Error> {
    d.decode_block(i, o)
}
fn deflate_boundary(d: &deflate::Decoder) -> (bool, u32) {
    (d.at_block_boundary(), d.unused_bits())
}
fn zlib_block(
    d: &mut zlib::Decoder,
    i: &[u8],
    o: &mut [u8],
) -> Result<(compcol::Progress, Status), Error> {
    d.decode_block(i, o)
}
fn zlib_boundary(d: &zlib::Decoder) -> (bool, u32) {
    (d.at_block_boundary(), d.unused_bits())
}
fn gzip_block(
    d: &mut gzip::Decoder,
    i: &[u8],
    o: &mut [u8],
) -> Result<(compcol::Progress, Status), Error> {
    d.decode_block(i, o)
}
fn gzip_boundary(d: &gzip::Decoder) -> (bool, u32) {
    (d.at_block_boundary(), d.unused_bits())
}

/// The stops `decode_block` must make: right after a container header (bit
/// `header_bits`, nothing decoded), then after every block but the last.
fn expected_stops(stream: &[u8], header_bits: usize, container: bool) -> Vec<(usize, usize)> {
    let ends = parse_blocks(stream, header_bits);
    let mut want = Vec::new();
    if container {
        want.push((header_bits, 0));
    }
    want.extend(ends.iter().filter(|e| !e.last).map(|e| (e.bit, e.out)));
    want
}

// ─── exact consumption ───────────────────────────────────────────────────

#[test]
fn raw_deflate_consumption_is_exact() {
    check_exact(deflate::Decoder::new, &hex(RAW), GARBAGE, &hex(PLAIN));
    check_exact(
        deflate::Decoder::new,
        &hex(FIXED),
        GARBAGE,
        &hex(FIXED_PLAIN),
    );
    // Without anything after it, too.
    check_exact(deflate::Decoder::new, &hex(RAW), &[], &hex(PLAIN));
}

#[test]
fn raw_deflate_consumption_is_exact_for_own_encoder() {
    let mut plain = Vec::new();
    for i in 0..20_000u32 {
        plain.push(if i % 1000 < 300 {
            (i * 7) as u8
        } else {
            b"abcd"[(i % 4) as usize]
        });
    }
    for level in [1u8, 6, 9] {
        let mut enc =
            deflate::Encoder::with_config(deflate::EncoderConfig::new().with_level(level));
        let mut stream = vec![0u8; plain.len() * 2 + 1024];
        let (p, _) = enc.encode(&plain, &mut stream).unwrap();
        let mut len = p.written;
        loop {
            let (p, status) = enc.finish(&mut stream[len..]).unwrap();
            len += p.written;
            if status == Status::StreamEnd {
                break;
            }
        }
        stream.truncate(len);
        let mut input = stream.clone();
        input.extend_from_slice(GARBAGE);
        for (step, out_len) in [(0, 4096), (1, 4096), (0, 1), (3, 7)] {
            let mut dec = deflate::Decoder::new();
            let (out, consumed) = drive(&mut dec, &input, step, out_len);
            assert_eq!(out, plain);
            assert_eq!(consumed, stream.len(), "level {level} step {step}");
        }
    }
}

#[test]
fn zlib_consumption_is_exact() {
    check_exact(zlib::Decoder::new, &hex(ZLIB), GARBAGE, &hex(PLAIN));
    check_exact(zlib::Decoder::new, &hex(ZLIB), &[], &hex(PLAIN));
}

#[test]
fn gzip_consumption_is_exact() {
    let g = hex(GZIP);
    let plain = hex(PLAIN);
    // One member, then bytes that are not another member.
    check_exact(gzip::Decoder::new, &g, GARBAGE, &plain);
    // Single-member mode stops after the trailer, whatever follows.
    let single = || gzip::Decoder::new().with_multi_member(false);
    check_exact(single, &g, &g, &plain);
    check_exact(single, &g, GARBAGE, &plain);
    // Two members, with and without garbage after them.
    let two = [g.clone(), g.clone()].concat();
    let plain2 = [plain.clone(), plain.clone()].concat();
    check_exact(gzip::Decoder::new, &two, GARBAGE, &plain2);
    check_exact(gzip::Decoder::new, &two, &[], &plain2);
}

/// After the end, `decode` reports nothing more consumed.
#[test]
fn nothing_consumed_after_the_end() {
    let mut input = hex(RAW);
    let n = input.len();
    input.extend_from_slice(GARBAGE);
    let mut dec = deflate::Decoder::new();
    let mut buf = vec![0u8; 4096];
    let (p, status) = dec.decode(&input, &mut buf).unwrap();
    assert_eq!((p.consumed, status), (n, Status::StreamEnd));
    let (p, status) = dec.decode(&input[n..], &mut buf).unwrap();
    assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));
    assert!(dec.unused_bits() < 8);
    assert!(dec.in_final_block());
}

// ─── need dictionary ─────────────────────────────────────────────────────

#[test]
fn need_dictionary_then_set_dictionary() {
    let mut input = hex(ZDICT);
    let n = input.len();
    input.extend_from_slice(GARBAGE);
    let mut dec = zlib::Decoder::new();
    let mut buf = vec![0u8; 4096];
    assert_eq!(dec.dictionary_id(), None);
    // The call that reads DICTID reports those bytes as consumed...
    let (p, _) = dec.decode(&input, &mut buf).unwrap();
    assert_eq!((p.consumed, p.written), (6, 0));
    assert!(dec.needs_dictionary());
    assert_eq!(dec.dictionary_id(), Some(DICT_ID));
    // ...and the next ones ask for the dictionary without consuming.
    assert_eq!(
        dec.decode(&input[6..], &mut buf),
        Err(Error::NeedDictionary)
    );
    assert_eq!(dec.finish(&mut buf), Err(Error::NeedDictionary));
    // A wrong dictionary is refused and the decoder keeps waiting.
    assert_eq!(dec.set_dictionary(b"nope"), Err(Error::ChecksumMismatch));
    assert!(dec.needs_dictionary());
    dec.set_dictionary(DICT).unwrap();
    assert!(!dec.needs_dictionary());
    assert_eq!(dec.dictionary_id(), Some(DICT_ID));
    assert_eq!(dec.set_dictionary(DICT), Err(Error::Unsupported));
    let (out, consumed) = drive(&mut dec, &input[6..], 0, 4096);
    assert_eq!(out, DICT_PLAIN);
    assert_eq!(6 + consumed, n);

    // `reset` forgets the dictionary: the stream asks again.
    dec.reset();
    assert_eq!(dec.dictionary_id(), None);
    let (p, _) = dec.decode(&input, &mut buf).unwrap();
    assert_eq!(p.consumed, 6);
    assert!(dec.needs_dictionary());
}

#[test]
fn need_dictionary_byte_at_a_time() {
    let mut input = hex(ZDICT);
    let n = input.len();
    input.extend_from_slice(GARBAGE);
    for out_len in [1, 4096] {
        let mut dec = zlib::Decoder::new();
        let mut buf = vec![0u8; out_len];
        let mut out = Vec::new();
        let mut pos = 0;
        let mut asked = 0;
        loop {
            let end = (pos + 1).min(input.len());
            match dec.decode(&input[pos..end], &mut buf) {
                Err(Error::NeedDictionary) => {
                    asked += 1;
                    assert_eq!(pos, 6);
                    assert_eq!(dec.dictionary_id(), Some(DICT_ID));
                    dec.set_dictionary(DICT).unwrap();
                }
                Ok((p, status)) => {
                    out.extend_from_slice(&buf[..p.written]);
                    pos += p.consumed;
                    if status == Status::StreamEnd {
                        break;
                    }
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(asked, 1);
        assert_eq!(out, DICT_PLAIN);
        assert_eq!(pos, n);
    }
}

#[test]
fn configured_dictionary_needs_no_signal() {
    let mut dec = zlib::Decoder::with_config(zlib::DecoderConfig {
        dictionary: DICT.to_vec(),
    });
    let (out, consumed) = drive(&mut dec, &hex(ZDICT), 1, 4096);
    assert_eq!(out, DICT_PLAIN);
    assert_eq!(consumed, hex(ZDICT).len());
    assert_eq!(dec.dictionary_id(), Some(DICT_ID));
    assert!(!dec.needs_dictionary());
}

#[test]
fn set_dictionary_without_fdict_is_refused() {
    let mut dec = zlib::Decoder::new();
    assert_eq!(dec.set_dictionary(DICT), Err(Error::Unsupported));
    let (out, _) = drive(&mut dec, &hex(ZLIB), 0, 4096);
    assert_eq!(out, hex(PLAIN));
    assert_eq!(dec.dictionary_id(), None);
    assert_eq!(dec.set_dictionary(DICT), Err(Error::Unsupported));
}

// ─── block boundaries ────────────────────────────────────────────────────

fn check_blocks_raw(stream: &[u8], plain: &[u8]) {
    let want = expected_stops(stream, 0, false);
    let mut input = stream.to_vec();
    input.extend_from_slice(GARBAGE);
    for step in STEPS {
        for out_len in OUT_LENS {
            let mut dec = deflate::Decoder::new();
            let (stops, out, consumed) = drive_blocks(
                &mut dec,
                deflate_block,
                deflate_boundary,
                &input,
                step,
                out_len,
            );
            assert_eq!(stops, want, "step {step} out {out_len}");
            assert_eq!(out, plain);
            assert_eq!(consumed, stream.len());
            assert!(dec.in_final_block());
        }
    }
}

#[test]
fn raw_deflate_stops_at_each_block() {
    let raw = hex(RAW);
    // The fixture has several blocks of each kind, including the empty
    // stored blocks of the sync and full flushes.
    let ends = parse_blocks(&raw, 0);
    assert!(ends.len() >= 5, "{ends:?}");
    check_blocks_raw(&raw, &hex(PLAIN));
    check_blocks_raw(&hex(FIXED), &hex(FIXED_PLAIN));
}

#[test]
fn zlib_and_gzip_stop_after_the_header_and_each_block() {
    let plain = hex(PLAIN);
    let z = hex(ZLIB);
    let g = hex(GZIP);
    let zwant = expected_stops(&z, 16, true);
    let gwant = expected_stops(&g, 80, true);
    for step in STEPS {
        for out_len in OUT_LENS {
            let mut dec = zlib::Decoder::new();
            let (stops, out, consumed) =
                drive_blocks(&mut dec, zlib_block, zlib_boundary, &z, step, out_len);
            assert_eq!(stops, zwant, "zlib step {step} out {out_len}");
            assert_eq!((out.as_slice(), consumed), (plain.as_slice(), z.len()));

            let mut dec = gzip::Decoder::new().with_multi_member(false);
            let (stops, out, consumed) =
                drive_blocks(&mut dec, gzip_block, gzip_boundary, &g, step, out_len);
            assert_eq!(stops, gwant, "gzip step {step} out {out_len}");
            assert_eq!((out.as_slice(), consumed), (plain.as_slice(), g.len()));
        }
    }
}

/// With a preset dictionary the header stop comes after `DICTID`, and once
/// the dictionary is set decoding goes on into the first block.
#[test]
fn zlib_block_stop_with_dictionary() {
    let z = hex(ZDICT);
    let mut dec = zlib::Decoder::with_config(zlib::DecoderConfig {
        dictionary: DICT.to_vec(),
    });
    let (stops, out, consumed) = drive_blocks(&mut dec, zlib_block, zlib_boundary, &z, 0, 4096);
    assert_eq!(stops, vec![(48, 0)]);
    assert_eq!((out.as_slice(), consumed), (DICT_PLAIN, z.len()));
}

/// Plain `decode` never stops early; `decode_block` does not change later
/// `decode` calls.
#[test]
fn decode_is_unaffected_by_decode_block() {
    let raw = hex(RAW);
    let mut dec = deflate::Decoder::new();
    let mut buf = vec![0u8; 4096];
    let (p, status) = dec.decode_block(&raw, &mut buf).unwrap();
    assert_ne!(status, Status::StreamEnd);
    assert!(dec.at_block_boundary());
    assert!(!dec.in_final_block());
    let first = parse_blocks(&raw, 0)[0];
    assert_eq!(p.consumed * 8 - dec.unused_bits() as usize, first.bit);
    let mut out = buf[..p.written].to_vec();
    let (q, status) = dec.decode(&raw[p.consumed..], &mut buf).unwrap();
    assert_eq!(status, Status::StreamEnd);
    out.extend_from_slice(&buf[..q.written]);
    assert_eq!(out, hex(PLAIN));
    assert_eq!(p.consumed + q.consumed, raw.len());
}

// ─── cross-check against the system zlib ─────────────────────────────────

/// Many streams from CPython's zlib — every level, all strategies, each
/// flush mode, raw / zlib / gzip, with and without a preset dictionary —
/// decoded whole and a byte at a time, with exact consumption and block
/// stops checked against the parser above. Skips without `python3`.
#[test]
fn python_zlib_streams() {
    use std::io::Read;
    use std::process::{Command, Stdio};

    const SCRIPT: &str = r#"
import random, struct, sys, zlib
random.seed(156)
words = [bytes(random.choice(b"etaoinshrdlu") for _ in range(random.randint(1, 8))) for _ in range(200)]
def data(n):
    out = bytearray()
    while len(out) < n:
        k = random.random()
        if k < 0.5:
            out += b" ".join(random.choice(words) for _ in range(50))
        elif k < 0.7:
            out += bytes(random.randrange(256) for _ in range(300))
        else:
            out += bytes([random.randrange(4)]) * random.randint(1, 600)
    return bytes(out[:n])
strategies = [zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE, zlib.Z_FIXED]
flushes = [None, zlib.Z_SYNC_FLUSH, zlib.Z_FULL_FLUSH, zlib.Z_BLOCK, zlib.Z_PARTIAL_FLUSH, zlib.Z_NO_FLUSH]
out = sys.stdout.buffer
case = 0
for level in range(10):
    for si, strategy in enumerate(strategies):
        kind = (level + si) % 3
        wbits = random.randint(9, 15) if case % 4 == 1 else 15
        wbits = [-wbits, wbits, wbits + 16][kind]
        zdict = data(random.randint(1, 3000)) if kind == 1 and case % 3 == 0 else b""
        kw = {"zdict": zdict} if zdict else {}
        c = zlib.compressobj(level, zlib.DEFLATED, wbits, random.randint(1, 9), strategy, **kw)
        plain = data(random.randint(0, 30000))
        comp = b""
        pos = 0
        while pos < len(plain):
            n = random.randint(1, 5000)
            comp += c.compress(plain[pos:pos + n])
            pos += n
            fl = flushes[(case + pos) % len(flushes)]
            if fl is not None:
                comp += c.flush(fl)
        comp += c.flush(zlib.Z_FINISH)
        for b in (bytes([kind]), struct.pack("<I", len(plain)), plain, struct.pack("<I", len(comp)), comp, struct.pack("<I", len(zdict)), zdict):
            out.write(b)
        case += 1
"#;
    let child = Command::new("python3")
        .args(["-I", "-c", SCRIPT])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let Ok(mut child) = child else {
        eprintln!("python3 not available; skipping");
        return;
    };
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    if !child.wait().unwrap().success() {
        eprintln!("python3 zlib not usable; skipping");
        return;
    }

    let mut rest = bytes.as_slice();
    fn field(rest: &mut &[u8]) -> Vec<u8> {
        let (n, tail) = rest.split_at(4);
        let n = u32::from_le_bytes(n.try_into().unwrap()) as usize;
        let (a, tail) = tail.split_at(n);
        *rest = tail;
        a.to_vec()
    }
    let mut cases = 0;
    while let Some((&kind, tail)) = rest.split_first() {
        rest = tail;
        let plain = field(&mut rest);
        let comp = field(&mut rest);
        let dict = field(&mut rest);
        cases += 1;

        let mut input = comp.clone();
        input.extend_from_slice(GARBAGE);
        let header_bits = match kind {
            0 => 0,
            1 => 16 + if dict.is_empty() { 0 } else { 32 },
            _ => 80,
        };
        let want = expected_stops(&comp, header_bits, kind != 0);
        assert_eq!(
            parse_blocks(&comp, header_bits).last().unwrap().out,
            plain.len()
        );
        let small = comp.len() < 6000;
        for (step, out_len) in [(0, 65536), (0, 1000), (1, 4096), (3, 1)] {
            if step != 0 && !small {
                continue;
            }
            let ctx = format!("case {cases} kind {kind} step {step} out {out_len}");
            let (out, consumed, stops) = match kind {
                0 => {
                    let mut d = deflate::Decoder::new();
                    let (out, consumed) = drive(&mut d, &input, step, out_len);
                    let mut d = deflate::Decoder::new();
                    let (stops, out2, c2) = drive_blocks(
                        &mut d,
                        deflate_block,
                        deflate_boundary,
                        &input,
                        step,
                        out_len,
                    );
                    assert_eq!((out2.as_slice(), c2), (out.as_slice(), consumed), "{ctx}");
                    (out, consumed, stops)
                }
                1 => {
                    let make = || {
                        zlib::Decoder::with_config(zlib::DecoderConfig {
                            dictionary: dict.clone(),
                        })
                    };
                    let (out, consumed) = drive(&mut make(), &input, step, out_len);
                    let (stops, out2, c2) = drive_blocks(
                        &mut make(),
                        zlib_block,
                        zlib_boundary,
                        &input,
                        step,
                        out_len,
                    );
                    assert_eq!((out2.as_slice(), c2), (out.as_slice(), consumed), "{ctx}");
                    if !dict.is_empty() {
                        // The same stream through the need-dictionary path.
                        let mut d = zlib::Decoder::new();
                        let mut buf = vec![0u8; 16];
                        let (p, _) = d.decode(&input, &mut buf).unwrap();
                        assert_eq!(p.consumed, 6, "{ctx}");
                        assert!(d.needs_dictionary());
                        d.set_dictionary(&dict).unwrap();
                        let (out3, c3) = drive(&mut d, &input[6..], step, out_len);
                        assert_eq!((out3.as_slice(), c3 + 6), (out.as_slice(), consumed));
                    }
                    (out, consumed, stops)
                }
                _ => {
                    let (out, consumed) = drive(&mut gzip::Decoder::new(), &input, step, out_len);
                    let (stops, out2, c2) = drive_blocks(
                        &mut gzip::Decoder::new().with_multi_member(false),
                        gzip_block,
                        gzip_boundary,
                        &input,
                        step,
                        out_len,
                    );
                    assert_eq!((out2.as_slice(), c2), (out.as_slice(), consumed), "{ctx}");
                    (out, consumed, stops)
                }
            };
            assert!(out == plain, "{ctx}: output differs");
            assert_eq!(consumed, comp.len(), "{ctx}");
            assert_eq!(stops, want, "{ctx}");
        }
    }
    assert_eq!(cases, 50);
}
