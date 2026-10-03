//! The `embed` deflate-family encoder: greedy LZ77 over a single-probe hash
//! table, coded with deflate's fixed Huffman codes. No code to build,
//! nothing to buffer but one block of input, a single pass.
//!
//! Input is gathered a [`BLOCK`] at a time and compressed as one deflate
//! block, matches only ever found within it, so the stream does not depend
//! on how the input was cut. Tokens go through a 64-bit buffer straight to
//! the caller's output, a byte at a time if that is all the room there is;
//! when the output fills, the block keeps its place and the next call
//! carries on.
//!
//! The table holds the low sixteen bits of the last position at which each
//! hash was seen. That is enough to tell a distance within a block; what it
//! cannot tell, such as a stale or never written entry, is caught by
//! comparing the data, which has to be done anyway.

use super::format::Format;
use super::{BLOCK, TABLE};
use crate::error::Error;
use crate::traits::{Flush, RawEncoder, RawProgress};

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// A match of the minimum length costs more than literals from this far.
const TOO_FAR: usize = 4096;
const END_OF_BLOCK: u32 = 256;
const MASK: usize = TABLE - 1;
const _: () = assert!(TABLE.is_power_of_two() && TABLE <= 65536);
const _: () = assert!(BLOCK <= 65536);

/// Where the stream is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Gathering input, between blocks; the header may not be written.
    Gather,
    /// A block is open: its header is written, its tokens up to `pos`.
    Open,
    /// The final empty block is written; so many trailer halves are.
    Trailer(u8),
    Done,
}

/// The base two logarithm of `value`, rounded down. Unlike `ilog2`, it has
/// no panic to link for a zero it is never given.
fn log2(value: u32) -> u32 {
    31 - value.leading_zeros()
}

/// One call's output.
struct Out<'a> {
    dst: &'a mut [u8],
    len: usize,
}

/// The most bits a token takes: a length code and its extra bits, a
/// distance code and its extra bits.
const TOKEN_BITS: u32 = 8 + 5 + 5 + 13;

/// A deflate-family encoder in format `F`.
pub(crate) struct Encoder<F> {
    block: [u8; BLOCK],
    /// How much of the block is filled, and how much of that is compressed.
    len: usize,
    pos: usize,
    table: [u16; TABLE],
    format: F,
    /// Bytes compressed so far, for the gzip trailer.
    size: u32,
    /// Bits written but not yet out, least significant first: 64 of them
    /// hold a token on top of what a full output left behind.
    bit_buf: u64,
    bit_cnt: u32,
    /// How much of the header has been written.
    header: usize,
    phase: Phase,
}

impl<F: Format> Encoder<F> {
    pub(crate) const fn new() -> Self {
        Encoder {
            block: [0; BLOCK],
            len: 0,
            pos: 0,
            table: [0; TABLE],
            format: F::INIT,
            size: 0,
            bit_buf: 0,
            bit_cnt: 0,
            header: 0,
            phase: Phase::Gather,
        }
    }

    /// Queues the `count` low bits of `value`, at most 16, the least
    /// significant first, which `ready` made room for. The others must be
    /// zeros.
    fn bits(&mut self, value: u32, count: u32) {
        self.bit_buf |= (value as u64) << self.bit_cnt;
        self.bit_cnt += count;
    }

    /// Moves whole bytes of queued bits to `out`, as far as it goes.
    fn flush(&mut self, out: &mut Out) {
        while self.bit_cnt >= 8 {
            let Some(slot) = out.dst.get_mut(out.len) else {
                return;
            };
            *slot = self.bit_buf as u8;
            out.len += 1;
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    /// Whether `count` more bits can be queued, after moving what can be
    /// moved to `out`. When not, `out` is full, and the caller leaves the
    /// rest for the next call.
    fn ready(&mut self, out: &mut Out, count: u32) -> bool {
        self.flush(out);
        self.bit_cnt + count <= u64::BITS
    }

    /// Queues a literal/length symbol with its fixed Huffman code.
    fn symbol(&mut self, sym: u32) {
        let (code, len) = match sym {
            0..=143 => (0x30 + sym, 8),
            144..=255 => (sym - 144 + 0x190, 9),
            256..=279 => (sym - 256, 7),
            _ => (sym - 280 + 0xc0, 8),
        };
        // Huffman codes go the most significant bit first.
        self.bits(code.reverse_bits() >> (32 - len), len);
    }

    /// Writes the container header, if it is not yet. Returns false if `out`
    /// filled before that was done; the next call picks it up.
    fn header(&mut self, out: &mut Out) -> bool {
        while let Some(&byte) = F::HEADER.get(self.header) {
            if !self.ready(out, 8) {
                return false;
            }
            self.bits(byte as u32, 8);
            self.header += 1;
        }
        true
    }

    /// Compresses the block, from where it left off, as far as `out` goes.
    /// Returns whether the block is done.
    fn compress(&mut self, out: &mut Out) -> bool {
        if self.phase == Phase::Gather {
            // Not the final block, fixed Huffman codes.
            if !self.header(out) || !self.ready(out, 3) {
                return false;
            }
            self.bits(0b010, 3);
            self.format
                .update(self.block.get(..self.len).unwrap_or(&[]));
            self.size = self.size.wrapping_add(self.len as u32);
            self.pos = 0;
            self.phase = Phase::Open;
        }
        while let Some(&byte) = self.block.get(self.pos).filter(|_| self.pos < self.len) {
            if !self.ready(out, TOKEN_BITS) {
                return false;
            }
            let (len, dist) = find(
                &mut self.table,
                self.block.get(..self.len).unwrap_or(&[]),
                self.pos,
            );
            if len < MIN_MATCH {
                self.symbol(byte as u32);
                self.pos += 1;
                continue;
            }
            self.pos += len;

            // The inverse of the decoder's arithmetic. Length symbols come by
            // four for each count of extra bits, distance ones by two.
            let len = (len - MIN_MATCH) as u32;
            let (sym, extra) = match len {
                0..=7 => (len, 0),
                255 => (28, 0),
                _ => {
                    let extra = log2(len) - 2;
                    (4 * extra + 4 + ((len >> extra) & 3), extra)
                }
            };
            self.symbol(257 + sym);
            self.bits(len & ((1 << extra) - 1), extra);

            let dist = (dist - 1) as u32;
            let (sym, extra) = match dist {
                0..=3 => (dist, 0),
                _ => {
                    let extra = log2(dist) - 1;
                    (2 * extra + 2 + ((dist >> extra) & 1), extra)
                }
            };
            // Distance codes are five bits long, the most significant first.
            self.bits(sym.reverse_bits() >> 27, 5);
            self.bits(dist & ((1 << extra) - 1), extra);
        }
        if !self.ready(out, 7) {
            return false;
        }
        self.symbol(END_OF_BLOCK);
        self.len = 0;
        self.pos = 0;
        self.phase = Phase::Gather;
        true
    }
}

/// Looks for a match for the data at `pos`. Returns its length, zero if
/// there is none, and distance.
fn find(table: &mut [u16; TABLE], data: &[u8], pos: usize) -> (usize, usize) {
    let ahead = data.get(pos..).unwrap_or(&[]);
    let Some(&[a, b, c]) = ahead.first_chunk() else {
        return (0, 0);
    };
    let hash = u32::from_le_bytes([a, b, c, 0]).wrapping_mul(0x9e37_79b1) >> 16;
    let Some(entry) = table.get_mut(hash as usize & MASK) else {
        return (0, 0);
    };
    let dist = (pos as u16).wrapping_sub(*entry) as usize;
    *entry = pos as u16;

    // A distance of zero is an entry never written, or stale.
    let Some(behind) = pos.checked_sub(dist).and_then(|from| data.get(from..)) else {
        return (0, 0);
    };
    if dist == 0 {
        return (0, 0);
    }
    let len = behind
        .iter()
        .zip(ahead)
        .take(MAX_MATCH)
        .take_while(|(a, b)| a == b)
        .count();
    if len == MIN_MATCH && dist > TOO_FAR {
        return (0, 0);
    }
    (len, dist)
}

impl<F: Format> RawEncoder for Encoder<F> {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if !matches!(self.phase, Phase::Gather | Phase::Open) {
            return Err(Error::Corrupt);
        }
        let mut out = Out {
            dst: output,
            len: 0,
        };
        let mut consumed = 0;
        loop {
            if (self.len == BLOCK || self.phase == Phase::Open) && !self.compress(&mut out) {
                break;
            }
            let Some(rest) = input.get(consumed..).filter(|rest| !rest.is_empty()) else {
                break;
            };
            let room = self.block.get_mut(self.len..).unwrap_or(&mut []);
            let n = room.len().min(rest.len());
            for (to, &from) in room.iter_mut().zip(rest) {
                *to = from;
            }
            self.len += n;
            consumed += n;
        }
        self.flush(&mut out);
        Ok(RawProgress {
            consumed,
            written: out.len,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut out = Out {
            dst: output,
            len: 0,
        };
        loop {
            match self.phase {
                Phase::Gather if self.len > 0 => {
                    if !self.compress(&mut out) {
                        break;
                    }
                }
                Phase::Open => {
                    if !self.compress(&mut out) {
                        break;
                    }
                }
                Phase::Gather => {
                    // A final, empty block, then padding to a byte boundary:
                    // one step, so that it is never half written.
                    if !self.header(&mut out) || !self.ready(&mut out, 3 + 7 + 7) {
                        break;
                    }
                    self.bits(0b011, 3);
                    self.symbol(END_OF_BLOCK);
                    if !self.bit_cnt.is_multiple_of(8) {
                        self.bits(0, 8 - self.bit_cnt % 8);
                    }
                    self.phase = Phase::Trailer(0);
                }
                Phase::Trailer(half) if (half as usize) < 2 * F::TRAILER => {
                    if !self.ready(&mut out, 16) {
                        break;
                    }
                    let words = self.format.trailer(self.size);
                    let word = words.get(half as usize / 2).copied().unwrap_or(0);
                    let value = if half % 2 == 0 {
                        word & 0xffff
                    } else {
                        word >> 16
                    };
                    self.bits(value, 16);
                    self.phase = Phase::Trailer(half + 1);
                }
                Phase::Trailer(_) => self.phase = Phase::Done,
                Phase::Done => {
                    self.flush(&mut out);
                    break;
                }
            }
        }
        Ok(RawProgress {
            consumed: 0,
            written: out.len,
            done: self.phase == Phase::Done && self.bit_cnt == 0,
        })
    }

    fn raw_reset(&mut self) {
        // The table needs no clearing: what it holds is checked against the
        // data.
        self.len = 0;
        self.pos = 0;
        self.format = F::INIT;
        self.size = 0;
        self.bit_buf = 0;
        self.bit_cnt = 0;
        self.header = 0;
        self.phase = Phase::Gather;
    }

    fn raw_flush(&mut self, _: &mut [u8], _: Flush) -> Result<RawProgress, Error> {
        // The tail of each block's end-of-block code sits in the bit buffer
        // and there is no way to byte-align it mid-stream.
        Err(Error::Unsupported)
    }
}
