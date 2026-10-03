//! The `embed` deflate-family encoder: greedy LZ77 over a single-probe hash
//! table, coded with deflate's fixed Huffman codes. No code to build,
//! nothing to buffer but one block of input, a single pass.
//!
//! The streaming [`Encoder`] gathers input a block at a time and compresses
//! each as one deflate block, matches only ever found within it, so the
//! stream does not depend on how the input was cut. Tokens go through a
//! 32-bit buffer straight to the caller's output, a byte at a time if that
//! is all the room there is; a token is only started if the output and the
//! buffer have room for all of it, and when they do not, the block keeps
//! its place and the next call carries on. The one-shot [`compress`] makes
//! a single block of all its input, with the caller's table.
//!
//! The table holds the low sixteen bits of the last position at which each
//! hash was seen. That is enough to tell a distance within deflate's reach;
//! what it cannot tell, such as a stale or never written entry, is caught
//! by comparing the data, which has to be done anyway.

use super::format::Format;
use crate::error::Error;
use crate::traits::{Flush, RawEncoder, RawProgress};

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MAX_DIST: usize = 32768;
/// A match of the minimum length costs more than literals from this far.
const TOO_FAR: usize = 4096;
const END_OF_BLOCK: u32 = 256;

/// The most bits a token takes: a length code and its extra bits, a
/// distance code and its extra bits.
const TOKEN_BITS: u32 = 8 + 5 + 5 + 13;

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

/// One call's output, and the bits on their way to it, the least
/// significant first.
struct Out<'a> {
    dst: &'a mut [u8],
    len: usize,
    bit_buf: u32,
    bit_cnt: u32,
}

impl Out<'_> {
    /// Moves whole bytes of the bit buffer to the output, as far as it goes.
    fn flush(&mut self) {
        while self.bit_cnt >= 8 {
            let Some(slot) = self.dst.get_mut(self.len) else {
                return;
            };
            *slot = self.bit_buf as u8;
            self.len += 1;
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    /// Whether `count` more bits fit, in the output and in the bit buffer,
    /// once it is full: then they can be written without a check.
    fn ready(&mut self, count: u32) -> bool {
        self.flush();
        let room = (self.dst.len() - self.len).min(4) as u32;
        self.bit_cnt + count < 32 + 8 * room
    }

    /// Writes the `count` low bits of `value`, at most 16; the others must
    /// be zeros. Fails if they do not fit in the bit buffer, the output
    /// being full.
    fn bits(&mut self, value: u32, count: u32) -> Result<(), Error> {
        self.flush();
        if self.bit_cnt + count >= 32 {
            return Err(Error::OutputTooSmall);
        }
        self.bit_buf |= value << self.bit_cnt;
        self.bit_cnt += count;
        Ok(())
    }

    /// Writes a literal/length symbol with its fixed Huffman code.
    fn symbol(&mut self, sym: u32) -> Result<(), Error> {
        let (code, len) = match sym {
            0..=143 => (0x30 + sym, 8),
            144..=255 => (sym - 144 + 0x190, 9),
            256..=279 => (sym - 256, 7),
            _ => (sym - 280 + 0xc0, 8),
        };
        // Huffman codes go the most significant bit first.
        self.bits(code.reverse_bits() >> (32 - len), len)
    }

    /// Writes a match: `len` bytes from `dist` back.
    fn copy(&mut self, len: usize, dist: usize) -> Result<(), Error> {
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
        self.symbol(257 + sym)?;
        self.bits(len & ((1 << extra) - 1), extra)?;

        let dist = (dist - 1) as u32;
        let (sym, extra) = match dist {
            0..=3 => (dist, 0),
            _ => {
                let extra = log2(dist) - 1;
                (2 * extra + 2 + ((dist >> extra) & 1), extra)
            }
        };
        // Distance codes are five bits long, the most significant first.
        self.bits(sym.reverse_bits() >> 27, 5)?;
        self.bits(dist & ((1 << extra) - 1), extra)
    }

    /// Writes a block's data as tokens, from `pos` on, finding matches with
    /// the `mask + 1` entries of `table`. With `CHECK`, stops before a
    /// token that might not fit, and returns where it did; without, fails
    /// if one does not.
    fn tokens<const CHECK: bool>(
        &mut self,
        table: &mut [u16],
        mask: usize,
        data: &[u8],
        mut pos: usize,
    ) -> Result<usize, Error> {
        while let Some(&byte) = data.get(pos) {
            if CHECK && !self.ready(TOKEN_BITS) {
                break;
            }
            let (len, dist) = find(table, mask, data, pos);
            if len < MIN_MATCH {
                self.symbol(byte as u32)?;
                pos += 1;
                continue;
            }
            pos += len;
            self.copy(len, dist)?;
        }
        Ok(pos)
    }
}

/// A deflate-family encoder in format `F`, compressing blocks of `B` bytes
/// with a table of `T` entries.
pub(crate) struct Encoder<F, const B: usize, const T: usize> {
    block: [u8; B],
    /// How much of the block is filled, and how much of that is compressed.
    len: usize,
    pos: usize,
    table: [u16; T],
    format: F,
    /// Bytes compressed so far, for the gzip trailer.
    size: u32,
    /// Bits written but not yet out, between calls.
    bit_buf: u32,
    bit_cnt: u32,
    /// How much of the header has been written.
    header: usize,
    phase: Phase,
}

impl<F: Format, const B: usize, const T: usize> Encoder<F, B, T> {
    /// Rejects, at build time, sizes the encoder cannot use.
    const VALID: () = assert!(
        B > 0 && B <= 65536 && T.is_power_of_two() && T <= 65536,
        "the block must be 1 to 65536 bytes, the table a power of two of at most 65536 entries"
    );

    pub(crate) const fn new() -> Self {
        let () = Self::VALID;
        Encoder {
            block: [0; B],
            len: 0,
            pos: 0,
            table: [0; T],
            format: F::INIT,
            size: 0,
            bit_buf: 0,
            bit_cnt: 0,
            header: 0,
            phase: Phase::Gather,
        }
    }

    /// The output of a call, carrying on with the bits the last one left.
    fn out<'a>(&self, dst: &'a mut [u8]) -> Out<'a> {
        Out {
            dst,
            len: 0,
            bit_buf: self.bit_buf,
            bit_cnt: self.bit_cnt,
        }
    }

    /// Ends a call: moves what it can to the output and keeps the rest.
    /// Returns how much was written.
    fn end(&mut self, mut out: Out) -> usize {
        out.flush();
        self.bit_buf = out.bit_buf;
        self.bit_cnt = out.bit_cnt;
        out.len
    }

    /// Writes the container header, if it is not yet. Returns false if the
    /// output filled before that was done; the next call picks it up.
    fn header(&mut self, out: &mut Out) -> bool {
        while let Some(&byte) = F::HEADER.get(self.header) {
            if !out.ready(8) {
                return false;
            }
            let _ = out.bits(byte as u32, 8);
            self.header += 1;
        }
        true
    }

    /// Compresses the block, from where it left off, as far as the output
    /// goes. Returns whether the block is done.
    fn compress(&mut self, out: &mut Out) -> bool {
        if self.phase == Phase::Gather {
            // Not the final block, fixed Huffman codes.
            if !self.header(out) || !out.ready(3) {
                return false;
            }
            let _ = out.bits(0b010, 3);
            self.format
                .update(self.block.get(..self.len).unwrap_or(&[]));
            self.size = self.size.wrapping_add(self.len as u32);
            self.pos = 0;
            self.phase = Phase::Open;
        }
        let data = self.block.get(..self.len).unwrap_or(&[]);
        // `ready` checks every token, so this cannot fail.
        self.pos = out
            .tokens::<true>(&mut self.table, T - 1, data, self.pos)
            .unwrap_or(self.pos);
        if self.pos < self.len || !out.ready(7) {
            return false;
        }
        let _ = out.symbol(END_OF_BLOCK);
        self.len = 0;
        self.pos = 0;
        self.phase = Phase::Gather;
        true
    }
}

/// Looks for a match for the data at `pos`, with the `mask + 1` entries of
/// `table` to look in. Returns its length, zero if there is none, and
/// distance.
fn find(table: &mut [u16], mask: usize, data: &[u8], pos: usize) -> (usize, usize) {
    let ahead = data.get(pos..).unwrap_or(&[]);
    let Some(&[a, b, c]) = ahead.first_chunk() else {
        return (0, 0);
    };
    let hash = u32::from_le_bytes([a, b, c, 0]).wrapping_mul(0x9e37_79b1) >> 16;
    let Some(entry) = table.get_mut(hash as usize & mask) else {
        return (0, 0);
    };
    let dist = (pos as u16).wrapping_sub(*entry) as usize;
    *entry = pos as u16;

    // A distance of zero is 65536 bytes back, or an entry never written.
    let Some(behind) = pos.checked_sub(dist).and_then(|from| data.get(from..)) else {
        return (0, 0);
    };
    if dist == 0 || dist > MAX_DIST {
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

impl<F: Format, const B: usize, const T: usize> RawEncoder for Encoder<F, B, T> {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if !matches!(self.phase, Phase::Gather | Phase::Open) {
            return Err(Error::Corrupt);
        }
        let mut out = self.out(output);
        let mut consumed = 0;
        loop {
            if (self.len == B || self.phase == Phase::Open) && !self.compress(&mut out) {
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
        Ok(RawProgress {
            consumed,
            written: self.end(out),
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut out = self.out(output);
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
                    if !self.header(&mut out) || !out.ready(3 + 7 + 7) {
                        break;
                    }
                    let _ = out.bits(0b011, 3);
                    let _ = out.symbol(END_OF_BLOCK);
                    let _ = out.bits(0, out.bit_cnt.wrapping_neg() & 7);
                    self.phase = Phase::Trailer(0);
                }
                Phase::Trailer(half) if (half as usize) < 2 * F::TRAILER => {
                    if !out.ready(16) {
                        break;
                    }
                    let words = self.format.trailer(self.size);
                    let word = words.get(half as usize / 2).copied().unwrap_or(0);
                    let value = if half % 2 == 0 {
                        word & 0xffff
                    } else {
                        word >> 16
                    };
                    let _ = out.bits(value, 16);
                    self.phase = Phase::Trailer(half + 1);
                }
                Phase::Trailer(_) => self.phase = Phase::Done,
                Phase::Done => break,
            }
        }
        let written = self.end(out);
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.phase == Phase::Done && self.bit_cnt == 0,
        })
    }

    fn raw_reset(&mut self) {
        // The table needs no clearing: what it holds is checked against the
        // data. The zeros are hidden from the optimizer: seen as such, they
        // would be merged into a call to `memclr`, which an encoder alone
        // does not otherwise link, for more code than the stores.
        let zero = core::hint::black_box(0);
        self.len = zero;
        self.pos = zero;
        self.header = zero;
        self.size = zero as u32;
        self.bit_buf = zero as u32;
        self.bit_cnt = zero as u32;
        self.format = F::INIT;
        self.phase = Phase::Gather;
    }

    fn raw_flush(&mut self, _: &mut [u8], _: Flush) -> Result<RawProgress, Error> {
        // The tail of each block's end-of-block code sits in the bit buffer
        // and there is no way to byte-align it mid-stream.
        Err(Error::Unsupported)
    }
}

// ─── one shot ───────────────────────────────────────────────────────────

/// Compresses `data` into `dst` in format `F`, as a single block, finding
/// matches with `table`, of which the largest power of two of entries, up
/// to 65536, gets used. Returns the length of the stream, or
/// `Error::OutputTooSmall` if it does not fit.
pub(crate) fn compress<F: Format>(
    data: &[u8],
    table: &mut [u16],
    dst: &mut [u8],
) -> Result<usize, Error> {
    let mask = match table.len().checked_ilog2() {
        Some(bits) => (1 << bits.min(16)) - 1,
        None => 0,
    };
    let mut out = Out {
        dst,
        len: 0,
        bit_buf: 0,
        bit_cnt: 0,
    };
    for &byte in F::HEADER {
        out.bits(byte as u32, 8)?;
    }
    if !data.is_empty() {
        // Not the final block, fixed Huffman codes.
        out.bits(0b010, 3)?;
        out.tokens::<false>(table, mask, data, 0)?;
        out.symbol(END_OF_BLOCK)?;
    }
    // A final, empty block, then padding to a byte boundary.
    out.bits(0b011, 3)?;
    out.symbol(END_OF_BLOCK)?;
    out.bits(0, out.bit_cnt.wrapping_neg() & 7)?;

    let mut format = F::INIT;
    format.update(data);
    let words = format.trailer(data.len() as u32);
    for &word in words.iter().take(F::TRAILER) {
        out.bits(word & 0xffff, 16)?;
        out.bits(word >> 16, 16)?;
    }
    out.flush();
    if out.bit_cnt != 0 {
        return Err(Error::OutputTooSmall);
    }
    Ok(out.len)
}
