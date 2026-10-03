//! The core of the `embed` deflate decoder: a bit reader over the input,
//! canonical Huffman codes decoded one bit at a time from the count of codes
//! of each length (in the manner of zlib's `puff`: slower than lookup
//! tables, but next to no code and no table to build), and the history
//! window the push decoder's output goes through.
//!
//! Everything that loops is cut into steps that are methods of their own,
//! for the state machine in `decoder` to take one at a time and roll back
//! when the input runs out midway, and for the one-shot functions in
//! `oneshot` to loop over. Nothing here indexes in a way that could
//! panic: a bare-metal build must link no panic machinery.

use super::WINDOW;
use super::format::Format;
use crate::error::Error;

pub(super) const MAX_BITS: usize = 15;
/// Most literal/length symbols a block can define.
pub(super) const MAX_LEN_SYMS: usize = 288;
/// Most distance symbols a block can define.
const MAX_DIST_SYMS: usize = 32;
pub(super) const MAX_SYMS: usize = MAX_LEN_SYMS + MAX_DIST_SYMS;

/// How many codes there are of each length. Aligned so that clearing it is
/// a job for `memclr4`, which is linked anyway, rather than for another
/// routine of `compiler_builtins`.
#[repr(align(4))]
pub(super) struct Counts(pub(super) [u16; MAX_BITS + 1]);

/// The storage of the two codes of a block, kept in the decoder between
/// pieces of input.
pub(super) struct Tables {
    counts: [Counts; 2],
    symbol: [u16; MAX_SYMS],
}

impl Tables {
    pub(super) const fn new() -> Self {
        Tables {
            counts: [Counts([0; MAX_BITS + 1]), Counts([0; MAX_BITS + 1])],
            symbol: [0; MAX_SYMS],
        }
    }

    /// The literal/length code and the distance code, to `build` or built.
    #[inline]
    pub(super) fn codes(&mut self) -> (Huffman<'_>, Huffman<'_>) {
        let [len_count, dist_count] = &mut self.counts;
        let (len_symbol, dist_symbol) = self.symbol.split_at_mut(MAX_LEN_SYMS);
        (
            Huffman::new(len_count, len_symbol),
            Huffman::new(dist_count, dist_symbol),
        )
    }
}

/// Order in which the code length code lengths are stored.
pub(super) const ORDER: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// A canonical Huffman code: `count[n]` codes of `n` bits each, and the
/// symbols they decode to, ordered by code.
pub(super) struct Huffman<'a> {
    count: &'a mut Counts,
    symbol: &'a mut [u16],
    /// The number of unused codes: zero for a complete code, negative for an
    /// over-subscribed one.
    pub(super) left: i32,
}

/// What a literal/length symbol stands for.
pub(super) enum Symbol {
    /// A literal, which went to the output.
    Literal,
    /// The end of the block.
    End,
    /// A match of this length, whose distance follows.
    Match(u32),
}

impl<'a> Huffman<'a> {
    pub(super) fn new(count: &'a mut Counts, symbol: &'a mut [u16]) -> Self {
        Huffman {
            count,
            symbol,
            left: 1,
        }
    }

    /// Builds the code from the code length of each symbol.
    pub(super) fn build(&mut self, lengths: &[u8]) {
        let count = &mut self.count.0;
        *count = [0; MAX_BITS + 1];
        for &len in lengths {
            count[(len & 15) as usize] += 1;
        }
        let mut left = 1;
        let mut offsets = [0u16; MAX_BITS + 1];
        for len in 1..=MAX_BITS {
            left = (left << 1) - count[len] as i32;
            if len < MAX_BITS {
                offsets[len + 1] = offsets[len] + count[len];
            }
        }

        // An over-subscribed code gets rejected before it is used; its symbols
        // that do not fit are dropped here.
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let offset = &mut offsets[(len & 15) as usize];
                if let Some(slot) = self.symbol.get_mut(*offset as usize) {
                    *slot = sym as u16;
                }
                *offset += 1;
            }
        }
        self.left = left;
    }

    /// Whether the code is one deflate permits for literals/lengths and for
    /// distances: complete, or made of a single one-bit code.
    fn is_valid(&self, symbols: usize) -> bool {
        let count = &self.count.0;
        self.left == 0 || (self.left > 0 && symbols == (count[0] + count[1]) as usize)
    }
}

/// The code lengths of the fixed codes: the literals/lengths, then all 32
/// five-bit distance codes, to make that code complete. The last two are
/// rejected when they come up.
pub(super) fn fixed_lengths(lengths: &mut [u8; MAX_SYMS]) {
    const RUNS: [(u8, u8); 5] = [(144, 8), (112, 9), (24, 7), (8, 8), (32, 5)];
    let mut rest = &mut lengths[..];
    for (count, len) in RUNS {
        let Some((run, tail)) = rest.split_at_mut_checked(count as usize) else {
            break;
        };
        run.fill(len);
        rest = tail;
    }
}

/// Builds the two codes of a compressed block given the code length of each
/// literal/length symbol, directly followed by those of the distance symbols.
/// Fails unless both codes are ones deflate permits.
pub(super) fn build_codes(
    lengths: &[u8],
    len_syms: usize,
    len_code: &mut Huffman,
    dist_code: &mut Huffman,
) -> Result<(), Error> {
    let (len_lengths, dist_lengths) = lengths.split_at_checked(len_syms).ok_or(Error::Corrupt)?;
    len_code.build(len_lengths);
    dist_code.build(dist_lengths);
    if !len_code.is_valid(len_lengths.len()) || !dist_code.is_valid(dist_lengths.len()) {
        return Err(Error::InvalidHuffmanTree);
    }
    Ok(())
}

// ─── the window and the output ──────────────────────────────────────────

/// Where the decoded bytes go: the push decoder's [`Windowed`] sink, or one
/// of the one-shot outputs in `oneshot`.
pub(crate) trait Out {
    /// Appends a byte. The push decoder has made sure there is room; the
    /// one-shot outputs fail when there is none.
    fn put(&mut self, byte: u8) -> Result<(), Error>;
    /// Fails unless a back-reference `dist` bytes back can be followed.
    fn check_dist(&self, dist: u32) -> Result<(), Error>;
}

/// The last `N` bytes produced, which back-references copy from. `N` is a
/// power of two, at most deflate's 32 KiB reach.
pub(super) struct Window<const N: usize> {
    buf: [u8; N],
    /// Bytes produced so far, modulo 2<sup>32</sup>; the next one goes at
    /// `pos % N`.
    pos: u32,
    /// How many bytes the window holds, up to `N`.
    avail: u32,
    /// The farthest back a reference may reach, if the caller asked for a
    /// check stricter than `N`; zero otherwise, so that a fresh window is
    /// all zeros and a `static` decoder lands in `.bss`.
    max_dist: u32,
}

impl<const N: usize> Window<N> {
    const MASK: usize = N - 1;
    /// Rejects, at build time, a window deflate cannot use.
    const VALID: () = assert!(
        N.is_power_of_two() && N <= WINDOW,
        "the window must be a power of two of at most 32768 bytes"
    );

    pub(super) const fn new() -> Self {
        let () = Self::VALID;
        Window {
            buf: [0; N],
            pos: 0,
            avail: 0,
            max_dist: 0,
        }
    }

    pub(super) fn set_max_dist(&mut self, max_dist: usize) {
        self.max_dist = max_dist.clamp(1, N) as u32;
    }

    /// Bytes produced so far, modulo 2<sup>32</sup>.
    pub(super) fn written(&self) -> u32 {
        self.pos
    }

    pub(super) fn reset(&mut self) {
        self.pos = 0;
        self.avail = 0;
    }

    #[inline]
    fn put(&mut self, byte: u8) {
        if let Some(slot) = self.buf.get_mut(self.pos as usize & Self::MASK) {
            *slot = byte;
        }
        self.pos = self.pos.wrapping_add(1);
        if self.avail < N as u32 {
            self.avail += 1;
        }
    }

    /// The byte `dist` back, which `check_dist` found in reach.
    #[inline]
    fn back(&self, dist: u32) -> u8 {
        self.buf
            .get(self.pos.wrapping_sub(dist) as usize & Self::MASK)
            .copied()
            .unwrap_or(0)
    }

    /// Distances past what the window holds, `N` at most, fail like any
    /// other bad distance: with a window smaller than the encoder's, a
    /// stream can be valid and still not decodable.
    fn check_dist(&self, dist: u32) -> Result<(), Error> {
        let max_dist = match self.max_dist {
            0 => N as u32,
            max_dist => max_dist,
        };
        if dist == 0 || dist > max_dist || dist > self.avail {
            return Err(Error::InvalidDistance);
        }
        Ok(())
    }
}

/// Where one call of the push decoder puts its output: into the window and
/// into the caller's slice, as far as that goes. The container's checksum
/// is fed from the slice, in bulk.
pub(super) struct Windowed<'a, F, const N: usize> {
    pub(super) window: &'a mut Window<N>,
    pub(super) format: &'a mut F,
    dst: &'a mut [u8],
    /// Bytes produced this call.
    pub(super) len: usize,
    /// Bytes of `dst` fed to the checksum so far.
    flushed: usize,
}

impl<'a, F: Format, const N: usize> Windowed<'a, F, N> {
    pub(super) fn new(window: &'a mut Window<N>, format: &'a mut F, dst: &'a mut [u8]) -> Self {
        Windowed {
            window,
            format,
            dst,
            len: 0,
            flushed: 0,
        }
    }

    /// Bytes the slice still has room for.
    #[inline]
    pub(super) fn room(&self) -> usize {
        self.dst.len() - self.len
    }

    #[inline]
    fn push(&mut self, byte: u8) {
        self.window.put(byte);
        if let Some(slot) = self.dst.get_mut(self.len) {
            *slot = byte;
        }
        self.len += 1;
    }

    /// Copies `n` bytes from `dist` back.
    fn copy(&mut self, dist: u32, n: usize) -> Result<(), Error> {
        self.window.check_dist(dist)?;
        for _ in 0..n {
            let byte = self.window.back(dist);
            self.push(byte);
        }
        Ok(())
    }

    /// Feeds the checksum what the slice holds that it has not had.
    pub(super) fn flush(&mut self) {
        if let Some(data) = self.dst.get(self.flushed..self.len) {
            self.format.update(data);
        }
        self.flushed = self.len;
    }
}

impl<F: Format, const N: usize> Out for Windowed<'_, F, N> {
    #[inline]
    fn put(&mut self, byte: u8) -> Result<(), Error> {
        self.push(byte);
        Ok(())
    }

    #[inline]
    fn check_dist(&self, dist: u32) -> Result<(), Error> {
        self.window.check_dist(dist)
    }
}

// ─── the bit reader and the steps ───────────────────────────────────────

/// The decoder's view of one call: the input left, the output, and the bit
/// buffer, which the containers read their headers and trailers through too.
pub(super) struct Inflate<'a, O> {
    pub(super) input: &'a [u8],
    pub(super) sink: O,
    pub(super) bit_buf: u32,
    pub(super) bit_cnt: u32,
    /// Whether the input has run out. From then on it reads as zeros, which
    /// spares an error path at every read; see `bits`.
    pub(super) exhausted: bool,
}

impl<O: Out> Inflate<'_, O> {
    /// Reads `need` bits, at most 16, least significant first.
    ///
    /// This cannot fail: once the input has run out, zeros are read and
    /// `exhausted` says so. Callers only have to make sure that zeros get
    /// them to the end of the step without looping forever and without
    /// producing any output on the way: zeros end every header field and
    /// make for an invalid stored block, and the steps that could output
    /// something check `exhausted` first.
    pub(super) fn bits(&mut self, need: u32) -> u16 {
        while self.bit_cnt < need {
            match self.input.split_first() {
                Some((&byte, rest)) if !self.exhausted => {
                    self.bit_buf |= (byte as u32) << self.bit_cnt;
                    self.input = rest;
                }
                _ => self.exhausted = true,
            }
            self.bit_cnt += 8;
        }
        let value = self.bit_buf & ((1 << need) - 1);
        self.bit_buf >>= need;
        self.bit_cnt -= need;
        value as u16
    }

    /// Reads 32 bits, as a little-endian trailer word.
    pub(super) fn word(&mut self) -> u32 {
        let low = self.bits(16) as u32;
        (self.bits(16) as u32) << 16 | low
    }

    /// Skips to the next byte boundary.
    pub(super) fn align(&mut self) {
        self.bits(self.bit_cnt & 7);
    }

    pub(super) fn ready(&self) -> Result<(), Error> {
        if self.exhausted {
            return Err(Error::UnexpectedEnd);
        }
        Ok(())
    }

    /// Reads the length of a stored block.
    pub(super) fn stored_len(&mut self) -> Result<u16, Error> {
        self.align();
        let len = self.bits(16);
        if self.bits(16) != !len {
            return Err(Error::Corrupt);
        }
        Ok(len)
    }

    /// Copies one byte of a stored block to the output.
    pub(super) fn stored_byte(&mut self) -> Result<(), Error> {
        let byte = self.bits(8) as u8;
        self.ready()?;
        self.sink.put(byte)
    }

    /// Reads how many literal/length, distance and code length symbols a
    /// dynamic block defines.
    pub(super) fn dynamic_head(&mut self) -> Result<(usize, usize, usize), Error> {
        let len_syms = self.bits(5) as usize + 257;
        let dist_syms = self.bits(5) as usize + 1;
        let code_syms = self.bits(4) as usize + 4;
        if len_syms > 286 || dist_syms > 30 {
            return Err(Error::Corrupt);
        }
        Ok((len_syms, dist_syms, code_syms))
    }

    /// Decodes one code length symbol into `lengths`, from `index` on. Returns
    /// the index after the run of lengths it stood for.
    pub(super) fn code_lengths(
        &mut self,
        code: &Huffman,
        lengths: &mut [u8],
        index: usize,
    ) -> Result<usize, Error> {
        let sym = self.decode(code)?;
        let (len, repeat) = match sym {
            0..=15 => (sym as u8, 1),
            16 => {
                let prev = *lengths
                    .get(index.wrapping_sub(1))
                    .ok_or(Error::InvalidHuffmanTree)?;
                (prev, 3 + self.bits(2))
            }
            17 => (0, 3 + self.bits(3)),
            _ => (0, 11 + self.bits(7)),
        };
        let end = index + repeat as usize;
        lengths
            .get_mut(index..end)
            .ok_or(Error::InvalidHuffmanTree)?
            .fill(len);
        Ok(end)
    }

    /// Decodes a literal/length symbol, and outputs it if it is a literal.
    pub(super) fn length(&mut self, code: &Huffman) -> Result<Symbol, Error> {
        let sym = self.decode(code)? as u32;
        if sym < 256 {
            self.sink.put(sym as u8)?;
            return Ok(Symbol::Literal);
        }
        if sym == 256 {
            return Ok(Symbol::End);
        }

        // Lengths 3..=258 from symbols 257..=285: four symbols for each
        // count of extra bits, except at both ends.
        let sym = sym - 257;
        let len = match sym {
            0..=3 => sym + 3,
            4..=27 => {
                let extra = (sym - 4) >> 2;
                ((4 + (sym & 3)) << extra) + 3 + self.bits(extra) as u32
            }
            28 => 258,
            _ => return Err(Error::InvalidHuffmanTree),
        };
        Ok(Symbol::Match(len))
    }

    /// Decodes the distance of a match.
    pub(super) fn distance(&mut self, code: &Huffman) -> Result<u32, Error> {
        // Distances 1..=32768 from symbols 0..=29, two symbols for each
        // count of extra bits.
        let sym = self.decode(code)? as u32;
        let dist = match sym {
            0..=1 => sym + 1,
            2..=29 => {
                let extra = (sym - 2) >> 1;
                ((2 + (sym & 1)) << extra) + 1 + self.bits(extra) as u32
            }
            _ => return Err(Error::InvalidHuffmanTree),
        };
        self.ready()?;
        self.sink.check_dist(dist)?;
        Ok(dist)
    }

    pub(super) fn decode(&mut self, code: &Huffman) -> Result<u16, Error> {
        let mut bits = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for &count in &code.count.0[1..] {
            let count = count as i32;
            bits |= self.bits(1) as i32;
            if bits - count < first {
                // Checked here for the sake of the callers' loops.
                self.ready()?;
                return code
                    .symbol
                    .get((index + bits - first) as usize)
                    .copied()
                    .ok_or(Error::InvalidHuffmanTree);
            }
            index += count;
            first = (first + count) << 1;
            bits <<= 1;
        }
        Err(Error::InvalidHuffmanTree)
    }
}

impl<F: Format, const N: usize> Inflate<'_, Windowed<'_, F, N>> {
    /// Copies up to `len` bytes from `dist` back, as many as the output has
    /// room for. Returns how many are left.
    pub(super) fn copy(&mut self, dist: u32, len: u32) -> Result<u32, Error> {
        let n = (len as usize).min(self.sink.room());
        self.sink.copy(dist, n)?;
        Ok(len - n as u32)
    }
}
