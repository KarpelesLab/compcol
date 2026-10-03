//! The deflate decoder (RFC 1951).
//!
//! Huffman codes are decoded canonically, one bit at a time, from a count of
//! codes per length and a list of symbols sorted by code, in the manner of
//! zlib's `puff`. This is slower than table lookups but needs very little
//! code and only about 1.5 KiB of stack.

use super::{Checksum, Error, Input, Output};

const MAX_BITS: usize = 15;
/// Most literal/length symbols a block can define.
pub(crate) const MAX_LEN_SYMS: usize = 288;
/// Most distance symbols a block can define.
const MAX_DIST_SYMS: usize = 32;
pub(crate) const MAX_SYMS: usize = MAX_LEN_SYMS + MAX_DIST_SYMS;

/// How many codes there are of each length. Aligned so that clearing it is a
/// job for `memclr4`, which is linked anyway, rather than for another routine
/// of `compiler_builtins`.
#[repr(align(4))]
pub(crate) struct Counts([u16; MAX_BITS + 1]);

/// The storage of the two codes of a block: on the stack for the pull
/// decoder, in the context of the push decoder.
pub(crate) struct Tables {
    counts: [Counts; 2],
    symbol: [u16; MAX_SYMS],
}

impl Tables {
    pub(crate) const fn new() -> Self {
        Tables {
            counts: [Counts([0; MAX_BITS + 1]), Counts([0; MAX_BITS + 1])],
            symbol: [0; MAX_SYMS],
        }
    }

    /// The literal/length code and the distance code, to `build` or built.
    #[inline]
    pub(crate) fn codes(&mut self) -> (Huffman<'_>, Huffman<'_>) {
        let [len_count, dist_count] = &mut self.counts;
        let (len_symbol, dist_symbol) = self.symbol.split_at_mut(MAX_LEN_SYMS);
        (
            Huffman::new(len_count, len_symbol),
            Huffman::new(dist_count, dist_symbol),
        )
    }
}

/// Order in which the code length code lengths are stored.
pub(crate) const ORDER: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// The decoder: a bit reader over the input, which the containers also read
/// their headers and trailers through, the output and its checksum.
///
/// Whatever loops here is made of steps that are methods of their own, for
/// the push decoder to take one at a time: see `push`.
pub(crate) struct Inflate<'a, I, O, C> {
    pub(crate) input: &'a mut I,
    pub(crate) out: &'a mut O,
    pub(crate) check: C,
    pub(crate) bit_buf: u32,
    pub(crate) bit_cnt: u32,
    /// The first failure of the input. From then on it reads as zeros, which
    /// spares an error path at every read; see `bits`.
    pub(crate) status: Result<(), Error>,
}

/// A canonical Huffman code: `count[n]` codes of `n` bits each, and the
/// symbols they decode to, ordered by code.
pub(crate) struct Huffman<'a> {
    count: &'a mut Counts,
    symbol: &'a mut [u16],
    /// The number of unused codes: zero for a complete code, negative for an
    /// over-subscribed one.
    pub(crate) left: i32,
}

/// What a literal/length symbol stands for.
pub(crate) enum Symbol {
    /// A literal, which went to the output.
    Literal,
    /// The end of the block.
    End,
    /// A match of this length, whose distance follows.
    Match(u32),
}

impl<'a> Huffman<'a> {
    /// A code to `build`, over storage of the caller's.
    fn new(count: &'a mut Counts, symbol: &'a mut [u16]) -> Self {
        Huffman {
            count,
            symbol,
            left: 1,
        }
    }

    /// Builds the code from the code length of each symbol.
    pub(crate) fn build(&mut self, lengths: &[u8]) {
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
pub(crate) fn fixed_lengths(lengths: &mut [u8; MAX_SYMS]) {
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
/// Returns whether both codes are ones deflate permits.
pub(crate) fn build_codes(
    lengths: &[u8],
    len_syms: usize,
    len_code: &mut Huffman,
    dist_code: &mut Huffman,
) -> Result<bool, Error> {
    let (len_lengths, dist_lengths) = lengths
        .split_at_checked(len_syms)
        .ok_or(Error::InvalidBlock)?;
    len_code.build(len_lengths);
    dist_code.build(dist_lengths);
    if !len_code.is_valid(len_lengths.len()) || !dist_code.is_valid(dist_lengths.len()) {
        return Ok(false);
    }
    Ok(true)
}

impl<'a, I: Input, O: Output, C: Checksum> Inflate<'a, I, O, C> {
    pub(crate) fn new(input: &'a mut I, out: &'a mut O, check: C) -> Self {
        Inflate {
            input,
            out,
            check,
            bit_buf: 0,
            bit_cnt: 0,
            status: Ok(()),
        }
    }

    /// Runs `decode`, then reports the failure of the input if there was one,
    /// rather than whatever was made of the zeros read past it.
    pub(crate) fn run(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let result = decode(self);
        self.status.and(result)
    }

    /// Reads `need` bits, at most 16, least significant first.
    ///
    /// This cannot fail: once the input has, it is not asked again, `status`
    /// holds its error, and zeros are read. Callers only have to make sure
    /// that zeros get them to `run`'s verdict, without looping forever and
    /// without producing any output on the way. Zeros end every header field
    /// and make for an invalid stored block; the loops that could go on, or
    /// output something, check `status`.
    pub(crate) fn bits(&mut self, need: u32) -> u16 {
        while self.bit_cnt < need {
            if self.status.is_ok() {
                match self.input.byte() {
                    Ok(byte) => self.bit_buf |= (byte as u32) << self.bit_cnt,
                    Err(error) => self.status = Err(error),
                }
            }
            self.bit_cnt += 8;
        }
        let value = self.bit_buf & ((1 << need) - 1);
        self.bit_buf >>= need;
        self.bit_cnt -= need;
        value as u16
    }

    /// Skips to the next byte boundary.
    pub(crate) fn align(&mut self) {
        self.bits(self.bit_cnt & 7);
    }

    /// Skips `bytes` bytes. Only valid on a byte boundary.
    #[cfg(feature = "gzip")]
    pub(crate) fn skip(&mut self, bytes: u16) {
        for _ in 0..bytes {
            self.bits(8);
        }
    }

    /// Decodes one raw deflate stream and flushes the output. Leaves the input
    /// right after the stream, on a byte boundary.
    pub(crate) fn inflate(&mut self) -> Result<(), Error> {
        loop {
            let last = self.bits(1) != 0;
            match self.bits(2) {
                0 => self.stored()?,
                1 => self.fixed()?,
                2 => self.dynamic()?,
                3 => return Err(Error::InvalidBlock),
                _ => return Err(Error::Unsupported),
            }
            if last {
                break;
            }
        }
        // Input is only ever fetched a byte at a time, so the bits left over
        // are padding and nothing past the end of the stream was consumed.
        self.align();
        self.out.flush(&mut self.check)
    }

    fn stored(&mut self) -> Result<(), Error> {
        for _ in 0..self.stored_len()? {
            self.stored_byte()?;
        }
        Ok(())
    }

    /// Reads the length of a stored block.
    pub(crate) fn stored_len(&mut self) -> Result<u16, Error> {
        self.align();
        let len = self.bits(16);
        if self.bits(16) != !len {
            return Err(Error::InvalidBlock);
        }
        Ok(len)
    }

    /// Copies one byte of a stored block to the output.
    pub(crate) fn stored_byte(&mut self) -> Result<(), Error> {
        let byte = self.bits(8) as u8;
        self.status?;
        self.out.put(byte, &mut self.check)
    }

    fn fixed(&mut self) -> Result<(), Error> {
        let mut lengths = [0u8; MAX_SYMS];
        fixed_lengths(&mut lengths);
        self.compressed(&lengths, MAX_LEN_SYMS).map(drop)
    }

    fn dynamic(&mut self) -> Result<(), Error> {
        let (len_syms, dist_syms, code_syms) = self.dynamic_head()?;

        let mut lengths = [0u8; MAX_SYMS];
        for &sym in ORDER.iter().take(code_syms) {
            lengths[(sym & 31) as usize] = self.bits(3) as u8;
        }
        let mut count = Counts([0; MAX_BITS + 1]);
        let mut symbol = [0; 19];
        let mut code = Huffman::new(&mut count, &mut symbol);
        code.build(&lengths[..19]);
        if code.left != 0 {
            return Err(Error::InvalidCode);
        }

        // Literal/length code lengths, directly followed by the distance ones.
        let lengths = lengths
            .get_mut(..len_syms + dist_syms)
            .ok_or(Error::InvalidBlock)?;
        let mut index = 0;
        while index < lengths.len() {
            index = self.code_lengths(&code, lengths, index)?;
        }

        // A block without an end-of-block code could never finish.
        if lengths.get(256) == Some(&0) {
            return Err(Error::InvalidCode);
        }
        match self.compressed(lengths, len_syms)? {
            true => Ok(()),
            false => Err(Error::InvalidCode),
        }
    }

    /// Reads how many literal/length, distance and code length symbols a
    /// dynamic block defines.
    pub(crate) fn dynamic_head(&mut self) -> Result<(usize, usize, usize), Error> {
        let len_syms = self.bits(5) as usize + 257;
        let dist_syms = self.bits(5) as usize + 1;
        let code_syms = self.bits(4) as usize + 4;
        if len_syms > 286 || dist_syms > 30 {
            return Err(Error::InvalidBlock);
        }
        Ok((len_syms, dist_syms, code_syms))
    }

    /// Decodes one code length symbol into `lengths`, from `index` on. Returns
    /// the index after the run of lengths it stood for.
    pub(crate) fn code_lengths(
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
                    .ok_or(Error::InvalidCode)?;
                (prev, 3 + self.bits(2))
            }
            17 => (0, 3 + self.bits(3)),
            _ => (0, 11 + self.bits(7)),
        };
        let end = index + repeat as usize;
        lengths
            .get_mut(index..end)
            .ok_or(Error::InvalidCode)?
            .fill(len);
        Ok(end)
    }

    /// Decodes a compressed block given the code length of each literal/length
    /// symbol, directly followed by those of the distance symbols. Returns
    /// whether both codes were ones deflate permits.
    fn compressed(&mut self, lengths: &[u8], len_syms: usize) -> Result<bool, Error> {
        let mut tables = Tables::new();
        let (mut len_code, mut dist_code) = tables.codes();
        if !build_codes(lengths, len_syms, &mut len_code, &mut dist_code)? {
            return Ok(false);
        }

        loop {
            match self.length(&len_code)? {
                Symbol::Literal => {}
                Symbol::End => return Ok(true),
                Symbol::Match(len) => self.distance(&dist_code, len)?,
            }
        }
    }

    /// Decodes a literal/length symbol, and outputs it if it is a literal.
    pub(crate) fn length(&mut self, code: &Huffman) -> Result<Symbol, Error> {
        let sym = self.decode(code)? as u32;
        if sym < 256 {
            self.out.put(sym as u8, &mut self.check)?;
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
            _ => return Err(Error::InvalidCode),
        };
        Ok(Symbol::Match(len))
    }

    /// Decodes the distance of a match of `len` bytes, and outputs the match.
    pub(crate) fn distance(&mut self, code: &Huffman, len: u32) -> Result<(), Error> {
        // Distances 1..=32768 from symbols 0..=29, two symbols for each
        // count of extra bits.
        let sym = self.decode(code)? as u32;
        let dist = match sym {
            0..=1 => sym + 1,
            2..=29 => {
                let extra = (sym - 2) >> 1;
                ((2 + (sym & 1)) << extra) + 1 + self.bits(extra) as u32
            }
            _ => return Err(Error::InvalidCode),
        };

        self.status?;
        self.out.copy(dist as usize, len as usize, &mut self.check)
    }

    fn decode(&mut self, code: &Huffman) -> Result<u16, Error> {
        let mut bits = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for &count in &code.count.0[1..] {
            let count = count as i32;
            bits |= self.bits(1) as i32;
            if bits - count < first {
                // Checked here for the sake of the callers' loops.
                self.status?;
                return code
                    .symbol
                    .get((index + bits - first) as usize)
                    .copied()
                    .ok_or(Error::InvalidCode);
            }
            index += count;
            first = (first + count) << 1;
            bits <<= 1;
        }
        Err(Error::InvalidCode)
    }
}
