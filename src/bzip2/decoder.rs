//! bzip2 streaming decoder.
//!
//! Strategy: we buffer the compressed input into an internal `Vec<u8>`
//! and walk it with a bit cursor. A block's header (CRC, origin, symbol
//! map, selectors, code tables) is parsed speculatively — if the
//! `BitReader` runs out mid-header we rewind and wait for more input —
//! and its Huffman symbols are then decoded incrementally, keeping the
//! decode state across calls, so a block arriving in small pieces is
//! never re-parsed. (The reference bzip2 source suspends its state
//! machine at any bit for the same effect.)
//!
//! Once a block's end-of-block symbol is seen we invert MTF, BWT and
//! the optional randomisation, and keep the result (at most the block
//! size, 900 kB). The last step, the inverse of RLE-1, is run straight
//! into the caller's output buffer as it drains, as libbzip2 does: a
//! block of maximal runs expands 51-fold, and materialising that would
//! hold tens of megabytes whatever output limit the caller applies. The
//! block CRC is therefore computed over the bytes as they are handed
//! out and checked once the block is exhausted, so a corrupt block's
//! bytes are emitted before the mismatch is reported (again as
//! libbzip2).
//!
//! What is accepted follows libbzip2 (`decompress.c`), not a stricter
//! reading of the format: code tables need not be complete prefix codes
//! (only a code the stream actually uses must decode), selectors past
//! the 18002 that can ever be used are ignored, and blocks with the
//! long-obsolete "randomised" bit (written by bzip2 0.9.0/0.9.5 for very
//! repetitive data) are de-randomised.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitReader;
use super::bwt::bwt_inverse;
use super::crc::Crc32;
use super::huffman::{DecodeTable, MAX_CODE_LEN};
use super::mtf::mtf_inverse_reduced;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const STREAM_END_MAGIC: u64 = 0x1772_4538_5090;

/// Selectors beyond this many can never be used (a block holds at most
/// 900 000 symbols plus EOB, in groups of 50); libbzip2 reads and drops
/// them, since some encoders round the count up.
const MAX_SELECTORS: usize = 18002;

/// How much of the caller's input is copied into `in_buf` at a time, and
/// how far the parser may get into `in_buf` before the bytes behind it
/// are dropped. Input is only taken when the parser has run dry, so a
/// call copies at most one window more than it consumes.
const INPUT_WINDOW: usize = 64 * 1024;

/// Upper bound, in bits, on a block header (everything between the block
/// magic and the first Huffman symbol); a longer one is `Error::Corrupt`.
///
/// The format itself sets no limit: each code length is reached from the
/// previous one by `+1`/`-1` steps, and nothing stops a stream stepping
/// up and down forever (libbzip2 keeps reading too), which would have us
/// buffer input without end while waiting for the header to finish. But
/// everything else in a header is bounded, and an encoder that steps
/// straight from one length to the next needs little:
///
/// * CRC, randomised bit, origin, symbol map, table and selector counts:
///   `32 + 1 + 24 + 16 + 16 * 16 + 3 + 15` = 347 bits;
/// * selectors: at most 32 767 (a 15-bit count) of at most 6 bits;
/// * code lengths: at most 6 tables of 258 symbols, each 5 bits to start
///   and, per symbol, at most 19 steps of 2 bits (lengths stay within
///   1..=20) and a stop bit.
///
/// That is 347 + 196 602 + 60 402 bits, under 32 KiB. 256 KiB leaves any
/// plausible encoder a wide margin and still keeps the decoder's input
/// buffer small.
const MAX_BLOCK_HEADER_BITS: usize = 8 * 256 * 1024;

/// bzip2 decoder configuration.
///
/// `#[non_exhaustive]`: construct via [`DecoderConfig::default`] and the
/// `with_*` builders rather than a struct literal, so new options can be
/// added in future without breaking downstream code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecoderConfig {
    /// Decode concatenated streams (`cat a.bz2 b.bz2`, pbzip2/lbzip2
    /// output) as one output, like `bzip2 -d`. Default `true`.
    ///
    /// With `false` the decoder stops at the end of the first stream,
    /// like `BZ2_bzDecompress` (and PHP's `bzdecompress`): `decode`
    /// returns `StreamEnd` as soon as the stream's trailer is read and
    /// leaves every byte after it unconsumed, so the caller can tell
    /// exactly where the bzip2 data ended. With `true` the end is only
    /// known once the bytes after a trailer turn out not to be another
    /// stream (or `finish` says there are none).
    pub multi_stream: bool,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self { multi_stream: true }
    }
}

impl DecoderConfig {
    /// Set [`multi_stream`](Self::multi_stream).
    pub fn with_multi_stream(mut self, multi_stream: bool) -> Self {
        self.multi_stream = multi_stream;
        self
    }
}

/// libbzip2's `BZ2_rNums` (`randtable.c`, © 1996-2019 Julian Seward):
/// the gaps between the bytes a randomised block flips.
const RNUMS: [u16; 512] = [
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949,
    214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680,
    480, 51, 878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807,
    591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476,
    693, 425, 174, 647, 73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874,
    474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604, 958, 533,
    221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553, 163,
    354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68,
    770, 919, 190, 373, 294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715,
    67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99, 820,
    908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626,
    789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250, 170, 774, 972, 275, 999, 639, 495,
    78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694, 363, 992,
    809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511,
    655, 814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268,
    926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656,
    610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879,
    194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679, 297,
    59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430,
    305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790,
    288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293,
    465, 502, 56, 661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286,
    215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645,
    210, 389, 550, 919, 135, 780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713,
    857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
];

/// Coarse decoder phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading 4-byte stream header `BZh<level>`.
    Header,
    /// Between blocks: poised to read either the block magic (and the
    /// block header after it) or the stream-end magic.
    BlockOrEnd,
    /// Block header parsed; decoding its Huffman symbols, state in
    /// `block`.
    Symbols,
    /// A block is decoded and waiting in `out` to be drained.
    DrainDecoded,
    /// End-of-stream magic seen; reading combined CRC.
    StreamCrc,
    /// A stream's combined CRC checked out. Like `bzip2 -d`, another
    /// `BZh<level>` stream may follow (`cat a.bz2 b.bz2`, pbzip2/lbzip2
    /// output); the next bytes decide between that and `Done` (anything
    /// else is trailing garbage, ignored as the reference tool does).
    /// Only reached with [`DecoderConfig::multi_stream`].
    BetweenStreams,
    /// Stream successfully terminated; return `done=true`.
    Done,
}

/// A block whose header has been read and whose symbols are being
/// decoded.
struct BlockDecode {
    stored_crc: u32,
    randomised: bool,
    origin: u32,
    /// The bytes in use, ascending: the initial MTF list.
    alphabet: Vec<u8>,
    selectors: Vec<u8>,
    tables: Vec<DecodeTable>,
    /// Upper bound on the block's length after RLE-2 (libbzip2's
    /// `nblockMAX`): a block never holds more than the declared size,
    /// which also stops a stream of huge zero-runs from inflating
    /// memory before any output (or `LimitedDecoder`) sees it.
    max_len: usize,
    /// MTF indices decoded so far (the RLE-2 runs expanded).
    mtf_indices: Vec<u8>,
    group_idx: usize,
    symbols_in_group: usize,
    /// The zero-run being accumulated from RUNA/RUNB symbols.
    zero_run: u32,
    zero_weight: u32,
}

/// A decoded block, as it came out of the inverse BWT (and
/// de-randomisation): still RLE-1 coded, and expanded on the way out.
struct BlockOut {
    data: Vec<u8>,
    /// Next byte of `data` to read.
    pos: usize,
    /// The byte of the current run.
    last: u8,
    /// Length so far of the current run of equal bytes in `data`, 0..=4.
    /// After four, the next byte of `data` is a repeat count.
    run: u8,
    /// Copies of `last` still owed from a repeat count.
    repeat: u8,
    /// CRC of the bytes handed out so far.
    crc: Crc32,
    stored_crc: u32,
}

impl BlockOut {
    /// Expand into `output[*written..]`, advancing `written`. Returns
    /// `true` once the whole block has been handed out.
    fn expand(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let start = *written;
        let mut w = start;
        loop {
            if self.repeat > 0 {
                let n = (self.repeat as usize).min(output.len() - w);
                if n == 0 {
                    break;
                }
                output[w..w + n].fill(self.last);
                self.repeat -= n as u8;
                w += n;
                continue;
            }
            let Some(&b) = self.data.get(self.pos) else {
                break;
            };
            if self.run == 4 {
                // The count after four equal bytes. (A block may end
                // right after the four, with no count: libbzip2 takes
                // that too.) Taken even when the output is full, so a
                // block is never left pending with nothing to emit.
                self.pos += 1;
                self.repeat = b;
                self.run = 0;
                continue;
            }
            if w == output.len() {
                break;
            }
            self.pos += 1;
            if self.run > 0 && b == self.last {
                self.run += 1;
            } else {
                self.last = b;
                self.run = 1;
            }
            output[w] = b;
            w += 1;
        }
        self.crc.update(&output[start..w]);
        *written = w;
        self.pos == self.data.len() && self.repeat == 0
    }
}

pub struct Decoder {
    config: DecoderConfig,

    /// Buffered compressed bytes — bzip2's bit stream is variable-rate
    /// and our parser needs random access, so we accumulate.
    in_buf: Vec<u8>,
    /// Position (in **bits** from the start of in_buf) of the parser.
    /// Everything before `bit_pos / 8` is no longer needed.
    bit_pos: usize,

    /// The decoded block being delivered to the caller, in
    /// `Phase::DrainDecoded`.
    out: Option<BlockOut>,

    /// The block being decoded, in `Phase::Symbols`.
    block: Option<Box<BlockDecode>>,

    /// Running combined CRC across already-decoded blocks. Matched
    /// against the stream footer at the end.
    combined_crc: u32,

    /// Header level digit (1..=9): bounds each block's size.
    level: u8,

    phase: Phase,
    poisoned: bool,

    /// Set by `finish`: no more input will arrive, so a partial
    /// `BZh` prefix after a stream is trailing garbage and a gated block
    /// header parse must be attempted now.
    finishing: bool,
    /// `in_buf.len()` that must be reached before the speculative block
    /// header parse is retried after it ran out of input. Each failed
    /// attempt re-parses the whole header, which a hostile stream can
    /// make arbitrarily long (code-length deltas may go up and down
    /// forever), so retrying on every new byte would be quadratic;
    /// requiring 1/8 more input per retry bounds the total work at a
    /// constant multiple of the header size.
    retry_at: usize,

    /// Total bytes ever copied into `in_buf`, for the tests.
    #[cfg(test)]
    copied_in: usize,
}

impl Decoder {
    pub fn new() -> Self {
        Self::with_config(DecoderConfig::default())
    }

    pub fn with_config(config: DecoderConfig) -> Self {
        Self {
            config,
            in_buf: Vec::new(),
            bit_pos: 0,
            out: None,
            block: None,
            combined_crc: 0,
            level: 0,
            phase: Phase::Header,
            poisoned: false,
            finishing: false,
            retry_at: 0,
            #[cfg(test)]
            copied_in: 0,
        }
    }

    /// Decoded bytes held for the caller, for the tests.
    #[cfg(test)]
    fn buffered_out(&self) -> usize {
        self.out.as_ref().map_or(0, |o| o.data.len())
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Try to make progress: parse whatever the buffered input
    /// supports, populating `self.out`. Returns `Ok(true)` if we
    /// made any state-machine progress, `Ok(false)` if we genuinely
    /// need more input or the decoded bytes must be drained first.
    fn step(&mut self) -> Result<bool, Error> {
        let r = match self.phase {
            Phase::Header => self.try_header(),
            Phase::BlockOrEnd => self.try_block_or_end(),
            Phase::Symbols => self.decode_symbols(),
            Phase::DrainDecoded => Ok(false), // caller drains, then we advance from BlockOrEnd
            Phase::StreamCrc => self.try_stream_crc(),
            Phase::BetweenStreams => self.try_between_streams(),
            Phase::Done => Ok(false),
        };
        r.map_err(|e| self.poison(e))
    }

    fn try_header(&mut self) -> Result<bool, Error> {
        // Need at least 4 bytes for "BZh<level>".
        let off = self.bit_pos / 8;
        if self.in_buf.len() - off < 4 {
            return Ok(false);
        }
        if &self.in_buf[off..off + 3] != b"BZh" {
            return Err(Error::BadHeader);
        }
        let lvl = self.in_buf[off + 3];
        if !(b'1'..=b'9').contains(&lvl) {
            return Err(Error::BadHeader);
        }
        self.level = lvl - b'0';
        self.bit_pos += 32;
        self.phase = Phase::BlockOrEnd;
        Ok(true)
    }

    fn try_block_or_end(&mut self) -> Result<bool, Error> {
        // The 48-bit magic, wherever in a byte it starts.
        let available_bits = self.in_buf.len() * 8 - self.bit_pos;
        if available_bits < 48 {
            return Ok(false);
        }
        let mut br = BitReader::new_at(&self.in_buf, self.bit_pos);
        let magic = br.read_bits_48()?;
        if magic == BLOCK_MAGIC {
            if !self.finishing && self.in_buf.len() < self.retry_at {
                // Not enough new input since the last failed attempt.
                return Ok(false);
            }
            // Parse the block header; if it runs past the buffered
            // input, stay before the magic and ask for more.
            match self.read_block_header(br.position()) {
                Ok((block, pos)) => {
                    self.retry_at = 0;
                    self.bit_pos = pos;
                    self.block = Some(Box::new(block));
                    self.phase = Phase::Symbols;
                    Ok(true)
                }
                Err(Error::UnexpectedEnd) => {
                    let parsed = self.in_buf.len() - self.bit_pos / 8;
                    self.retry_at = self.in_buf.len() + (parsed / 8).max(1);
                    Ok(false)
                }
                Err(e) => Err(e),
            }
        } else if magic == STREAM_END_MAGIC {
            self.bit_pos = br.position();
            self.phase = Phase::StreamCrc;
            Ok(true)
        } else {
            // A bad stream magic ("BZh") is a header error, a bad block
            // magic is corrupt data: libbzip2 reports BZ_DATA_ERROR_MAGIC
            // and BZ_DATA_ERROR respectively.
            Err(Error::Corrupt)
        }
    }

    fn try_stream_crc(&mut self) -> Result<bool, Error> {
        let available_bits = self.in_buf.len() * 8 - self.bit_pos;
        if available_bits < 32 {
            return Ok(false);
        }
        let mut br = BitReader::new_at(&self.in_buf, self.bit_pos);
        let expected = br.read_bits(32)?;
        if expected != self.combined_crc {
            return Err(Error::ChecksumMismatch);
        }
        // Advance to the next byte boundary; bzip2 pads the trailer
        // with zero bits up to a byte boundary.
        self.bit_pos = br.position().next_multiple_of(8);
        self.phase = if self.config.multi_stream {
            Phase::BetweenStreams
        } else {
            Phase::Done
        };
        Ok(true)
    }

    fn try_between_streams(&mut self) -> Result<bool, Error> {
        let avail = &self.in_buf[self.bit_pos / 8..];
        let n = avail.len().min(3);
        if avail[..n] != b"BZh"[..n] {
            // Trailing garbage: the stream is over.
            self.phase = Phase::Done;
            return Ok(true);
        }
        if avail.len() < 4 {
            if self.finishing {
                // No more input: nothing (or a lone partial magic) follows.
                self.phase = Phase::Done;
                return Ok(true);
            }
            return Ok(false);
        }
        if (b'1'..=b'9').contains(&avail[3]) {
            // Another stream: its combined CRC starts afresh.
            self.combined_crc = 0;
            self.phase = Phase::Header;
        } else {
            self.phase = Phase::Done;
        }
        Ok(true)
    }

    /// Parse a block header starting at bit `pos` (just after the
    /// 48-bit block magic). Returns the block's decode state and the
    /// bit position of its first Huffman symbol.
    ///
    /// Returns `Err(Error::UnexpectedEnd)` to signal "more input
    /// needed"; other errors are real failures.
    fn read_block_header(&self, pos: usize) -> Result<(BlockDecode, usize), Error> {
        let mut br = BitReader::new_at(&self.in_buf, pos);

        let stored_crc = br.read_bits(32)?;
        let randomised = br.read_bit()? != 0;
        let origin = br.read_bits(24)?;

        // Symbol map.
        let stripe_top = br.read_bits(16)?;
        let mut alphabet: Vec<u8> = Vec::with_capacity(64);
        for stripe in 0..16 {
            let stripe_used = stripe_top & (1 << (15 - stripe)) != 0;
            if !stripe_used {
                continue;
            }
            let mask = br.read_bits(16)?;
            for byte in 0..16 {
                if mask & (1 << (15 - byte)) != 0 {
                    alphabet.push(((stripe << 4) | byte) as u8);
                }
            }
        }
        if alphabet.is_empty() {
            return Err(Error::Corrupt);
        }
        let alpha_size = alphabet.len() + 2; // RUNA/RUNB merged + EOB

        let num_tables = br.read_bits(3)? as usize;
        if !(2..=6).contains(&num_tables) {
            return Err(Error::Corrupt);
        }
        let num_selectors = br.read_bits(15)? as usize;
        if num_selectors == 0 {
            return Err(Error::Corrupt);
        }

        // Read MTF-coded selectors: each is a unary count of 1-bits
        // followed by a 0 stop-bit; that count is the MTF position
        // (0..num_tables). Ones past MAX_SELECTORS are read and dropped.
        let mut mtf_list: Vec<u8> = (0..num_tables as u8).collect();
        let mut selectors: Vec<u8> = Vec::with_capacity(num_selectors.min(MAX_SELECTORS));
        for _ in 0..num_selectors {
            let mut pos = 0;
            loop {
                if pos >= num_tables {
                    return Err(Error::Corrupt);
                }
                let bit = br.read_bit()?;
                if bit == 0 {
                    break;
                }
                pos += 1;
            }
            if selectors.len() < MAX_SELECTORS {
                let v = mtf_list.remove(pos);
                selectors.push(v);
                mtf_list.insert(0, v);
            }
        }

        // Per-table code-length tables.
        let mut tables: Vec<DecodeTable> = Vec::with_capacity(num_tables);
        for _ in 0..num_tables {
            let mut cur = br.read_bits(5)? as i32;
            if !(1..=(MAX_CODE_LEN as i32)).contains(&cur) {
                return Err(Error::Corrupt);
            }
            let mut lens = vec![0u8; alpha_size];
            for symbol_len in lens.iter_mut() {
                loop {
                    let b = br.read_bit()?;
                    if b == 0 {
                        break;
                    }
                    // Read another bit: 0 = +1, 1 = -1.
                    let dir = br.read_bit()?;
                    if dir == 0 {
                        cur += 1;
                    } else {
                        cur -= 1;
                    }
                    if !(1..=(MAX_CODE_LEN as i32)).contains(&cur) {
                        return Err(Error::Corrupt);
                    }
                    // The one loop in a header that the format does
                    // not bound.
                    if br.position() - pos > MAX_BLOCK_HEADER_BITS {
                        return Err(Error::Corrupt);
                    }
                }
                *symbol_len = cur as u8;
            }
            tables.push(DecodeTable::from_lengths(&lens)?);
        }

        let block = BlockDecode {
            stored_crc,
            randomised,
            origin,
            alphabet,
            selectors,
            tables,
            max_len: self.level as usize * 100_000,
            mtf_indices: Vec::new(),
            group_idx: 0,
            symbols_in_group: 0,
            zero_run: 0,
            zero_weight: 1,
        };
        Ok((block, br.position()))
    }

    /// Decode as many of the current block's symbols as the buffered
    /// input holds. On the end-of-block symbol, reconstruct the block
    /// (up to the inverse BWT) into `out`.
    fn decode_symbols(&mut self) -> Result<bool, Error> {
        let mut blk = self.block.take().expect("Symbols phase without a block");
        let start = self.bit_pos;
        let mut br = BitReader::new_at(&self.in_buf, self.bit_pos);
        let num_used = blk.alphabet.len();
        let eob = (num_used + 1) as u16;

        // Decode symbols 50 at a time, switching tables per group per
        // selector, until EOB. Each RUNA/RUNB extends the current
        // zero-run; a non-zero symbol materialises the run as that many
        // zero MTF indices and then pushes its own MTF index.
        let ended = loop {
            if blk.symbols_in_group == 0 {
                if blk.group_idx >= blk.selectors.len() {
                    return Err(Error::Corrupt);
                }
                blk.symbols_in_group = 50;
            }
            let at = br.position();
            let tbl = &blk.tables[blk.selectors[blk.group_idx] as usize];
            let s = match tbl.decode_symbol(&mut br) {
                Ok(s) => s,
                Err(Error::UnexpectedEnd) => {
                    // Resume at this symbol once more input arrives.
                    self.bit_pos = at;
                    break false;
                }
                Err(e) => return Err(e),
            };
            blk.symbols_in_group -= 1;
            if blk.symbols_in_group == 0 {
                blk.group_idx += 1;
            }

            if s == eob {
                self.bit_pos = br.position();
                break true;
            }

            if s <= 1 {
                let contrib = if s == 0 { 1 } else { 2 };
                blk.zero_run = blk.zero_run.saturating_add(contrib * blk.zero_weight);
                blk.zero_weight = blk.zero_weight.saturating_mul(2);
                // The materialised indices plus the in-flight zero-run
                // must stay within the block size. This catches both a
                // single oversized run and the death-by-a-thousand-runs
                // stream where each non-zero symbol flushes and resets a
                // fresh one.
                if blk.mtf_indices.len() + blk.zero_run as usize > blk.max_len {
                    return Err(Error::Corrupt);
                }
            } else {
                if blk.zero_run > 0 {
                    let run = blk.zero_run as usize;
                    blk.mtf_indices.extend(core::iter::repeat_n(0u8, run));
                    blk.zero_run = 0;
                    blk.zero_weight = 1;
                }
                // s >= 2 → MTF index (s - 1) in 1..=num_used-1.
                let idx = (s - 1) as usize;
                if idx >= num_used || blk.mtf_indices.len() >= blk.max_len {
                    return Err(Error::Corrupt);
                }
                blk.mtf_indices.push(idx as u8);
            }
        };
        if !ended {
            let progressed = self.bit_pos != start;
            self.block = Some(blk);
            return Ok(progressed);
        }

        if blk.zero_run > 0 {
            let run = blk.zero_run as usize;
            blk.mtf_indices.extend(core::iter::repeat_n(0u8, run));
        }

        // mtf_indices is the L-column-after-MTF stream; invert MTF, then
        // invert BWT, then the randomisation. RLE-1 is undone as the
        // block drains, and the block CRC checked at its end.
        let l_column = mtf_inverse_reduced(&blk.mtf_indices, &blk.alphabet);
        drop(blk.mtf_indices);
        if blk.origin as usize >= l_column.len() {
            return Err(Error::Corrupt);
        }
        let mut bwt = bwt_inverse(&l_column, blk.origin);
        if blk.randomised {
            derandomise(&mut bwt);
        }
        self.out = Some(BlockOut {
            data: bwt,
            pos: 0,
            last: 0,
            run: 0,
            repeat: 0,
            crc: Crc32::new(),
            stored_crc: blk.stored_crc,
        });
        self.phase = Phase::DrainDecoded;
        Ok(true)
    }

    /// Drain and parse until the output is full, the stream is over, or
    /// the buffered input runs out. Returns whether it stopped for want
    /// of input.
    fn run(&mut self, output: &mut [u8], written: &mut usize) -> Result<bool, Error> {
        loop {
            // Hand out the decoded block, as far as the output allows.
            self.drain(output, written)?;
            if matches!(self.phase, Phase::Done) {
                return Ok(false);
            }
            if *written == output.len() && !output.is_empty() {
                // Output full: let the caller drain.
                return Ok(false);
            }
            if !self.step()? {
                // In `DrainDecoded`, decoded bytes are waiting but the
                // output is empty-sized.
                return Ok(self.phase != Phase::DrainDecoded);
            }
        }
    }

    /// Expand the pending block into the output. Once all of it is out,
    /// check its CRC and move on to whatever follows the block.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> Result<(), Error> {
        let Some(out) = self.out.as_mut() else {
            return Ok(());
        };
        if !out.expand(output, written) {
            return Ok(());
        }
        let (computed, stored) = (out.crc.value(), out.stored_crc);
        self.out = None;
        if computed != stored {
            return Err(self.poison(Error::ChecksumMismatch));
        }
        // Update combined CRC: rotate-left then XOR.
        self.combined_crc = self.combined_crc.rotate_left(1) ^ stored;
        self.phase = Phase::BlockOrEnd;
        Ok(())
    }
}

/// Undo a randomised block's bit flips (libbzip2's `BZ_RAND_UPD_MASK` /
/// `BZ_RAND_MASK`), over the block after inverse BWT and before RLE-1:
/// the low bit of every byte at a position the `RNUMS` gaps land on is
/// inverted.
fn derandomise(block: &mut [u8]) {
    let mut to_go: u32 = 0;
    let mut t_pos = 0usize;
    for b in block.iter_mut() {
        if to_go == 0 {
            to_go = RNUMS[t_pos] as u32;
            t_pos = (t_pos + 1) % RNUMS.len();
        }
        to_go -= 1;
        if to_go == 1 {
            *b ^= 1;
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        // How much of `input` has been copied into `in_buf`.
        let mut taken = 0usize;

        // Parse what is buffered, and take input only once the parser
        // has run dry, a window at a time. A caller may pass everything
        // it has left on every call; copying all of that in just to hand
        // most of it back would cost (calls x remaining input).
        let starved = loop {
            if !self.run(output, &mut written)? {
                break false;
            }
            if taken == input.len() {
                break true;
            }
            // Drop the prefix the parser is done with. What stays is at
            // most a partial block header, so `in_buf` stays bounded by
            // `MAX_BLOCK_HEADER_BITS` and a few windows however much
            // input goes by (and its length in bits fits a 32-bit usize).
            let off = self.bit_pos / 8;
            if off >= INPUT_WINDOW {
                self.in_buf.drain(..off);
                self.bit_pos -= off * 8;
                self.retry_at = self.retry_at.saturating_sub(off);
            }
            let n = (input.len() - taken).min(INPUT_WINDOW);
            self.in_buf.extend_from_slice(&input[taken..taken + n]);
            taken += n;
            #[cfg(test)]
            {
                self.copied_in += n;
            }
        };

        // Unless the parser is waiting for more input (in which case it
        // needs everything buffered), the bytes past its position are
        // not ours yet — the next block, or whatever follows the
        // stream. Hand back the ones that came from this call so the
        // caller can see where the bzip2 data stops and pass the rest
        // again; bytes from earlier calls were already reported
        // consumed. Without `multi_stream`, the end of the stream is
        // thus exact.
        let mut consumed = taken;
        if !starved {
            let frontier = self.bit_pos.div_ceil(8);
            let give_back = (self.in_buf.len() - frontier).min(consumed);
            self.in_buf.truncate(self.in_buf.len() - give_back);
            consumed -= give_back;
        }

        Ok(RawProgress {
            consumed,
            written,
            done: matches!(self.phase, Phase::Done),
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        self.finishing = true;
        let p = self.raw_decode(&[], output)?;
        if p.done {
            Ok(p)
        } else if output.is_empty() || p.written > 0 {
            // A decoded block can be larger than the caller's buffer: the
            // input may be fully absorbed while decoded bytes are still
            // pending. `finish` must stay drainable — report
            // "not done" so the caller drains and calls again. Only a call
            // with nothing left to hand over reports a truncated stream;
            // failing earlier dropped the bytes written this call.
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: false,
            })
        } else {
            // We're not done, nothing is left to hand over, and there is
            // no input left to advance with — truncated stream.
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.bit_pos = 0;
        self.out = None;
        self.block = None;
        self.combined_crc = 0;
        self.level = 0;
        self.phase = Phase::Header;
        self.poisoned = false;
        self.finishing = false;
        self.retry_at = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bzip2::{Encoder, EncoderConfig};
    use crate::traits::RawEncoder;

    /// Deterministic incompressible bytes.
    fn noise(n: usize) -> Vec<u8> {
        let mut x: u32 = 0x9E37_79B9;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    fn encode(plain: &[u8], level: u8) -> Vec<u8> {
        let mut enc = Encoder::with_config(EncoderConfig { level });
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut pos = 0;
        while pos < plain.len() {
            let p = enc.raw_encode(&plain[pos..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            pos += p.consumed;
        }
        loop {
            let p = enc.raw_finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            if p.done {
                break;
            }
        }
        out
    }

    /// A caller that passes everything it has left on each call (as
    /// `vec::decompress_to_vec` does) must not make the decoder copy the
    /// whole remainder every time: the bytes taken into `in_buf` stay
    /// proportional to the stream, whatever follows it.
    #[test]
    fn whole_remaining_input_per_call_is_not_recopied() {
        let plain = noise(300_000);
        let stream = encode(&plain, 1); // several 100 kB blocks
        let mut input = stream.clone();
        input.resize(stream.len() + (4 << 20), 0xA5); // trailing junk

        let mut dec = Decoder::new();
        let mut buf = [0u8; 1024];
        let mut got = Vec::new();
        let mut pos = 0;
        loop {
            let p = dec.raw_decode(&input[pos..], &mut buf).unwrap();
            got.extend_from_slice(&buf[..p.written]);
            pos += p.consumed;
            assert!(dec.in_buf.len() <= 1 << 20, "in_buf {}", dec.in_buf.len());
            if p.done {
                break;
            }
            assert!(p.consumed > 0 || p.written > 0, "stalled at {pos}");
        }
        assert!(got == plain);
        assert_eq!(pos, stream.len());
        assert!(
            dec.copied_in <= 3 * stream.len(),
            "copied {} bytes for a {}-byte stream",
            dec.copied_in,
            stream.len()
        );
    }

    /// `(b"a" * 259 + b"b" * 259) * 88803` through `bzip2 -9`: every
    /// run is the longest RLE-1 can code (four bytes and a count of
    /// 255), so 146 bytes decode to 46 MB.
    const MAX_RUNS_9: [u8; 146] = [
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x05, 0x0a, 0x41, 0xfd, 0x02,
        0x0f, 0x55, 0x41, 0x00, 0xc0, 0x00, 0x30, 0x00, 0x00, 0x08, 0x20, 0x00, 0x90, 0x19, 0xa6,
        0x82, 0x6a, 0xa6, 0xd4, 0xe1, 0x50, 0x12, 0xea, 0x15, 0x01, 0x2d, 0x52, 0x80, 0x96, 0x15,
        0x01, 0x2e, 0xa8, 0x90, 0x55, 0x59, 0x24, 0x82, 0xaa, 0xc2, 0xa0, 0x25, 0x85, 0x40, 0x4b,
        0x92, 0x48, 0x2a, 0xad, 0x52, 0x80, 0x97, 0x85, 0x40, 0x4b, 0xe6, 0x28, 0x2b, 0x24, 0xca,
        0x6b, 0x27, 0xcd, 0xb1, 0x69, 0xa0, 0x40, 0x2a, 0x78, 0x20, 0x18, 0x00, 0x06, 0x00, 0x00,
        0x01, 0x04, 0x00, 0x12, 0x20, 0xa5, 0x00, 0x52, 0xa6, 0xd4, 0xe2, 0xa1, 0x49, 0x38, 0x2a,
        0x14, 0x93, 0x52, 0x85, 0x24, 0xc5, 0x42, 0x92, 0x74, 0x24, 0x80, 0x31, 0x24, 0x80, 0x31,
        0x50, 0xa4, 0x98, 0xa8, 0x52, 0x4e, 0x24, 0x90, 0x07, 0x52, 0x85, 0x24, 0xc2, 0xa1, 0x49,
        0x3c, 0x5d, 0xc9, 0x14, 0xe1, 0x42, 0x40, 0xd1, 0xe4, 0x22, 0xdc,
    ];

    /// A block of maximal runs expands 51-fold. The decoder must not
    /// hold the expansion: what it keeps per block is bounded by the
    /// block size, and the rest goes straight to the caller, whose
    /// output limit (here 1 KiB a call) is thus honoured.
    #[test]
    fn run_expansion_is_not_materialised() {
        const TOTAL: usize = 518 * 88803;
        let mut dec = Decoder::new();
        let mut buf = [0u8; 1024];
        let mut input = &MAX_RUNS_9[..];
        let mut total = 0usize;
        let mut max_held = 0usize;
        loop {
            let p = if input.is_empty() {
                dec.raw_finish(&mut buf).unwrap()
            } else {
                dec.raw_decode(input, &mut buf).unwrap()
            };
            input = &input[p.consumed..];
            max_held = max_held.max(dec.buffered_out());
            // The output is runs of 259: a, b, a, b, ...
            let mut chunk = &buf[..p.written];
            while !chunk.is_empty() {
                let in_run = total % 259;
                let n = (259 - in_run).min(chunk.len());
                let want = if (total / 259).is_multiple_of(2) {
                    b'a'
                } else {
                    b'b'
                };
                assert!(chunk[..n] == [want; 259][..n], "at {total}");
                total += n;
                chunk = &chunk[n..];
            }
            if p.done {
                break;
            }
            assert!(
                p.consumed > 0 || p.written > 0 || input.is_empty(),
                "stalled at {total}"
            );
        }
        assert_eq!(total, TOTAL);
        assert!(input.is_empty());
        // A level-9 block is at most 900 000 bytes before expansion.
        assert!(max_held <= 900_000, "held {max_held} decoded bytes");
    }

    fn expand_all(data: &[u8], out_chunk: usize) -> (Vec<u8>, u32) {
        let mut blk = BlockOut {
            data: data.to_vec(),
            pos: 0,
            last: 0,
            run: 0,
            repeat: 0,
            crc: Crc32::new(),
            stored_crc: 0,
        };
        let mut got = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        loop {
            let mut w = 0;
            let done = blk.expand(&mut buf, &mut w);
            got.extend_from_slice(&buf[..w]);
            if done {
                break;
            }
            assert_eq!(w, out_chunk, "stopped short of a full buffer");
        }
        // Done stays done, and writes nothing more.
        let mut w = 0;
        assert!(blk.expand(&mut buf, &mut w));
        assert_eq!(w, 0);
        (got, blk.crc.value())
    }

    /// The incremental RLE-1 expansion agrees with the one-shot
    /// reference for any split of the output.
    #[test]
    fn incremental_rle1_matches_one_shot() {
        use crate::bzip2::rle::rle1_inverse;

        let mut cases: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"abc".to_vec(),
            b"aaab".to_vec(),
            // Four equal bytes at the very end, with no count.
            b"aaaa".to_vec(),
            b"xaaaa".to_vec(),
            vec![b'a', b'a', b'a', b'a', 0],
            vec![b'a', b'a', b'a', b'a', 0, b'a'],
            vec![b'a', b'a', b'a', b'a', 255],
            // A count equal to the run's byte, then the same byte again:
            // the run starts afresh after a count.
            vec![4, 4, 4, 4, 4, 4, 4, 4, 4, 1, 4],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![b'a', b'a', b'a', b'a', 3, b'a', b'a', b'a', b'a', 251, b'b'],
            [b'a', b'a', b'a', b'a', 255].repeat(50),
        ];
        // Small alphabets make runs, counts and their collisions common.
        let mut x: u32 = 12345;
        for len in [1usize, 2, 5, 17, 100, 1000] {
            for alphabet in [1u32, 2, 3, 6] {
                let v: Vec<u8> = (0..len)
                    .map(|_| {
                        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                        ((x >> 16) % alphabet) as u8
                    })
                    .collect();
                cases.push(v);
            }
        }
        for data in &cases {
            let want = rle1_inverse(data);
            let mut crc = Crc32::new();
            crc.update(&want);
            for out_chunk in [1usize, 2, 3, 4, 5, 7, 254, 255, 256, 259, 4096] {
                let (got, got_crc) = expand_all(data, out_chunk);
                assert!(got == want, "{data:?} by {out_chunk}");
                assert_eq!(got_crc, crc.value(), "{data:?} by {out_chunk}");
            }
        }
    }
}
