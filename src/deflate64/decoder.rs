//! Streaming PKWARE deflate64 decoder.
//!
//! Structurally identical to the RFC 1951 deflate decoder: same three block
//! types, same code-length-code prelude, same canonical Huffman. The
//! differences are entirely in the alphabet tables (see `tables.rs`):
//!
//!  * literal/length symbol 285 now consumes 16 extra bits and decodes to a
//!    match length of 3..=65538 (rather than the fixed 258 of deflate);
//!  * distance symbols 30 and 31 are real, each consuming 14 extra bits, so
//!    distances of 32769..=65536 are reachable in the 64 KiB window.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::BitReader;
use crate::error::Error;
use crate::huffman::CanonicalDecoder;
use crate::traits::{RawDecoder, RawProgress};

use super::tables::{
    CODE_LENGTH_ORDER, DIST_BASE, DIST_EXTRA, END_OF_BLOCK, FIXED_DIST_LENGTHS, FIXED_LIT_LENGTHS,
    LENGTH_BASE, LENGTH_EXTRA, NUM_DIST_SYMBOLS, NUM_LITLEN_SYMBOLS, WINDOW_SIZE,
};

/// Configuration for the deflate64 decoder.
///
/// Carries one field: an optional **preset dictionary** that is loaded
/// into the 64 KiB sliding window before decoding starts. Container
/// formats whose chunked deflate64 streams reference data from a previous
/// chunk pass it through here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Bytes to load into the sliding window before decoding. Up to the
    /// last 64 KiB are retained.
    pub dictionary: Vec<u8>,
}

struct DynamicLensWork {
    cl_dec: CanonicalDecoder<19>,
    hlit_count: u16,
    hdist_count: u8,
    lengths: [u8; 320],
    pos: u16,
    prev_len: u8,
    sub: DynLenSub,
}

#[derive(Debug, Clone, Copy)]
enum DynLenSub {
    Symbol,
    RepeatPrev,
    RepeatZeroShort,
    RepeatZeroLong,
}

/// The literal/length and distance decoders of one Huffman block.
struct Tables {
    lit: CanonicalDecoder<288>,
    dist: CanonicalDecoder<32>,
}

#[derive(Debug, Clone, Copy)]
enum HuffmanPhase {
    NextSymbol,
    LengthExtra {
        base_length: u32,
        extra_bits: u8,
    },
    DistanceSymbol {
        length: u32,
    },
    DistanceExtra {
        length: u32,
        base_dist: u32,
        extra_bits: u8,
    },
    EmittingMatch {
        distance: u32,
        remaining: u32,
    },
}

enum DecState {
    BlockHeader,
    StoredAlign,
    StoredLength,
    Stored {
        remaining: u32,
    },
    DynamicHeader,
    DynamicHCLENLengths {
        hlit: u8,
        hdist: u8,
        hclen: u8,
        idx: u8,
        cl_lens: [u8; 19],
    },
    DynamicCodeLengthsData(Box<DynamicLensWork>),
    /// Inside a Huffman block; `fixed` selects which of the decoder's two
    /// table sets it reads.
    HuffmanBlock {
        fixed: bool,
        phase: HuffmanPhase,
    },
    Done,
}

pub struct Decoder {
    bit_reader: BitReader,
    window: Box<[u8; WINDOW_SIZE]>,
    window_pos: usize,
    window_size: usize,
    state: DecState,
    last_block: bool,
    poisoned: bool,
    /// The configured preset dictionary (its last 64 KiB), kept so that
    /// `reset` can seed the window with it again.
    dictionary: Box<[u8]>,
    /// The fixed-Huffman tables, built on the first fixed block and kept
    /// for the decoder's lifetime (they never change): a run of empty fixed
    /// blocks costs 10 bits each and must not cost a table build each.
    fixed_tables: Option<Box<Tables>>,
    /// The current dynamic block's tables; the allocation is reused from
    /// block to block.
    dynamic_tables: Option<Box<Tables>>,
    /// How many times the fixed-Huffman tables were built (test hook).
    #[cfg(test)]
    fixed_builds: u32,
}

impl Decoder {
    /// True iff the decoder has consumed a complete deflate64 stream (the
    /// last BFINAL=1 block ended in EOB).
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DecState::Done)
    }

    /// Align the bit reader to a byte boundary and return any whole bytes
    /// still sitting in its accumulator.
    ///
    /// Once the stream has ended this returns nothing: the decoder already
    /// leaves every byte after the final block unconsumed, so whatever
    /// follows the deflate64 payload can be read straight from the input,
    /// at the sum of the `consumed` counts. Kept for callers written when
    /// the decoder read ahead.
    pub fn drain_trailing_bytes(&mut self) -> alloc::vec::Vec<u8> {
        self.bit_reader.align_to_byte();
        let mut out = alloc::vec::Vec::new();
        while self.bit_reader.bits_available() >= 8 {
            out.push(self.bit_reader.peek(8) as u8);
            self.bit_reader.drop_bits(8);
        }
        out
    }

    pub fn new() -> Self {
        Self {
            bit_reader: BitReader::new(),
            window: Box::new([0u8; WINDOW_SIZE]),
            window_pos: 0,
            window_size: 0,
            state: DecState::BlockHeader,
            last_block: false,
            poisoned: false,
            dictionary: Box::default(),
            fixed_tables: None,
            dynamic_tables: None,
            #[cfg(test)]
            fixed_builds: 0,
        }
    }

    /// Build a decoder with the given [`DecoderConfig`].
    pub fn with_config(config: DecoderConfig) -> Self {
        let mut d = Self::new();
        let start = config.dictionary.len().saturating_sub(WINDOW_SIZE);
        let dictionary: Box<[u8]> = config.dictionary[start..].into();
        d.load_dictionary(&dictionary);
        d.dictionary = dictionary;
        d
    }

    /// Seed the sliding window with `dict`. If `dict` is longer than
    /// 64 KiB only its trailing 64 KiB is kept.
    pub(crate) fn load_dictionary(&mut self, dict: &[u8]) {
        let take = dict.len().min(WINDOW_SIZE);
        let start = dict.len() - take;
        let bytes = &dict[start..];
        self.window_pos = 0;
        self.window_size = 0;
        for &b in bytes {
            self.window[self.window_pos] = b;
            self.window_pos = (self.window_pos + 1) % WINDOW_SIZE;
            if self.window_size < WINDOW_SIZE {
                self.window_size += 1;
            }
        }
    }

    /// Reset the bit reader and block-decode state but keep the 64 KiB
    /// sliding window intact. Useful for chained streams that share
    /// history across chunk boundaries.
    pub fn reset_keep_window(&mut self) {
        self.bit_reader.reset();
        self.state = DecState::BlockHeader;
        self.last_block = false;
        self.poisoned = false;
    }

    fn refill(&mut self, input: &[u8], consumed: &mut usize) {
        while *consumed < input.len() && self.bit_reader.bits_available() <= 56 {
            self.bit_reader.feed(input[*consumed]);
            *consumed += 1;
        }
    }

    fn emit_byte(&mut self, byte: u8, output: &mut [u8], written: &mut usize) {
        debug_assert!(*written < output.len());
        output[*written] = byte;
        *written += 1;
        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) % WINDOW_SIZE;
        if self.window_size < WINDOW_SIZE {
            self.window_size += 1;
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    fn transition_after_block(&mut self) {
        if self.last_block {
            self.state = DecState::Done;
        } else {
            self.state = DecState::BlockHeader;
        }
    }

    /// Hand back the whole bytes still in the bit reader when the decoder
    /// returns for any reason other than waiting on input: the stream
    /// ended or the output is full. This keeps `consumed` exact at the end
    /// of the stream.
    ///
    /// The bytes held are always the last ones fed in this call: a call
    /// starts either with fewer than 8 bits (handed back last time) or with
    /// bits that all belong to the pending field, which was short of them,
    /// so those are used up before anything else.
    fn unfeed(&mut self, consumed: &mut usize) {
        let blocked_on_output = matches!(
            self.state,
            DecState::Done
                | DecState::Stored { .. }
                | DecState::HuffmanBlock {
                    phase: HuffmanPhase::EmittingMatch { .. },
                    ..
                }
        );
        if blocked_on_output {
            let n = self.bit_reader.unfeed_whole_bytes() as usize;
            debug_assert!(n <= *consumed);
            *consumed -= n.min(*consumed);
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
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            // Past the final block nothing more is read: what follows the
            // stream is not this decoder's.
            if matches!(self.state, DecState::Done) {
                break;
            }

            let initial_consumed = consumed;
            let initial_written = written;
            self.refill(input, &mut consumed);

            let made_progress = self.step(input, &mut consumed, output, &mut written)?;

            if !made_progress && consumed == initial_consumed && written == initial_written {
                break;
            }
        }
        self.unfeed(&mut consumed);

        Ok(RawProgress {
            // See the matching note in `deflate`: reporting `false` after the
            // BFINAL block leaves a trailing-garbage stream stuck returning
            // `OutputFull` with no progress, spinning any loop that waits for
            // `Status::StreamEnd`.
            done: matches!(self.state, DecState::Done),
            consumed,
            written,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // All the input is in, but the bit reader may still hold the end of
        // the stream, and a match may be half copied, for want of output:
        // hand that out first. Only a stream that stops short with nothing
        // left to give is truncated.
        let p = self.raw_decode(&[], output)?;
        // A match or a literal (kept as an `EmittingMatch` too) waiting for
        // room is output still owed, not a truncated stream, even if this
        // call had no room to take any of it: the caller comes back with
        // a buffer.
        let owes_output = matches!(
            self.state,
            DecState::HuffmanBlock {
                phase: HuffmanPhase::EmittingMatch { .. },
                ..
            }
        );
        if matches!(self.state, DecState::Done) || p.written > 0 || owes_output {
            return Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: matches!(self.state, DecState::Done),
            });
        }
        Err(self.poison(Error::UnexpectedEnd))
    }

    fn raw_reset(&mut self) {
        self.bit_reader.reset();
        // Configuration survives a reset: seed the window with the preset
        // dictionary again (this also rewinds `window_pos`/`window_size`).
        let dictionary = core::mem::take(&mut self.dictionary);
        self.load_dictionary(&dictionary);
        self.dictionary = dictionary;
        self.state = DecState::BlockHeader;
        self.last_block = false;
        self.poisoned = false;
    }
}

impl Decoder {
    fn step(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
        output: &mut [u8],
        written: &mut usize,
    ) -> Result<bool, Error> {
        match core::mem::replace(&mut self.state, DecState::Done) {
            DecState::Done => {
                self.state = DecState::Done;
                Ok(false)
            }

            DecState::BlockHeader => {
                if self.bit_reader.bits_available() < 3 {
                    self.state = DecState::BlockHeader;
                    return Ok(false);
                }
                let bfinal = self.bit_reader.peek(1);
                self.bit_reader.drop_bits(1);
                let btype = self.bit_reader.peek(2) as u8;
                self.bit_reader.drop_bits(2);
                self.last_block = bfinal != 0;
                match btype {
                    0 => self.state = DecState::StoredAlign,
                    1 => {
                        if self.fixed_tables.is_none() {
                            #[cfg(test)]
                            {
                                self.fixed_builds += 1;
                            }
                            let lit = CanonicalDecoder::<288>::from_lengths(&FIXED_LIT_LENGTHS)
                                .map_err(|e| self.poison(e))?;
                            let dist = CanonicalDecoder::<32>::from_lengths(&FIXED_DIST_LENGTHS)
                                .map_err(|e| self.poison(e))?;
                            self.fixed_tables = Some(Box::new(Tables { lit, dist }));
                        }
                        self.state = DecState::HuffmanBlock {
                            fixed: true,
                            phase: HuffmanPhase::NextSymbol,
                        };
                    }
                    2 => self.state = DecState::DynamicHeader,
                    _ => return Err(self.poison(Error::InvalidBlockType)),
                }
                Ok(true)
            }

            DecState::StoredAlign => {
                self.bit_reader.align_to_byte();
                self.state = DecState::StoredLength;
                Ok(true)
            }

            DecState::StoredLength => {
                if self.bit_reader.bits_available() < 32 {
                    self.state = DecState::StoredLength;
                    return Ok(false);
                }
                let len = self.bit_reader.peek(16) as u16;
                self.bit_reader.drop_bits(16);
                let nlen = self.bit_reader.peek(16) as u16;
                self.bit_reader.drop_bits(16);
                if len != !nlen {
                    return Err(self.poison(Error::Corrupt));
                }
                self.state = DecState::Stored {
                    remaining: len as u32,
                };
                Ok(true)
            }

            DecState::Stored { mut remaining } => {
                let mut progress = false;
                while remaining > 0
                    && self.bit_reader.bits_available() >= 8
                    && *written < output.len()
                {
                    let b = self.bit_reader.peek(8) as u8;
                    self.bit_reader.drop_bits(8);
                    self.emit_byte(b, output, written);
                    remaining -= 1;
                    progress = true;
                }
                while remaining > 0 && *consumed < input.len() && *written < output.len() {
                    let b = input[*consumed];
                    *consumed += 1;
                    self.emit_byte(b, output, written);
                    remaining -= 1;
                    progress = true;
                }
                if remaining == 0 {
                    self.transition_after_block();
                } else {
                    self.state = DecState::Stored { remaining };
                }
                Ok(progress)
            }

            DecState::DynamicHeader => {
                if self.bit_reader.bits_available() < 14 {
                    self.state = DecState::DynamicHeader;
                    return Ok(false);
                }
                let hlit = self.bit_reader.peek(5) as u8;
                self.bit_reader.drop_bits(5);
                let hdist = self.bit_reader.peek(5) as u8;
                self.bit_reader.drop_bits(5);
                let hclen = self.bit_reader.peek(4) as u8;
                self.bit_reader.drop_bits(4);
                // hlit -> 257..=286, hdist -> 1..=32 (all 32 symbols valid in deflate64),
                // hclen -> 4..=19.
                if hlit > 29 || hdist > 31 || hclen > 15 {
                    return Err(self.poison(Error::Corrupt));
                }
                self.state = DecState::DynamicHCLENLengths {
                    hlit,
                    hdist,
                    hclen,
                    idx: 0,
                    cl_lens: [0u8; 19],
                };
                Ok(true)
            }

            DecState::DynamicHCLENLengths {
                hlit,
                hdist,
                hclen,
                mut idx,
                mut cl_lens,
            } => {
                let total = hclen as usize + 4;
                let mut progress = false;
                while (idx as usize) < total {
                    if self.bit_reader.bits_available() < 3 {
                        break;
                    }
                    let len = self.bit_reader.peek(3) as u8;
                    self.bit_reader.drop_bits(3);
                    cl_lens[CODE_LENGTH_ORDER[idx as usize]] = len;
                    idx += 1;
                    progress = true;
                }
                if (idx as usize) < total {
                    self.state = DecState::DynamicHCLENLengths {
                        hlit,
                        hdist,
                        hclen,
                        idx,
                        cl_lens,
                    };
                    return Ok(progress);
                }
                let cl_dec =
                    CanonicalDecoder::<19>::from_lengths(&cl_lens).map_err(|e| self.poison(e))?;
                let hlit_count = hlit as u16 + 257;
                let hdist_count = hdist + 1;
                let work = DynamicLensWork {
                    cl_dec,
                    hlit_count,
                    hdist_count,
                    lengths: [0u8; 320],
                    pos: 0,
                    prev_len: 0,
                    sub: DynLenSub::Symbol,
                };
                self.state = DecState::DynamicCodeLengthsData(Box::new(work));
                Ok(true)
            }

            DecState::DynamicCodeLengthsData(mut work) => {
                let total = work.hlit_count as usize + work.hdist_count as usize;
                let mut progress = false;

                loop {
                    if (work.pos as usize) >= total {
                        break;
                    }
                    match work.sub {
                        DynLenSub::Symbol => match work.cl_dec.decode(&mut self.bit_reader) {
                            Ok(Some(sym)) => {
                                progress = true;
                                match sym {
                                    0..=15 => {
                                        work.lengths[work.pos as usize] = sym as u8;
                                        work.prev_len = sym as u8;
                                        work.pos += 1;
                                    }
                                    16 => work.sub = DynLenSub::RepeatPrev,
                                    17 => work.sub = DynLenSub::RepeatZeroShort,
                                    18 => work.sub = DynLenSub::RepeatZeroLong,
                                    _ => return Err(self.poison(Error::Corrupt)),
                                }
                            }
                            Ok(None) => break,
                            Err(e) => return Err(self.poison(e)),
                        },
                        DynLenSub::RepeatPrev => {
                            if self.bit_reader.bits_available() < 2 {
                                break;
                            }
                            let n = self.bit_reader.peek(2) as usize + 3;
                            self.bit_reader.drop_bits(2);
                            if work.pos as usize + n > total || work.pos == 0 {
                                return Err(self.poison(Error::Corrupt));
                            }
                            let v = work.prev_len;
                            for _ in 0..n {
                                work.lengths[work.pos as usize] = v;
                                work.pos += 1;
                            }
                            work.sub = DynLenSub::Symbol;
                            progress = true;
                        }
                        DynLenSub::RepeatZeroShort => {
                            if self.bit_reader.bits_available() < 3 {
                                break;
                            }
                            let n = self.bit_reader.peek(3) as usize + 3;
                            self.bit_reader.drop_bits(3);
                            if work.pos as usize + n > total {
                                return Err(self.poison(Error::Corrupt));
                            }
                            for _ in 0..n {
                                work.lengths[work.pos as usize] = 0;
                                work.pos += 1;
                            }
                            work.prev_len = 0;
                            work.sub = DynLenSub::Symbol;
                            progress = true;
                        }
                        DynLenSub::RepeatZeroLong => {
                            if self.bit_reader.bits_available() < 7 {
                                break;
                            }
                            let n = self.bit_reader.peek(7) as usize + 11;
                            self.bit_reader.drop_bits(7);
                            if work.pos as usize + n > total {
                                return Err(self.poison(Error::Corrupt));
                            }
                            for _ in 0..n {
                                work.lengths[work.pos as usize] = 0;
                                work.pos += 1;
                            }
                            work.prev_len = 0;
                            work.sub = DynLenSub::Symbol;
                            progress = true;
                        }
                    }
                }

                if (work.pos as usize) < total {
                    self.state = DecState::DynamicCodeLengthsData(work);
                    return Ok(progress);
                }

                let mut lit_lens = [0u8; 288];
                lit_lens[..work.hlit_count as usize]
                    .copy_from_slice(&work.lengths[..work.hlit_count as usize]);

                let mut dist_lens = [0u8; 32];
                let dist_src_start = work.hlit_count as usize;
                let dist_src_end = dist_src_start + work.hdist_count as usize;
                dist_lens[..work.hdist_count as usize]
                    .copy_from_slice(&work.lengths[dist_src_start..dist_src_end]);

                let lit =
                    CanonicalDecoder::<288>::from_lengths(&lit_lens).map_err(|e| self.poison(e))?;
                let dist =
                    CanonicalDecoder::<32>::from_lengths(&dist_lens).map_err(|e| self.poison(e))?;
                match &mut self.dynamic_tables {
                    Some(t) => {
                        t.lit = lit;
                        t.dist = dist;
                    }
                    None => self.dynamic_tables = Some(Box::new(Tables { lit, dist })),
                }
                self.state = DecState::HuffmanBlock {
                    fixed: false,
                    phase: HuffmanPhase::NextSymbol,
                };
                Ok(true)
            }

            DecState::HuffmanBlock { fixed, phase } => {
                // Lend the block's tables out of `self` for the duration of
                // the call, so the block loop can borrow the rest freely.
                let slot = if fixed {
                    &mut self.fixed_tables
                } else {
                    &mut self.dynamic_tables
                };
                let Some(tables) = slot.take() else {
                    return Err(self.poison(Error::Corrupt));
                };
                let r = self.huffman_block(&tables, fixed, phase, output, written);
                if fixed {
                    self.fixed_tables = Some(tables);
                } else {
                    self.dynamic_tables = Some(tables);
                }
                r
            }
        }
    }

    /// Decode symbols of the current Huffman block until it ends or the
    /// input or output runs out, then store the state to resume from.
    fn huffman_block(
        &mut self,
        tables: &Tables,
        fixed: bool,
        mut phase: HuffmanPhase,
        output: &mut [u8],
        written: &mut usize,
    ) -> Result<bool, Error> {
        let mut progress = false;
        loop {
            match phase {
                HuffmanPhase::NextSymbol => match tables.lit.decode(&mut self.bit_reader) {
                    Ok(Some(sym)) => {
                        progress = true;
                        if sym < END_OF_BLOCK {
                            if *written >= output.len() {
                                // Stash literal in the "pending literal"
                                // sentinel slot — same trick deflate uses.
                                phase = HuffmanPhase::EmittingMatch {
                                    distance: u32::MAX,
                                    remaining: sym as u32,
                                };
                                self.state = DecState::HuffmanBlock { fixed, phase };
                                return Ok(progress);
                            }
                            self.emit_byte(sym as u8, output, written);
                        } else if sym == END_OF_BLOCK {
                            self.transition_after_block();
                            return Ok(true);
                        } else if (sym as usize) < NUM_LITLEN_SYMBOLS {
                            let idx = (sym - 257) as usize;
                            let base_length = LENGTH_BASE[idx];
                            let extra_bits = LENGTH_EXTRA[idx];
                            phase = HuffmanPhase::LengthExtra {
                                base_length,
                                extra_bits,
                            };
                        } else {
                            return Err(self.poison(Error::Corrupt));
                        }
                    }
                    Ok(None) => break,
                    Err(e) => return Err(self.poison(e)),
                },
                HuffmanPhase::LengthExtra {
                    base_length,
                    extra_bits,
                } => {
                    if self.bit_reader.bits_available() < extra_bits as u32 {
                        break;
                    }
                    let extra = if extra_bits == 0 {
                        0u32
                    } else {
                        self.bit_reader.peek(extra_bits as u32) as u32
                    };
                    self.bit_reader.drop_bits(extra_bits as u32);
                    let length = base_length + extra;
                    phase = HuffmanPhase::DistanceSymbol { length };
                    progress = true;
                }
                HuffmanPhase::DistanceSymbol { length } => {
                    match tables.dist.decode(&mut self.bit_reader) {
                        Ok(Some(sym)) => {
                            progress = true;
                            if (sym as usize) >= NUM_DIST_SYMBOLS {
                                return Err(self.poison(Error::Corrupt));
                            }
                            let idx = sym as usize;
                            let base_dist = DIST_BASE[idx];
                            let extra_bits = DIST_EXTRA[idx];
                            phase = HuffmanPhase::DistanceExtra {
                                length,
                                base_dist,
                                extra_bits,
                            };
                        }
                        Ok(None) => break,
                        Err(e) => return Err(self.poison(e)),
                    }
                }
                HuffmanPhase::DistanceExtra {
                    length,
                    base_dist,
                    extra_bits,
                } => {
                    if self.bit_reader.bits_available() < extra_bits as u32 {
                        break;
                    }
                    let extra = if extra_bits == 0 {
                        0u32
                    } else {
                        self.bit_reader.peek(extra_bits as u32) as u32
                    };
                    self.bit_reader.drop_bits(extra_bits as u32);
                    let distance = base_dist + extra;
                    if distance == 0 || (distance as usize) > self.window_size {
                        return Err(self.poison(Error::InvalidDistance));
                    }
                    phase = HuffmanPhase::EmittingMatch {
                        distance,
                        remaining: length,
                    };
                    progress = true;
                }
                HuffmanPhase::EmittingMatch {
                    distance,
                    mut remaining,
                } => {
                    // Sentinel: distance == u32::MAX means we're emitting a
                    // single pending literal whose value is `remaining` (0..=255).
                    if distance == u32::MAX {
                        if *written >= output.len() {
                            phase = HuffmanPhase::EmittingMatch {
                                distance,
                                remaining,
                            };
                            break;
                        }
                        let byte = remaining as u8;
                        self.emit_byte(byte, output, written);
                        progress = true;
                        phase = HuffmanPhase::NextSymbol;
                        continue;
                    }
                    // Copy the match run in contiguous, non-wrapping
                    // spans. Non-overlapping spans use a single
                    // copy_within + copy_from_slice; overlapping spans
                    // (distance < remaining) replicate the d-byte
                    // pattern with an expanding doubling copy instead
                    // of one byte at a time.
                    let d = distance as usize;
                    while remaining > 0 && *written < output.len() {
                        let out_room = output.len() - *written;
                        let src = if self.window_pos >= d {
                            self.window_pos - d
                        } else {
                            self.window_pos + WINDOW_SIZE - d
                        };
                        let dst_room = WINDOW_SIZE - self.window_pos;
                        let src_room = WINDOW_SIZE - src;
                        let span = (remaining as usize)
                            .min(out_room)
                            .min(dst_room)
                            .min(src_room);
                        if span == 0 {
                            break;
                        }

                        if d >= span {
                            let wp = self.window_pos;
                            self.window.copy_within(src..src + span, wp);
                            output[*written..*written + span]
                                .copy_from_slice(&self.window[wp..wp + span]);
                            *written += span;
                            self.window_pos = wp + span;
                        } else if src + d == self.window_pos {
                            let start = self.window_pos; // == src + d
                            let mut produced = 0usize;
                            while produced < span {
                                let copy = d.min(span - produced);
                                self.window.copy_within(
                                    src + produced..src + produced + copy,
                                    start + produced,
                                );
                                produced += copy;
                            }
                            output[*written..*written + span]
                                .copy_from_slice(&self.window[start..start + span]);
                            *written += span;
                            self.window_pos = start + span;
                        } else {
                            // Rare: overlapping source wraps the ring.
                            let start = self.window_pos;
                            for i in 0..span {
                                let s = if start + i >= d {
                                    start + i - d
                                } else {
                                    start + i + WINDOW_SIZE - d
                                };
                                let b = self.window[s];
                                self.window[start + i] = b;
                                output[*written] = b;
                                *written += 1;
                            }
                            self.window_pos = start + span;
                        }

                        if self.window_pos == WINDOW_SIZE {
                            self.window_pos = 0;
                        }
                        if self.window_size < WINDOW_SIZE {
                            self.window_size = (self.window_size + span).min(WINDOW_SIZE);
                        }
                        remaining -= span as u32;
                        progress = true;
                    }
                    if remaining == 0 {
                        phase = HuffmanPhase::NextSymbol;
                    } else {
                        phase = HuffmanPhase::EmittingMatch {
                            distance,
                            remaining,
                        };
                        break;
                    }
                }
            }
        }
        self.state = DecState::HuffmanBlock { fixed, phase };
        Ok(progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `count` empty fixed-Huffman blocks (BFINAL=0, BTYPE=01, EOB): 10 bits
    /// each, no output.
    fn empty_fixed_blocks(count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        let (mut acc, mut n) = (0u64, 0u32);
        for _ in 0..count {
            acc |= 0b010u64 << n;
            n += 10;
            while n >= 8 {
                bytes.push(acc as u8);
                acc >>= 8;
                n -= 8;
            }
        }
        bytes
    }

    #[test]
    fn fixed_tables_are_built_once() {
        let input = empty_fixed_blocks(2000);
        let mut dec = Decoder::new();
        let mut out = [0u8; 64];
        let p = dec.raw_decode(&input, &mut out).unwrap();
        assert_eq!(p.consumed, input.len());
        assert_eq!(p.written, 0);
        assert!(!p.done);
        assert_eq!(dec.fixed_builds, 1);

        // The cache survives a reset.
        dec.raw_reset();
        dec.raw_decode(&input, &mut out).unwrap();
        assert_eq!(dec.fixed_builds, 1);
    }
}
