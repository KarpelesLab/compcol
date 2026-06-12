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

struct HuffmanBlockWork {
    lit: CanonicalDecoder<288>,
    dist: CanonicalDecoder<32>,
    phase: HuffmanPhase,
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
    HuffmanBlock(Box<HuffmanBlockWork>),
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
}

impl Decoder {
    /// True iff the decoder has consumed a complete deflate64 stream (the
    /// last BFINAL=1 block ended in EOB).
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DecState::Done)
    }

    /// Align the bit reader to a byte boundary and return any whole bytes
    /// still sitting in its accumulator. Container wrappers call this when
    /// the deflate64 payload ends so they can recover pre-buffered trailer
    /// bytes.
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
        }
    }

    /// Build a decoder with the given [`DecoderConfig`].
    pub fn with_config(config: DecoderConfig) -> Self {
        let mut d = Self::new();
        d.load_dictionary(&config.dictionary);
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
            let initial_consumed = consumed;
            let initial_written = written;
            self.refill(input, &mut consumed);

            if matches!(self.state, DecState::Done) {
                break;
            }

            let made_progress = self.step(input, &mut consumed, output, &mut written)?;

            if !made_progress && consumed == initial_consumed && written == initial_written {
                break;
            }
        }

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        match self.state {
            DecState::Done => Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            }),
            _ => Err(self.poison(Error::UnexpectedEnd)),
        }
    }

    fn raw_reset(&mut self) {
        self.bit_reader.reset();
        self.window_pos = 0;
        self.window_size = 0;
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
                        let lit = CanonicalDecoder::<288>::from_lengths(&FIXED_LIT_LENGTHS)
                            .map_err(|e| self.poison(e))?;
                        let dist = CanonicalDecoder::<32>::from_lengths(&FIXED_DIST_LENGTHS)
                            .map_err(|e| self.poison(e))?;
                        self.state = DecState::HuffmanBlock(Box::new(HuffmanBlockWork {
                            lit,
                            dist,
                            phase: HuffmanPhase::NextSymbol,
                        }));
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
                self.state = DecState::HuffmanBlock(Box::new(HuffmanBlockWork {
                    lit,
                    dist,
                    phase: HuffmanPhase::NextSymbol,
                }));
                Ok(true)
            }

            DecState::HuffmanBlock(mut work) => {
                let mut progress = false;
                loop {
                    match work.phase {
                        HuffmanPhase::NextSymbol => match work.lit.decode(&mut self.bit_reader) {
                            Ok(Some(sym)) => {
                                progress = true;
                                if sym < END_OF_BLOCK {
                                    if *written >= output.len() {
                                        // Stash literal in the "pending literal"
                                        // sentinel slot — same trick deflate uses.
                                        work.phase = HuffmanPhase::EmittingMatch {
                                            distance: u32::MAX,
                                            remaining: sym as u32,
                                        };
                                        self.state = DecState::HuffmanBlock(work);
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
                                    work.phase = HuffmanPhase::LengthExtra {
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
                            work.phase = HuffmanPhase::DistanceSymbol { length };
                            progress = true;
                        }
                        HuffmanPhase::DistanceSymbol { length } => {
                            match work.dist.decode(&mut self.bit_reader) {
                                Ok(Some(sym)) => {
                                    progress = true;
                                    if (sym as usize) >= NUM_DIST_SYMBOLS {
                                        return Err(self.poison(Error::Corrupt));
                                    }
                                    let idx = sym as usize;
                                    let base_dist = DIST_BASE[idx];
                                    let extra_bits = DIST_EXTRA[idx];
                                    work.phase = HuffmanPhase::DistanceExtra {
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
                            work.phase = HuffmanPhase::EmittingMatch {
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
                                    work.phase = HuffmanPhase::EmittingMatch {
                                        distance,
                                        remaining,
                                    };
                                    break;
                                }
                                let byte = remaining as u8;
                                self.emit_byte(byte, output, written);
                                progress = true;
                                work.phase = HuffmanPhase::NextSymbol;
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
                                work.phase = HuffmanPhase::NextSymbol;
                            } else {
                                work.phase = HuffmanPhase::EmittingMatch {
                                    distance,
                                    remaining,
                                };
                                break;
                            }
                        }
                    }
                }
                self.state = DecState::HuffmanBlock(work);
                Ok(progress)
            }
        }
    }
}
