//! Streaming RFC 1951 (deflate) decoder.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::BitReader;
use crate::error::Error;
use crate::huffman::CanonicalDecoder;
use crate::traits::{RawDecoder, RawProgress};

/// Configuration for the deflate decoder.
///
/// Currently carries one field: an optional **preset dictionary** used to
/// seed the 32 KiB sliding window before decoding starts. This matches
/// RFC 1951 §3.2.4's "preset dictionary" concept and the zlib container's
/// `FDICT` mechanism, and is what container formats like CAB MSZIP need
/// when back-references in one block reach into the previous block's
/// decompressed output.
///
/// If `dictionary` is longer than 32 KiB only the trailing 32 KiB is
/// retained (the rest is unreachable from any back-reference). An empty
/// dictionary — the default — is equivalent to the older configless API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Bytes to load into the sliding window before decoding. Up to the
    /// last `window_size` bytes are retained.
    pub dictionary: Vec<u8>,
    /// Sliding-window size in bytes, clamped to `1..=WINDOW_SIZE` (the full
    /// 32 KiB deflate window is the default). A smaller window lets the
    /// decoder read streams produced for a small-window decoder — e.g.
    /// qemu/qcow2 inflates compressed clusters with a 4 KiB window
    /// (`inflateInit2(-12)`) — and uses proportionally less memory. Any
    /// back-reference farther than `window_size` is rejected with
    /// `Error::InvalidDistance`, so this also lets an encoder prove its
    /// output stays within a given window (pair with
    /// `EncoderConfig::max_distance`).
    pub window_size: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            dictionary: Vec::new(),
            window_size: WINDOW_SIZE,
        }
    }
}

use super::tables::{
    CODE_LENGTH_ORDER, DIST_BASE, DIST_EXTRA, END_OF_BLOCK, FIXED_DIST_LENGTHS, FIXED_LIT_LENGTHS,
    LENGTH_BASE, LENGTH_EXTRA, WINDOW_SIZE,
};

// ─── per-block work buffers, boxed to keep the enum tiny ────────────────

struct DynamicLensWork {
    cl_dec: CanonicalDecoder<19>,
    hlit_count: u16,    // HLIT + 257; number of literal/length code lengths
    hdist_count: u8,    // HDIST + 1; number of distance code lengths
    lengths: [u8; 320], // capacity for max HLIT(286) + max HDIST(30) + slack
    pos: u16,
    prev_len: u8,
    sub: DynLenSub,
}

#[derive(Debug, Clone, Copy)]
enum DynLenSub {
    /// Waiting to decode the next code-length-code symbol.
    Symbol,
    /// Symbol 16 read; need 2 extra bits then emit `prev_len` repeated 3..=6 times.
    RepeatPrev,
    /// Symbol 17 read; need 3 extra bits then emit 0 repeated 3..=10 times.
    RepeatZeroShort,
    /// Symbol 18 read; need 7 extra bits then emit 0 repeated 11..=138 times.
    RepeatZeroLong,
}

struct HuffmanBlockWork {
    lit: CanonicalDecoder<288>,
    dist: CanonicalDecoder<32>,
    phase: HuffmanPhase,
}

#[derive(Debug, Clone, Copy)]
enum HuffmanPhase {
    /// About to decode the next literal/length symbol.
    NextSymbol,
    /// Read a length code; need its extra bits.
    LengthExtra { base_length: u16, extra_bits: u8 },
    /// Have a length; need to decode the distance symbol.
    DistanceSymbol { length: u16 },
    /// Read a distance code; need its extra bits.
    DistanceExtra {
        length: u16,
        base_dist: u16,
        extra_bits: u8,
    },
    /// Copying a match from the sliding window into output.
    EmittingMatch { distance: u16, remaining: u16 },
}

enum DecState {
    BlockHeader,
    StoredAlign,
    StoredLength,
    Stored {
        remaining: u32,
    },
    DynamicHeader,
    /// Reading the HCLEN+4 code-length-code lengths (3 bits each), permuted
    /// by `CODE_LENGTH_ORDER`.
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
    /// Circular history buffer of `win_cap` bytes (heap-allocated to the
    /// configured window size, ≤ 32 KiB).
    window: Box<[u8]>,
    /// Ring capacity = the sliding-window size = the maximum legal match
    /// distance. `1..=WINDOW_SIZE`.
    win_cap: usize,
    window_pos: usize,
    window_size: usize, // 0..=win_cap; how many valid bytes lie behind window_pos
    state: DecState,
    last_block: bool,
    poisoned: bool,
}

impl Decoder {
    /// True iff the decoder has consumed a complete deflate stream (the
    /// last BFINAL=1 block ended in EOB) and is in the absorbing `Done` state.
    /// Used by the zlib / gzip wrappers to know when to start consuming the
    /// container's trailer.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DecState::Done)
    }

    /// Align the bit reader to a byte boundary and return any whole bytes
    /// still sitting in its accumulator.
    ///
    /// The deflate decoder eagerly pulls bytes into its bit reader to
    /// minimise per-bit overhead, so when a deflate stream embedded in a
    /// container ends, the next-bytes-of-input have likely already been
    /// pre-buffered. Container wrappers call this to recover them as the
    /// first bytes of their trailer.
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
        Self::with_window_capacity(WINDOW_SIZE)
    }

    /// Build a decoder whose sliding window holds `cap` bytes (clamped to
    /// `1..=WINDOW_SIZE`). `cap` is both the history size and the maximum
    /// legal back-reference distance.
    fn with_window_capacity(cap: usize) -> Self {
        let cap = cap.clamp(1, WINDOW_SIZE);
        Self {
            bit_reader: BitReader::new(),
            window: alloc::vec![0u8; cap].into_boxed_slice(),
            win_cap: cap,
            window_pos: 0,
            window_size: 0,
            state: DecState::BlockHeader,
            last_block: false,
            poisoned: false,
        }
    }

    /// Build a decoder with the given [`DecoderConfig`]. The configured
    /// dictionary (last 32 KiB if longer) is loaded into the sliding
    /// window before any input is consumed, so the very first block's
    /// back-references can reach into it as if it were already-decoded
    /// output.
    pub fn with_config(config: DecoderConfig) -> Self {
        let mut d = Self::with_window_capacity(config.window_size);
        d.load_dictionary(&config.dictionary);
        d
    }

    /// Seed the sliding window with `dict`. Used internally by
    /// [`with_config`] and the zlib container's `FDICT` handling. If
    /// `dict` is longer than 32 KiB only its trailing 32 KiB is kept
    /// (anything older is unreachable from a deflate back-reference).
    /// Replaces any prior window contents.
    pub(crate) fn load_dictionary(&mut self, dict: &[u8]) {
        let take = dict.len().min(self.win_cap);
        let start = dict.len() - take;
        let bytes = &dict[start..];
        // Reset window state, then write the dictionary as if it had been
        // emitted by a prior decode pass. `window_pos` ends up just past
        // the last dictionary byte, which is where future emit_byte calls
        // will continue from — matching the relative-distance semantics
        // that deflate back-references rely on.
        self.window_pos = 0;
        self.window_size = 0;
        for &b in bytes {
            self.window[self.window_pos] = b;
            self.window_pos = (self.window_pos + 1) % self.win_cap;
            if self.window_size < self.win_cap {
                self.window_size += 1;
            }
        }
    }

    /// Reset the bit reader and block-decode state but **keep** the
    /// 32 KiB sliding window contents intact.
    ///
    /// This is what CAB MSZIP and similar "chained deflate stream"
    /// containers need: every chunk is a self-contained deflate stream
    /// whose back-references can still reach into the previous chunk's
    /// last 32 KiB of decompressed output. Call this between chunks to
    /// re-arm the decoder for a fresh stream while preserving history.
    ///
    /// For the more common "throw everything away" reset, use the
    /// [`Decoder::reset`](crate::Decoder::reset) method from the
    /// `Decoder` trait, which clears the window too.
    pub fn reset_keep_window(&mut self) {
        self.bit_reader.reset();
        self.state = DecState::BlockHeader;
        self.last_block = false;
        self.poisoned = false;
    }

    /// Pull bytes from `input[*consumed..]` into the bit reader, stopping
    /// at either the end of input or once the reader can't hold another
    /// byte without risking overflow.
    fn refill(&mut self, input: &[u8], consumed: &mut usize) {
        while *consumed < input.len() && self.bit_reader.bits_available() <= 56 {
            self.bit_reader.feed(input[*consumed]);
            *consumed += 1;
        }
    }

    /// Write one byte to both the sliding window and the caller's output.
    fn emit_byte(&mut self, byte: u8, output: &mut [u8], written: &mut usize) {
        debug_assert!(*written < output.len());
        output[*written] = byte;
        *written += 1;
        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) % self.win_cap;
        if self.window_size < self.win_cap {
            self.window_size += 1;
        }
    }

    /// Mark the decoder as poisoned and return the given error.
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

            // Reached Done? Caller should now call finish(); return whatever progress we made.
            if matches!(self.state, DecState::Done) {
                break;
            }

            let made_progress = self.step(input, &mut consumed, output, &mut written)?;

            // If nothing changed, we're blocked on more input, more output, or both.
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
        // The deflate decoder never *needs* to emit more bytes during finish:
        // either we already saw the BFINAL=1 end-of-block and reached Done,
        // in which case we're done; or we didn't, in which case the stream
        // ended mid-block.
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
    /// Advance the state machine by one substep. Returns `Ok(true)` if forward
    /// progress was made (state advanced), `Ok(false)` if blocked.
    fn step(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
        output: &mut [u8],
        written: &mut usize,
    ) -> Result<bool, Error> {
        match core::mem::replace(&mut self.state, DecState::Done) {
            // ── Done is the absorbing state ──────────────────────────────
            DecState::Done => {
                self.state = DecState::Done;
                Ok(false)
            }

            // ── 3-bit block header (BFINAL + BTYPE) ─────────────────────
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
                        // Fixed-Huffman block: build the static tables once per block.
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
                // First drain any buffered bytes still in the bit reader.
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
                // Then copy raw input bytes directly.
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
                // hlit is HLIT (0..=29) -> literal/length lengths = HLIT + 257 (in 257..=286)
                // hdist is HDIST (0..=29) -> distance lengths = HDIST + 1 (in 1..=30)
                // hclen is HCLEN (0..=15) -> code-length-code lengths = HCLEN + 4 (in 4..=19)
                if hlit > 29 || hdist > 29 || hclen > 15 {
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
                        DynLenSub::Symbol => {
                            match work.cl_dec.decode(&mut self.bit_reader) {
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
                                        _ => {
                                            return Err(self.poison(Error::Corrupt));
                                        }
                                    }
                                }
                                Ok(None) => break, // need more bits
                                Err(e) => {
                                    return Err(self.poison(e));
                                }
                            }
                        }
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

                // Both length arrays are filled; build the two block-Huffman decoders.
                // lit_lengths is positions 0..hlit_count, padded to 288 with zeros.
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
                        HuffmanPhase::NextSymbol => {
                            match work.lit.decode(&mut self.bit_reader) {
                                Ok(Some(sym)) => {
                                    progress = true;
                                    if sym < END_OF_BLOCK {
                                        // Literal byte
                                        if *written >= output.len() {
                                            // No room — stash the decoded literal back.
                                            // Trick: re-push the byte via a special phase.
                                            // Easier: just keep work in NextSymbol and the byte
                                            // is "lost"... no, that's wrong. We need to remember.
                                            // Use a dedicated phase for "pending literal".
                                            // For simplicity we emit only when there's room.
                                            // Since we already consumed the bits, store the
                                            // literal in a stash slot. But our enum doesn't have
                                            // that yet. Let's add a Match-phase trick instead:
                                            // model a 1-byte literal as a self-copy with d=0?
                                            // No. Add a pending-literal phase.
                                            work.phase = HuffmanPhase::EmittingMatch {
                                                distance: u16::MAX, // sentinel: literal
                                                remaining: sym,
                                            };
                                            self.state = DecState::HuffmanBlock(work);
                                            return Ok(progress);
                                        }
                                        self.emit_byte(sym as u8, output, written);
                                    } else if sym == END_OF_BLOCK {
                                        self.transition_after_block();
                                        return Ok(true);
                                    } else if sym < 286 {
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
                            }
                        }
                        HuffmanPhase::LengthExtra {
                            base_length,
                            extra_bits,
                        } => {
                            if self.bit_reader.bits_available() < extra_bits as u32 {
                                break;
                            }
                            let extra = if extra_bits == 0 {
                                0
                            } else {
                                self.bit_reader.peek(extra_bits as u32) as u16
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
                                    if sym >= 30 {
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
                                0
                            } else {
                                self.bit_reader.peek(extra_bits as u32) as u16
                            };
                            self.bit_reader.drop_bits(extra_bits as u32);
                            let distance = base_dist + extra;
                            // Reject distance 0, distances reaching before the
                            // start of produced output, and — for a reduced
                            // window — anything beyond the configured size
                            // (`window_size` is itself capped at `win_cap`, so
                            // the second test only bites before the window has
                            // filled; the explicit `win_cap` check documents the
                            // small-window rejection that mirrors zlib's
                            // `inflateInit2(-wbits)` Z_DATA_ERROR).
                            if distance == 0
                                || (distance as usize) > self.window_size
                                || (distance as usize) > self.win_cap
                            {
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
                            // Sentinel: distance == u16::MAX means we're emitting a single
                            // pending literal whose value is `remaining` (0..=255).
                            if distance == u16::MAX {
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
                            // Bulk-copy the non-overlapping run; fall back
                            // to the byte loop for overlap (distance < remaining)
                            // and wrap-spanning chunks.
                            let d = distance as usize;
                            let out_room = output.len() - *written;
                            let mut chunk = (remaining as usize).min(out_room);
                            if chunk > 0 && d >= chunk {
                                let src = (self.window_pos + self.win_cap - d) % self.win_cap;
                                // Limit chunk so source and destination
                                // ranges do not wrap the circular window.
                                let src_room = self.win_cap - src;
                                let dst_room = self.win_cap - self.window_pos;
                                chunk = chunk.min(src_room).min(dst_room);
                                if chunk > 0 {
                                    // Copy to output.
                                    output[*written..*written + chunk]
                                        .copy_from_slice(&self.window[src..src + chunk]);
                                    // Copy to window via copy_within (src and dst
                                    // don't overlap because d >= chunk).
                                    self.window.copy_within(src..src + chunk, self.window_pos);
                                    *written += chunk;
                                    self.window_pos = (self.window_pos + chunk) % self.win_cap;
                                    if self.window_size < self.win_cap {
                                        self.window_size =
                                            (self.window_size + chunk).min(self.win_cap);
                                    }
                                    remaining -= chunk as u16;
                                    progress = true;
                                }
                            }
                            while remaining > 0 && *written < output.len() {
                                let d = distance as usize;
                                let src = (self.window_pos + self.win_cap - d) % self.win_cap;
                                let b = self.window[src];
                                self.emit_byte(b, output, written);
                                remaining -= 1;
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
