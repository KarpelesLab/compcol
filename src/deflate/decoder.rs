//! Streaming RFC 1951 (deflate) decoder.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bits::BitReader;
use crate::error::Error;
use crate::huffman::CanonicalDecoder;
use crate::traits::{Progress, RawDecoder, RawProgress, Status};

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
/// `#[non_exhaustive]`: construct via [`DecoderConfig::default`] and the
/// `with_*` builders rather than a struct literal, so new options can be added
/// in future without breaking downstream code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl DecoderConfig {
    /// Default configuration: no preset dictionary, full 32 KiB window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the sliding window with a preset dictionary (the last
    /// `window_size` bytes are retained).
    #[must_use]
    pub fn with_dictionary(mut self, dictionary: Vec<u8>) -> Self {
        self.dictionary = dictionary;
        self
    }

    /// Set the sliding-window size in bytes (clamped to `1..=WINDOW_SIZE`).
    /// A smaller window decodes streams produced for a small-window decoder
    /// and uses less memory; back-references beyond it are rejected.
    #[must_use]
    pub fn with_window_size(mut self, window_size: usize) -> Self {
        self.window_size = window_size;
        self
    }
}

use super::inftable::{self, Alphabet, EXC, K_BAD, K_EOB, LIT, Table};
use super::tables::{CODE_LENGTH_ORDER, FIXED_DIST_LENGTHS, FIXED_LIT_LENGTHS, WINDOW_SIZE};

/// Root-table widths. 11 bits resolves nearly every literal/length code in
/// one lookup; distance codes are fewer, so 8 bits does the same for them.
const LIT_TABLE: usize = 1 << 11;
const DIST_TABLE: usize = 1 << 8;

/// The fast loop runs while at least this much output room is left: three
/// literals and a longest match, plus the up-to-15-byte overrun of the
/// chunked match copy.
const FAST_OUT_MARGIN: usize = 3 + 258 + 16;
/// ... and at least this much input: two 8-byte refills per iteration.
const FAST_IN_MARGIN: usize = 16;
/// Bytes past the end of the history ring, there only so that the fast
/// loop's 16-byte chunked copies out of the window may over-read.
const WINDOW_SLACK: usize = 16;

// ─── per-block work buffers ──────────────────────────────────────────────

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

/// The current block's Huffman tables, allocated once per decoder.
struct Tables {
    lit: Table<LIT_TABLE>,
    dist: Table<DIST_TABLE>,
    /// The tables hold the fixed code (so a run of fixed blocks builds it once).
    fixed: bool,
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
    /// Copying a match into the output.
    EmittingMatch { distance: u16, remaining: u16 },
    /// A literal decoded with no output room for it.
    PendingLiteral(u8),
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
    HuffmanBlock(HuffmanPhase),
    Done,
}

/// How the fast loop stopped.
enum FastExit {
    /// Too little input or output room left; carry on symbol by symbol.
    Margin,
    /// The block's end-of-block code was decoded.
    EndOfBlock,
}

pub struct Decoder {
    bit_reader: BitReader,
    /// Circular history buffer of `win_cap` bytes (heap-allocated to the
    /// configured window size, ≤ 32 KiB, plus [`WINDOW_SLACK`]). It holds the output of earlier
    /// calls: within a call, matches read the bytes written so far straight
    /// from the caller's output, and the window is brought up to date as
    /// the call returns.
    window: Box<[u8]>,
    /// Ring capacity = the sliding-window size = the maximum legal match
    /// distance. `1..=WINDOW_SIZE`.
    win_cap: usize,
    window_pos: usize,
    window_size: usize, // 0..=win_cap; how many valid bytes lie behind window_pos
    tables: Box<Tables>,
    state: DecState,
    last_block: bool,
    poisoned: bool,
    /// Set by [`Decoder::decode_block`] for the duration of the call: stop
    /// as soon as a block ends.
    stop_at_block: bool,
    /// A block ended during the current call.
    block_ended: bool,
    /// The configured preset dictionary (its last `win_cap` bytes), kept so
    /// that `reset` can seed the window with it again.
    dictionary: Box<[u8]>,
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
    /// Once the stream has ended this returns nothing: the decoder already
    /// leaves every byte after the final block unconsumed, so a container's
    /// trailer can be read straight from the input.
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

    /// Like [`decode`](crate::Decoder::decode), but returns as soon as a
    /// deflate block ends, like zlib's `inflate(Z_BLOCK)`.
    ///
    /// The final block is not a stop of its own: its end is the end of the
    /// stream ([`Status::StreamEnd`]). After a stop,
    /// [`at_block_boundary`](Self::at_block_boundary) is true and the input
    /// is consumed exactly up to the byte holding the block's last bit;
    /// [`unused_bits`](Self::unused_bits) says how many bits of that byte
    /// belong to the next block. The status is `InputEmpty` or `OutputFull`
    /// as usual; call again to decode the next block.
    pub fn decode_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(Progress, Status), Error> {
        self.stop_at_block = true;
        let r = crate::Decoder::decode(self, input, output);
        self.stop_at_block = false;
        r
    }

    pub(crate) fn set_stop_at_block(&mut self, stop: bool) {
        self.stop_at_block = stop;
    }

    /// True when the next thing to read is a block header: before the
    /// first block, or between two blocks.
    pub fn at_block_boundary(&self) -> bool {
        matches!(self.state, DecState::BlockHeader)
    }

    /// True once the header of the final block (`BFINAL = 1`) has been
    /// read; it stays true after the stream ends.
    pub fn in_final_block(&self) -> bool {
        self.last_block
    }

    /// Bits taken from the input but not decoded yet. Below 8 — the unused
    /// bits of the last consumed byte, as in zlib's `data_type & 7` — after
    /// [`decode_block`](Self::decode_block) stops, once the stream has
    /// ended, and when `decode` returns holding output it had no room for.
    /// When `decode` returns for want of input it can be more: the start of
    /// a field that is not complete yet.
    pub fn unused_bits(&self) -> u32 {
        self.bit_reader.bits_available()
    }

    /// Build a decoder whose sliding window holds `cap` bytes (clamped to
    /// `1..=WINDOW_SIZE`). `cap` is both the history size and the maximum
    /// legal back-reference distance.
    fn with_window_capacity(cap: usize) -> Self {
        let cap = cap.clamp(1, WINDOW_SIZE);
        Self {
            bit_reader: BitReader::new(),
            window: alloc::vec![0u8; cap + WINDOW_SLACK].into_boxed_slice(),
            win_cap: cap,
            window_pos: 0,
            window_size: 0,
            tables: Box::new(Tables {
                lit: Table::new(),
                dist: Table::new(),
                fixed: false,
            }),
            state: DecState::BlockHeader,
            last_block: false,
            poisoned: false,
            stop_at_block: false,
            block_ended: false,
            dictionary: Box::default(),
        }
    }

    /// Build a decoder with the given [`DecoderConfig`]. The configured
    /// dictionary (last 32 KiB if longer) is loaded into the sliding
    /// window before any input is consumed, so the very first block's
    /// back-references can reach into it as if it were already-decoded
    /// output.
    pub fn with_config(config: DecoderConfig) -> Self {
        let mut d = Self::with_window_capacity(config.window_size);
        let start = config.dictionary.len().saturating_sub(d.win_cap);
        let dictionary: Box<[u8]> = config.dictionary[start..].into();
        d.load_dictionary(&dictionary);
        d.dictionary = dictionary;
        d
    }

    /// Seed the sliding window with `dict`. Used internally by
    /// [`with_config`] and the zlib container's `FDICT` handling. If
    /// `dict` is longer than 32 KiB only its trailing 32 KiB is kept
    /// (anything older is unreachable from a deflate back-reference).
    /// Replaces any prior window contents.
    pub(crate) fn load_dictionary(&mut self, dict: &[u8]) {
        self.window_pos = 0;
        self.window_size = 0;
        self.push_history(dict);
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
    /// `Decoder` trait, which clears the window too (back to the configured
    /// preset dictionary, if any).
    pub fn reset_keep_window(&mut self) {
        self.bit_reader.reset();
        self.state = DecState::BlockHeader;
        self.last_block = false;
        self.poisoned = false;
        self.block_ended = false;
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

    /// Append `data` to the history ring, keeping its last `win_cap` bytes.
    fn push_history(&mut self, data: &[u8]) {
        let cap = self.win_cap;
        let data = &data[data.len().saturating_sub(cap)..];
        let n = data.len();
        if n == 0 {
            return;
        }
        let first = n.min(cap - self.window_pos);
        self.window[self.window_pos..self.window_pos + first].copy_from_slice(&data[..first]);
        self.window[..n - first].copy_from_slice(&data[first..]);
        self.window_pos += n;
        if self.window_pos >= cap {
            self.window_pos -= cap;
        }
        self.window_size = (self.window_size + n).min(cap);
    }

    /// Copy up to `len` bytes of the match at `distance` into
    /// `output[*written..]` (as many as fit); returns how many. `distance`
    /// must be within the history: the window plus `output[..*written]`.
    fn copy_match(
        &self,
        output: &mut [u8],
        written: &mut usize,
        distance: usize,
        len: usize,
    ) -> usize {
        let n = len.min(output.len() - *written);
        let mut done = 0;
        if distance > *written {
            // The start of the match lies in the window, `back` bytes
            // before its end.
            let back = distance - *written;
            let take = back.min(n);
            let mut src = if self.window_pos >= back {
                self.window_pos - back
            } else {
                self.window_pos + self.win_cap - back
            };
            while done < take {
                let span = (take - done).min(self.win_cap - src);
                output[*written + done..*written + done + span]
                    .copy_from_slice(&self.window[src..src + span]);
                done += span;
                src += span;
                if src == self.win_cap {
                    src = 0;
                }
            }
        }
        copy_overlapping(output, *written + done, distance, n - done);
        *written += n;
        n
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
            self.block_ended = true;
        }
    }

    /// Hand back the whole bytes still in the bit reader when the decoder
    /// returns for any reason other than waiting on input: the stream
    /// ended, a block ended under `decode_block`, or the output is full.
    /// This keeps `consumed` exact at the end of the stream.
    ///
    /// The bytes held are always the last ones fed in this call: a call
    /// starts either with fewer than 8 bits (handed back last time) or with
    /// bits that all belong to the pending field, so those are used up
    /// before anything else.
    fn unfeed(&mut self, stopped: bool, consumed: &mut usize) {
        let blocked_on_output = match &self.state {
            DecState::Done | DecState::Stored { .. } => true,
            DecState::HuffmanBlock(phase) => matches!(
                phase,
                HuffmanPhase::EmittingMatch { .. } | HuffmanPhase::PendingLiteral(_)
            ),
            _ => stopped,
        };
        if blocked_on_output {
            let n = self.bit_reader.unfeed_whole_bytes() as usize;
            debug_assert!(n <= *consumed);
            *consumed -= n.min(*consumed);
        }
    }
}

/// Copy `n` bytes to `out[dst..]` from `distance` bytes back, byte by byte
/// in effect (the source may overlap the destination). Exact: writes
/// nothing past `dst + n`.
fn copy_overlapping(out: &mut [u8], dst: usize, distance: usize, n: usize) {
    if n == 0 {
        return;
    }
    let src = dst - distance;
    if distance >= n {
        out.copy_within(src..src + n, dst);
    } else if distance == 1 {
        let b = out[src];
        out[dst..dst + n].fill(b);
    } else {
        // `[src, dst + done)` repeats with period `distance`, so its start
        // can be copied forward a growing span at a time.
        let mut done = 0;
        while done < n {
            let span = (distance + done).min(n - done);
            out.copy_within(src..src + span, dst + done);
            done += span;
        }
    }
}

/// The fast loop's match copy: like [`copy_overlapping`] but it copies in
/// whole chunks, so it may write up to 32 bytes from `dst` for a short
/// match and up to 15 bytes past `dst + n` for a long one; the caller
/// guarantees that room.
#[inline(always)]
fn copy_match_fast(out: &mut [u8], dst: usize, distance: usize, n: usize) {
    let mut s = dst - distance;
    let mut d = dst;
    let end = dst + n;
    if distance >= 16 {
        // Most matches are short: 16 bytes, then another 16, unrolled so
        // their lengths do not cost a loop exit; then a loop.
        let chunk: [u8; 16] = out[s..s + 16].try_into().unwrap();
        out[d..d + 16].copy_from_slice(&chunk);
        if n > 16 {
            let chunk: [u8; 16] = out[s + 16..s + 32].try_into().unwrap();
            out[d + 16..d + 32].copy_from_slice(&chunk);
        }
        if n > 32 {
            s += 32;
            d += 32;
            loop {
                let chunk: [u8; 16] = out[s..s + 16].try_into().unwrap();
                out[d..d + 16].copy_from_slice(&chunk);
                s += 16;
                d += 16;
                if d >= end {
                    break;
                }
            }
        }
    } else if distance >= 8 {
        let chunk: [u8; 8] = out[s..s + 8].try_into().unwrap();
        out[d..d + 8].copy_from_slice(&chunk);
        if n > 8 {
            let chunk: [u8; 8] = out[s + 8..s + 16].try_into().unwrap();
            out[d + 8..d + 16].copy_from_slice(&chunk);
        }
        if n > 16 {
            s += 16;
            d += 16;
            loop {
                let chunk: [u8; 8] = out[s..s + 8].try_into().unwrap();
                out[d..d + 8].copy_from_slice(&chunk);
                s += 8;
                d += 8;
                if d >= end {
                    break;
                }
            }
        }
    } else if distance == 1 {
        let chunk = [out[s]; 16];
        loop {
            out[d..d + 16].copy_from_slice(&chunk);
            d += 16;
            if d >= end {
                break;
            }
        }
    } else {
        // Short period: lay down the first 8 bytes one at a time, then copy
        // 8 at a time from a multiple of the period that is at least 8 back.
        for i in 0..8 {
            out[d + i] = out[s + i];
        }
        if n > 8 {
            let period = distance * 8usize.div_ceil(distance);
            d += 8;
            s = d - period;
            loop {
                let chunk: [u8; 8] = out[s..s + 8].try_into().unwrap();
                out[d..d + 8].copy_from_slice(&chunk);
                s += 8;
                d += 8;
                if d >= end {
                    break;
                }
            }
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
        self.block_ended = false;
        let mut stopped = false;

        loop {
            // Reached Done? Caller should now call finish(); return whatever progress we made.
            if matches!(self.state, DecState::Done) {
                break;
            }

            let initial_consumed = consumed;
            let initial_written = written;
            self.refill(input, &mut consumed);

            let made_progress = self.step(input, &mut consumed, output, &mut written)?;

            if self.block_ended && self.stop_at_block {
                stopped = true;
                break;
            }
            // If nothing changed, we're blocked on more input, more output, or both.
            if !made_progress && consumed == initial_consumed && written == initial_written {
                break;
            }
        }
        self.unfeed(stopped, &mut consumed);
        self.push_history(&output[..written]);

        Ok(RawProgress {
            // Report completion so the bridge maps this to `Status::StreamEnd`.
            // Reporting `false` here once the BFINAL block has been consumed
            // leaves a stream with trailing bytes returning `OutputFull` with
            // nothing consumed and nothing written, and a caller that loops
            // until StreamEnd (e.g. `vec::decompress_to_vec`) then spins
            // forever on unchanged state.
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
        if matches!(self.state, DecState::Done) || p.written > 0 {
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
        self.block_ended = false;
    }
}

impl Decoder {
    /// Decode literal/length/distance codes straight from `input` while at
    /// least [`FAST_IN_MARGIN`] input bytes and [`FAST_OUT_MARGIN`] output
    /// bytes remain, with no per-field bookkeeping: the bit buffer is
    /// refilled 8 bytes at a time and every field of a match is decoded in
    /// one go. Decodes exactly what the symbol-by-symbol path would.
    #[inline(never)]
    fn fast_huffman(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
        output: &mut [u8],
        written: &mut usize,
    ) -> Result<FastExit, Error> {
        let (mut acc, mut nbits) = self.bit_reader.parts();
        let mut ip = *consumed;
        let mut op = *written;
        let lit = &self.tables.lit;
        let dist_t = &self.tables.dist;
        let history = self.window_size;
        let win_cap = self.win_cap;
        let mut exit = FastExit::Margin;
        let mut err = None;

        // Refill to at least 56 bits. Bytes are taken whole; the bits of the
        // next byte that also land in `acc` above `nbits` are the same ones
        // the following refill ORs in, so they do no harm, and are cleared
        // by `set_parts` on the way out.
        macro_rules! refill {
            () => {
                if nbits < 56 {
                    let w = u64::from_le_bytes(input[ip..ip + 8].try_into().unwrap());
                    acc |= w << nbits;
                    ip += ((63 - nbits) >> 3) as usize;
                    nbits |= 56;
                }
            };
        }
        macro_rules! consume {
            ($n:expr) => {{
                let n = $n;
                acc >>= n;
                nbits -= n;
            }};
        }

        // `e` is always the entry for the bits at the bottom of `acc`,
        // looked up as soon as the previous field is dropped so the table
        // load overlaps the work in between (a match copy, say). It is
        // only acted on once the loop has checked its margins, and dropped
        // unused when the loop ends, so the slow path decodes it again.
        if input.len() - ip < FAST_IN_MARGIN {
            return Ok(exit);
        }
        refill!();
        let mut e = lit.lookup(acc);
        while input.len() - ip >= FAST_IN_MARGIN && output.len() - op >= FAST_OUT_MARGIN {
            refill!();
            let mut saved = acc;
            // Up to two literals per refill (15 bits each at most); the
            // lookup after them sees at least 26 bits, enough for any code.
            if e & LIT != 0 {
                consume!(inftable::total_len(e));
                let byte = inftable::value(e) as u8;
                saved = acc;
                e = lit.lookup(acc);
                output[op] = byte;
                op += 1;
                if e & LIT != 0 {
                    consume!(inftable::total_len(e));
                    let byte = inftable::value(e) as u8;
                    e = lit.lookup(acc);
                    output[op] = byte;
                    op += 1;
                    continue;
                }
            }
            if e & EXC != 0 {
                // At least 41 bits are left, more than any code, so an
                // unmatched code is an error now, as on the slow path.
                let k = inftable::kind(e);
                if k == K_EOB {
                    consume!(inftable::total_len(e));
                    exit = FastExit::EndOfBlock;
                } else if k == K_BAD {
                    err = Some(Error::Corrupt);
                } else {
                    err = Some(Error::InvalidHuffmanTree);
                }
                break;
            }
            // Length: code plus up to 5 extra bits, leaving at least 21 —
            // enough to look up the distance code before refilling.
            consume!(inftable::total_len(e));
            let length = (inftable::value(e) + inftable::extra_value(e, saved)) as usize;
            let de = dist_t.lookup(acc);
            refill!();
            if de & EXC != 0 {
                err = Some(if inftable::kind(de) == K_BAD {
                    Error::Corrupt
                } else {
                    Error::InvalidHuffmanTree
                });
                break;
            }
            // Distance: code plus up to 13 extra bits (28 at most), leaving
            // at least 28 for the next lookup.
            saved = acc;
            consume!(inftable::total_len(de));
            let distance = (inftable::value(de) + inftable::extra_value(de, saved)) as usize;
            e = lit.lookup(acc);
            if distance > history + op || distance > win_cap {
                err = Some(Error::InvalidDistance);
                break;
            }
            if distance <= op {
                copy_match_fast(output, op, distance, length);
                op += length;
            } else {
                op = self.copy_from_window(output, op, distance, length);
            }
        }
        if let Some(e) = err {
            return Err(self.poison(e));
        }
        self.bit_reader.set_parts(acc, nbits);
        *consumed = ip;
        *written = op;
        if let FastExit::EndOfBlock = exit {
            self.transition_after_block();
        }
        Ok(exit)
    }

    /// The fast loop's copy of a match that starts in the window (the
    /// output of earlier calls), out of line to keep the loop tight.
    /// Returns the new output position.
    #[inline(never)]
    fn copy_from_window(
        &self,
        output: &mut [u8],
        op: usize,
        distance: usize,
        length: usize,
    ) -> usize {
        let win_cap = self.win_cap;
        // The match starts `back` bytes before the end of the window.
        let back = distance - op;
        let src = if back <= self.window_pos {
            self.window_pos - back
        } else {
            self.window_pos + win_cap - back
        };
        if length <= back && src + length <= win_cap {
            // Wholly inside the window and not wrapping: chunked,
            // over-reading into the window's slack.
            let mut s = src;
            let mut d = op;
            let end = op + length;
            loop {
                let chunk: [u8; 16] = self.window[s..s + 16].try_into().unwrap();
                output[d..d + 16].copy_from_slice(&chunk);
                s += 16;
                d += 16;
                if d >= end {
                    break;
                }
            }
            end
        } else {
            let mut w = op;
            self.copy_match(output, &mut w, distance, length);
            w
        }
    }

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
                        // Fixed-Huffman block: the static tables, built once
                        // for a run of fixed blocks.
                        if !self.tables.fixed {
                            let t = &mut *self.tables;
                            t.lit.build(&FIXED_LIT_LENGTHS, Alphabet::LitLen)?;
                            t.dist.build(&FIXED_DIST_LENGTHS, Alphabet::Dist)?;
                            t.fixed = true;
                        }
                        self.state = DecState::HuffmanBlock(HuffmanPhase::NextSymbol);
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
                    output[*written] = self.bit_reader.peek(8) as u8;
                    *written += 1;
                    self.bit_reader.drop_bits(8);
                    remaining -= 1;
                    progress = true;
                }
                // Then copy raw input bytes directly.
                let n = (remaining as usize)
                    .min(input.len() - *consumed)
                    .min(output.len() - *written);
                if n > 0 {
                    output[*written..*written + n]
                        .copy_from_slice(&input[*consumed..*consumed + n]);
                    *written += n;
                    *consumed += n;
                    remaining -= n as u32;
                    progress = true;
                }
                if remaining == 0 {
                    // Ending the block is progress too, even an empty one.
                    self.transition_after_block();
                    progress = true;
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
                            let p = work.pos as usize;
                            work.lengths[p..p + n].fill(v);
                            work.pos += n as u16;
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
                            let p = work.pos as usize;
                            work.lengths[p..p + n].fill(0);
                            work.pos += n as u16;
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
                            let p = work.pos as usize;
                            work.lengths[p..p + n].fill(0);
                            work.pos += n as u16;
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

                // Both length arrays are filled; build the two block tables.
                let hlit = work.hlit_count as usize;
                let hdist = work.hdist_count as usize;
                let t = &mut *self.tables;
                t.fixed = false;
                let r = t
                    .lit
                    .build(&work.lengths[..hlit], Alphabet::LitLen)
                    .and_then(|()| {
                        t.dist
                            .build(&work.lengths[hlit..hlit + hdist], Alphabet::Dist)
                    });
                r.map_err(|e| self.poison(e))?;
                self.state = DecState::HuffmanBlock(HuffmanPhase::NextSymbol);
                Ok(true)
            }

            DecState::HuffmanBlock(mut phase) => {
                let mut progress = false;
                loop {
                    match phase {
                        HuffmanPhase::NextSymbol => {
                            if input.len() - *consumed >= FAST_IN_MARGIN
                                && output.len() - *written >= FAST_OUT_MARGIN
                            {
                                let before = (*consumed, *written, self.bit_reader.parts());
                                let exit = self.fast_huffman(input, consumed, output, written)?;
                                if before != (*consumed, *written, self.bit_reader.parts()) {
                                    progress = true;
                                }
                                if let FastExit::EndOfBlock = exit {
                                    return Ok(true);
                                }
                            }
                            let (bits, avail) = self.bit_reader.parts();
                            let e = match self.tables.lit.decode_short(bits, avail) {
                                Ok(Some(e)) => e,
                                Ok(None) => break,
                                Err(e) => return Err(self.poison(e)),
                            };
                            self.bit_reader.drop_bits(inftable::code_len(e));
                            progress = true;
                            if e & LIT != 0 {
                                let byte = inftable::value(e) as u8;
                                if *written >= output.len() {
                                    // No room: hold the literal until the
                                    // next call.
                                    phase = HuffmanPhase::PendingLiteral(byte);
                                    break;
                                }
                                output[*written] = byte;
                                *written += 1;
                            } else if e & EXC == 0 {
                                phase = HuffmanPhase::LengthExtra {
                                    base_length: inftable::value(e) as u16,
                                    extra_bits: inftable::extra_bits(e) as u8,
                                };
                            } else if inftable::kind(e) == K_EOB {
                                self.transition_after_block();
                                return Ok(true);
                            } else {
                                return Err(self.poison(Error::Corrupt));
                            }
                        }
                        HuffmanPhase::LengthExtra {
                            base_length,
                            extra_bits,
                        } => {
                            if self.bit_reader.bits_available() < extra_bits as u32 {
                                break;
                            }
                            let extra = self.bit_reader.peek(extra_bits as u32) as u16;
                            self.bit_reader.drop_bits(extra_bits as u32);
                            let length = base_length + extra;
                            phase = HuffmanPhase::DistanceSymbol { length };
                            progress = true;
                        }
                        HuffmanPhase::DistanceSymbol { length } => {
                            let (bits, avail) = self.bit_reader.parts();
                            let e = match self.tables.dist.decode_short(bits, avail) {
                                Ok(Some(e)) => e,
                                Ok(None) => break,
                                Err(e) => return Err(self.poison(e)),
                            };
                            self.bit_reader.drop_bits(inftable::code_len(e));
                            progress = true;
                            if e & EXC != 0 {
                                return Err(self.poison(Error::Corrupt));
                            }
                            phase = HuffmanPhase::DistanceExtra {
                                length,
                                base_dist: inftable::value(e) as u16,
                                extra_bits: inftable::extra_bits(e) as u8,
                            };
                        }
                        HuffmanPhase::DistanceExtra {
                            length,
                            base_dist,
                            extra_bits,
                        } => {
                            if self.bit_reader.bits_available() < extra_bits as u32 {
                                break;
                            }
                            let extra = self.bit_reader.peek(extra_bits as u32) as u16;
                            self.bit_reader.drop_bits(extra_bits as u32);
                            let distance = base_dist + extra;
                            // Reject distances reaching before the start of
                            // the output (the window plus what this call has
                            // written), and — for a reduced window — anything
                            // beyond the configured size, which mirrors zlib's
                            // `inflateInit2(-wbits)` Z_DATA_ERROR.
                            if distance == 0
                                || (distance as usize) > self.window_size + *written
                                || (distance as usize) > self.win_cap
                            {
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
                            remaining,
                        } => {
                            let n = self.copy_match(
                                output,
                                written,
                                distance as usize,
                                remaining as usize,
                            );
                            if n > 0 {
                                progress = true;
                            }
                            let remaining = remaining - n as u16;
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
                        HuffmanPhase::PendingLiteral(byte) => {
                            if *written >= output.len() {
                                break;
                            }
                            output[*written] = byte;
                            *written += 1;
                            progress = true;
                            phase = HuffmanPhase::NextSymbol;
                        }
                    }
                }
                self.state = DecState::HuffmanBlock(phase);
                Ok(progress)
            }
        }
    }
}
