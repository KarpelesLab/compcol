//! XPress Huffman streaming encoder.
//!
//! Strategy: buffer up to 65,536 bytes of input then close out one block.
//! Each block is encoded by:
//!
//!   1. Picking literal/match tokens via a simple greedy LZ77 search
//!      against the bytes of the current block (no inter-block matches —
//!      MS-XCA's distance encoding is unbounded in principle, but we
//!      keep matches inside the current block to make the decoder's
//!      `MatchOffset` byte-copy stay within emitted output).
//!   2. Building a frequency histogram, running length-limited
//!      package-merge (≤ 15 bits), packing the 256-byte length table.
//!   3. Encoding tokens into a bit-plus-raw-byte stream using the
//!      "deferred word slot" pattern in [`BlockWriter`] below: word slots
//!      are reserved at the wire position the decoder will read them
//!      from, and patched as bits accumulate, so raw escape bytes can
//!      land at the byte offset the decoder's `CurrentPosition` is at.
//!
//! The output is byte-for-byte compatible with the MS-XCA decoder for
//! any input we accept (round-trip tests verify this against our own
//! decoder; the framing wrapper is the 4-byte LE u32 of the input
//! length described in [`super`]).
//!
//! No level dial — the encoder always runs at its default greedy mode.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Flush, RawEncoder, RawProgress};

use super::huffman::{NUM_SYMBOLS, length_limited_huffman, lengths_to_codes, pack_lengths};

const BLOCK_BYTES: usize = 65536;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 65535 + 3; // length field can encode up to 65535+3 via the 2-byte escape path.
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NIL: u32 = u32::MAX;

/// Public encoder configuration. Kept for API compatibility with the
/// `_with_level` factory helper; the level value is unused since this
/// codec has no compression levels.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncoderConfig {
    /// Reserved. Currently ignored.
    pub level: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Need to emit the 4-byte LE length header on the next call. Set
    /// only once at startup; `finish` may revisit if reset has happened.
    NeedHeader,
    /// Buffering input for the current block.
    Buffering,
    /// All emission complete.
    Done,
}

pub struct Encoder {
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
    out_idx: usize,

    phase: Phase,
    total_input: u64,
    header_emitted: bool,

    #[allow(dead_code)]
    config: EncoderConfig,

    // Hash table for LZ77 match finding. `head[h]` stores the most-recent
    // position with hash `h`, or `NIL`. `prev[i]` is the previous position
    // with the same hash as `in_buf[i]`. Cleared per block (matches don't
    // cross block boundaries — the decoder copies from `OutputBuffer`
    // which has the previously-decoded bytes, but limiting to in-block
    // keeps the encoder simpler and still decodes correctly).
    head: Vec<u32>,
    prev: Vec<u32>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }
    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            in_buf: Vec::new(),
            out_buf: Vec::new(),
            out_idx: 0,
            phase: Phase::NeedHeader,
            total_input: 0,
            header_emitted: false,
            config,
            head: alloc::vec![NIL; HASH_SIZE],
            prev: Vec::new(),
        }
    }

    fn drain_out_into(&mut self, output: &mut [u8]) -> usize {
        let avail = self.out_buf.len() - self.out_idx;
        let n = avail.min(output.len());
        output[..n].copy_from_slice(&self.out_buf[self.out_idx..self.out_idx + n]);
        self.out_idx += n;
        if self.out_idx == self.out_buf.len() {
            self.out_buf.clear();
            self.out_idx = 0;
        }
        n
    }

    /// Encode every fully-collected 64 KiB block from `in_buf`, leaving
    /// any tail (less than 64 KiB) buffered. Called during `raw_encode`.
    fn flush_full_blocks(&mut self) -> Result<(), Error> {
        while self.in_buf.len() >= BLOCK_BYTES {
            let block: Vec<u8> = self.in_buf.drain(..BLOCK_BYTES).collect();
            self.encode_block(&block, false)?;
        }
        Ok(())
    }

    fn encode_block(&mut self, data: &[u8], is_last: bool) -> Result<(), Error> {
        // 1. Parse to tokens.
        let tokens = lz77_parse(data, &mut self.head, &mut self.prev);

        // 2. Frequency histogram + EOF marker.
        let mut freqs = [0u32; NUM_SYMBOLS];
        for tok in &tokens {
            match tok {
                Token::Literal(b) => freqs[*b as usize] += 1,
                Token::Match { length, distance } => {
                    let dist_hi = high_bit_index(*distance);
                    let len_minus_3 = length - 3;
                    let class = if len_minus_3 < 15 { len_minus_3 } else { 15 };
                    let sym = 256 + class + 16 * dist_hi;
                    freqs[sym as usize] += 1;
                }
            }
        }
        if is_last {
            freqs[256] += 1;
        }

        // 3. Length-limited code lengths.
        let lengths = length_limited_huffman(&freqs, 15);
        let codes = lengths_to_codes(&lengths);

        // 4. Pack length table.
        let packed = pack_lengths(&lengths);
        self.out_buf.extend_from_slice(&packed);

        // 5. Bit-stream emission.
        let mut bw = BlockWriter::new();
        for tok in &tokens {
            match tok {
                Token::Literal(b) => {
                    let sym = *b as usize;
                    bw.write_bits(codes[sym] as u32, lengths[sym] as u32, &mut self.out_buf);
                }
                Token::Match { length, distance } => {
                    let dist_hi = high_bit_index(*distance);
                    let len_minus_3 = length - 3;
                    let class = if len_minus_3 < 15 { len_minus_3 } else { 15 };
                    let sym = (256 + class + 16 * dist_hi) as usize;
                    bw.write_bits(codes[sym] as u32, lengths[sym] as u32, &mut self.out_buf);
                    // Long-length escape.
                    if len_minus_3 >= 15 {
                        let remaining = len_minus_3 - 15;
                        if remaining < 255 {
                            // remaining fits in a byte but encoded as len_minus_3 - 15
                            // which lands in 0..=254; spec wants the *full* length to
                            // be readable by inverting the read: ReadByte returns
                            // a value `b`; if b == 255, ReadByte further reads a u16
                            // that represents the length itself. So for the short-escape
                            // path the byte we write should be remaining (i.e. length - 3 - 15).
                            bw.write_raw_byte(remaining as u8, &mut self.out_buf);
                        } else {
                            // Long escape: byte 0xFF + u16 LE of the full length.
                            bw.write_raw_byte(255, &mut self.out_buf);
                            let full_len_minus_3 = len_minus_3 as u16;
                            bw.write_raw_byte((full_len_minus_3 & 0xFF) as u8, &mut self.out_buf);
                            bw.write_raw_byte(
                                ((full_len_minus_3 >> 8) & 0xFF) as u8,
                                &mut self.out_buf,
                            );
                        }
                    }
                    // Distance extras.
                    if dist_hi > 0 {
                        let low_mask = (1u32 << dist_hi) - 1;
                        let dist_low = (*distance) & low_mask;
                        bw.write_bits(dist_low, dist_hi, &mut self.out_buf);
                    }
                }
            }
        }
        if is_last {
            // EOF marker (symbol 256).
            bw.write_bits(codes[256] as u32, lengths[256] as u32, &mut self.out_buf);
        }
        // Pad any reserved-but-unfilled word slots by re-emitting the
        // EOF code until they're saturated. The decoder will read the
        // first EOF and check `output_emitted == total_output`; if so it
        // transitions to DrainTail and ignores further codes. Without
        // this padding, reserved slots stay zero and the decoder
        // interprets them as the lowest-code symbol (which is whatever
        // came first in the canonical order).
        bw.pad_with(codes[256] as u32, lengths[256] as u32, &mut self.out_buf);
        if is_last {
            // The MS-XCA decoder pseudocode refills the 32-bit register
            // eagerly after every symbol consumption, even when no
            // further bits will be read. Pad with one zero word at end
            // of the LAST block so the EOF-symbol's trailing refill
            // always succeeds. Non-last blocks don't need this — the
            // decoder transitions on `output_emitted >= block_end` and
            // never speculatively refills.
            self.out_buf.push(0);
            self.out_buf.push(0);
        }
        Ok(())
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        // The 4-byte framing header carries `total_input`, which we
        // don't know until `finish` is called. Hold all encoded bytes
        // internally until then so the header can sit at byte 0.
        // (`drain_out_into` is only used by `raw_finish`.)
        let _ = &mut written;
        let _ = output;

        match self.phase {
            Phase::NeedHeader => {
                self.phase = Phase::Buffering;
            }
            Phase::Done => {
                return Ok(RawProgress {
                    consumed: 0,
                    written: 0,
                    done: false,
                });
            }
            Phase::Buffering => {}
        }

        if !input.is_empty() {
            self.in_buf.extend_from_slice(input);
            self.total_input += input.len() as u64;
            consumed = input.len();
        }

        // Encode any full blocks present. Their bytes accumulate in
        // `self.out_buf`; nothing is sent to the caller until `finish`.
        self.flush_full_blocks()?;

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        // First, ensure all blocks have been emitted and the header is in
        // place. This only runs once (idempotent on phase transitions);
        // subsequent calls just drain whatever's left in `out_buf`.
        if !matches!(self.phase, Phase::Done) {
            if self.in_buf.len() >= BLOCK_BYTES {
                self.flush_full_blocks()?;
            }
            if !self.in_buf.is_empty() {
                let tail: Vec<u8> = core::mem::take(&mut self.in_buf);
                self.encode_block(&tail, true)?;
            } else if self.total_input == 0 {
                // Empty input: header alone (total_output = 0) tells the
                // decoder to terminate.
            } else {
                // total_input was a multiple of BLOCK_BYTES; emit one
                // trailing empty block carrying just the EOF marker.
                let empty: Vec<u8> = Vec::new();
                self.encode_block(&empty, true)?;
            }
            if !self.header_emitted {
                let hdr = (self.total_input as u32).to_le_bytes();
                // Prepend the 4 header bytes.
                self.out_buf.splice(0..0, hdr.iter().copied());
                self.header_emitted = true;
            }
            self.phase = Phase::Done;
        }
        written += self.drain_out_into(&mut output[written..]);
        let done = self.out_idx == self.out_buf.len();
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.out_buf.clear();
        self.out_idx = 0;
        self.phase = Phase::NeedHeader;
        self.total_input = 0;
        self.header_emitted = false;
        for h in self.head.iter_mut() {
            *h = NIL;
        }
        self.prev.clear();
    }

    fn raw_flush(&mut self, _output: &mut [u8], _mode: Flush) -> Result<RawProgress, Error> {
        // XPress Huffman has no in-band sync marker (blocks are 64 KiB
        // boundaries but they're determined by output position, not
        // an explicit marker). Per-format flush is a no-op.
        Ok(RawProgress {
            consumed: 0,
            written: 0,
            done: true,
        })
    }
}

// ─── LZ77 token parser ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Token {
    Literal(u8),
    Match { length: u32, distance: u32 },
}

fn hash3(b: &[u8]) -> u32 {
    // 24-bit -> 15-bit hash. Knuth's golden-ratio multiplicative.
    let v = (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16);
    v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)
}

fn lz77_parse(data: &[u8], head: &mut [u32], prev: &mut Vec<u32>) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    if data.len() < MIN_MATCH {
        for &b in data {
            tokens.push(Token::Literal(b));
        }
        return tokens;
    }
    for h in head.iter_mut() {
        *h = NIL;
    }
    prev.clear();
    prev.resize(data.len(), NIL);

    let mut i: usize = 0;
    let stop = data.len() - (MIN_MATCH - 1);
    while i < stop {
        let h = hash3(&data[i..i + MIN_MATCH]) as usize;
        // Walk the chain looking for the best (longest) match. Bound the
        // walk so worst-case quadratic input doesn't time out.
        let max_chain = 64usize;
        let mut best_len: usize = 0;
        let mut best_dist: usize = 0;
        let mut cur = head[h];
        let mut tries = 0usize;
        while cur != NIL && tries < max_chain {
            let pos = cur as usize;
            if pos >= i {
                break;
            }
            let dist = i - pos;
            // Distance must be representable: dist_hi <= 15 → dist < 2^16
            // is a safe ceiling. Larger distances are rejected by the
            // encoder (just drop the candidate).
            if dist == 0 || dist >= 65536 {
                cur = prev[pos];
                tries += 1;
                continue;
            }
            // Compute match length.
            let mut l = 0usize;
            let max_possible = (data.len() - i).min(MAX_MATCH);
            while l < max_possible && data[pos + l] == data[i + l] {
                l += 1;
            }
            if l >= MIN_MATCH && l > best_len {
                best_len = l;
                best_dist = dist;
                if l >= 32 {
                    break;
                }
            }
            cur = prev[pos];
            tries += 1;
        }
        // Insert i into the chain.
        prev[i] = head[h];
        head[h] = i as u32;

        // Sym=256 (class=0, dist_hi=0, i.e. length=3 + distance=1) is
        // ambiguous with the EOF marker. Demote these matches to literals
        // so the decoder never has to disambiguate via output-position
        // bookkeeping.
        if best_len == MIN_MATCH && best_dist == 1 {
            best_len = 0;
        }
        if best_len >= MIN_MATCH {
            tokens.push(Token::Match {
                length: best_len as u32,
                distance: best_dist as u32,
            });
            // Insert every byte covered by the match into the hash chain
            // (except `i` already done) so subsequent positions can find
            // them. Skip the last MIN_MATCH-1 to keep within bounds.
            let mut j = i + 1;
            let end = (i + best_len).min(stop);
            while j < end {
                let h2 = hash3(&data[j..j + MIN_MATCH]) as usize;
                prev[j] = head[h2];
                head[h2] = j as u32;
                j += 1;
            }
            i += best_len;
        } else {
            tokens.push(Token::Literal(data[i]));
            i += 1;
        }
    }
    while i < data.len() {
        tokens.push(Token::Literal(data[i]));
        i += 1;
    }
    tokens
}

fn high_bit_index(v: u32) -> u32 {
    debug_assert!(v > 0);
    31 - v.leading_zeros()
}

// ─── Bit emitter with deferred word slots ─────────────────────────────────

/// Block-scope bit writer that interleaves raw bytes with MSB-first bit
/// packing into 16-bit LE words.
///
/// The MS-XCA reader prefills 2 words before consuming any bits, so the
/// writer reserves those 2 slots up-front. Subsequent `write_bits` calls
/// patch the head reserved slot once 16 bits have accumulated; new slots
/// are reserved at the writer's high-water mark when an emit would
/// otherwise have no slot to land in.
///
/// `write_raw_byte` is the tricky one: an escape byte must land at the
/// CURRENT high-water mark on wire, but any partial bits already in the
/// accumulator have to live in word slots that come BEFORE the byte.
/// We achieve that by ensuring at least
/// `ceil(pending_bits / 16)` reserved slots exist before pushing the byte.
struct BlockWriter {
    acc: u32,
    pending_bits: u32,
    slots: VecDeque<usize>,
    /// Whether we've reserved the two initial word slots yet.
    primed: bool,
    /// Cumulative bits passed to [`write_bits`] since [`prime`]. Used to
    /// compute the decoder's expected word count at any raw-byte
    /// insertion point.
    cum_bits: u32,
    /// Cumulative word slots reserved (prime + on-demand). Each slot is
    /// 2 wire bytes.
    words_reserved: u32,
}

impl BlockWriter {
    fn new() -> Self {
        Self {
            acc: 0,
            pending_bits: 0,
            slots: VecDeque::new(),
            primed: false,
            cum_bits: 0,
            words_reserved: 0,
        }
    }

    fn prime(&mut self, out: &mut Vec<u8>) {
        if self.primed {
            return;
        }
        self.primed = true;
        for _ in 0..2 {
            let idx = out.len();
            out.push(0);
            out.push(0);
            self.slots.push_back(idx);
            self.words_reserved += 1;
        }
    }

    /// Reserve a new 2-byte word slot at the current end of `out` and
    /// queue it for later patching by [`write_bits`].
    fn reserve_slot(&mut self, out: &mut Vec<u8>) {
        let idx = out.len();
        out.push(0);
        out.push(0);
        self.slots.push_back(idx);
        self.words_reserved += 1;
    }

    /// Like [`reserve_slot`] but returns the new slot's index for
    /// immediate use without queueing.
    fn reserve_and_return(&mut self, out: &mut Vec<u8>) -> usize {
        let idx = out.len();
        out.push(0);
        out.push(0);
        self.words_reserved += 1;
        idx
    }

    /// Number of wire words the decoder will have read at this point in
    /// the stream, given `cum_bits` bits emitted so far.
    fn decoder_words_at(cum_bits: u32) -> u32 {
        // Decoder reads 2 prefill words then 1 word per refill. Refills
        // fire each time EBC goes < 0 (EBC starts at 16, decreases by
        // consumed bits, +16 per refill). For N bits consumed, refills
        // = max(0, ceil((N - 16) / 16)).
        if cum_bits <= 16 {
            2
        } else {
            2 + (cum_bits - 16).div_ceil(16)
        }
    }

    fn patch(out: &mut [u8], idx: usize, word: u16) {
        out[idx] = word as u8;
        out[idx + 1] = (word >> 8) as u8;
    }

    fn write_bits(&mut self, value: u32, len: u32, out: &mut Vec<u8>) {
        if !self.primed {
            self.prime(out);
        }
        if len == 0 {
            return;
        }
        debug_assert!(len <= 16);
        let value = value & ((1u32 << len) - 1);
        // Append `len` bits below the existing partial accumulator.
        // We store `acc` packed at the high end of 32 bits so the top 16
        // bits can be extracted as the next word when pending_bits >= 16.
        // To do that cleanly, shift the new bits into the slot starting
        // at bit (31 - pending_bits).
        self.acc |= value << (32 - self.pending_bits - len);
        self.pending_bits += len;
        self.cum_bits += len;
        while self.pending_bits >= 16 {
            let word = ((self.acc >> 16) & 0xFFFF) as u16;
            self.acc <<= 16;
            self.pending_bits -= 16;
            let idx = self
                .slots
                .pop_front()
                .unwrap_or_else(|| self.reserve_and_return(out));
            Self::patch(out, idx, word);
        }
    }

    fn write_raw_byte(&mut self, b: u8, out: &mut Vec<u8>) {
        if !self.primed {
            self.prime(out);
        }
        // Ensure enough word slots are reserved to match the decoder's
        // CP at this point: the byte must land where the decoder reads
        // it. The decoder's word-read count after `cum_bits` is given
        // by `decoder_words_at`; reserve extra slots until our count
        // matches, so the byte lands at byte offset (W * 2) in the
        // current block payload.
        let required = Self::decoder_words_at(self.cum_bits);
        while self.words_reserved < required {
            self.reserve_slot(out);
        }
        out.push(b);
    }

    /// Re-emit `(value, len)` bits until all reserved-but-unfilled slots
    /// have been patched. Called once at end-of-block to ensure those
    /// slots don't contain garbage zero bits (which would decode as
    /// whichever symbol claims code `000…`).
    fn pad_with(&mut self, value: u32, len: u32, out: &mut Vec<u8>) {
        if !self.primed {
            self.prime(out);
        }
        if len == 0 {
            // Can't pad — fall back to the regular finalize semantics.
            self.finalize(out);
            return;
        }
        while !self.slots.is_empty() || self.pending_bits >= 16 {
            self.write_bits(value, len, out);
            // Safety: each iteration consumes either a slot (via flush)
            // or accumulates pending_bits. The loop terminates because
            // each slot fill drops one slot, and pending_bits doesn't
            // grow unbounded (we only enter the loop when there are
            // slots left or 16+ pending bits to flush).
        }
        self.finalize(out);
    }

    fn finalize(&mut self, out: &mut Vec<u8>) {
        if !self.primed {
            self.prime(out);
        }
        // Flush remaining pending bits into the next reserved slot (or a
        // freshly-reserved one), padded with zeros at the low end.
        if self.pending_bits > 0 {
            // Bits live in the top `pending_bits` of `acc`; pad low bits
            // with zero by taking the top 16 of acc.
            let word = ((self.acc >> 16) & 0xFFFF) as u16;
            self.acc = 0;
            self.pending_bits = 0;
            let idx = self
                .slots
                .pop_front()
                .unwrap_or_else(|| self.reserve_and_return(out));
            Self::patch(out, idx, word);
        }
        // Ensure the wire has at least `decoder_words_at(cum_bits)`
        // word slots — the decoder triggers an extra refill for the
        // bottom of the register that the encoder hasn't accounted for
        // via its own pending-bits flushes. Without this top-up the
        // decoder advances its CP past the encoder's last written word
        // and into whatever comes next (garbage or the start of the
        // following block's table), breaking inter-block alignment.
        let required = Self::decoder_words_at(self.cum_bits);
        while self.words_reserved < required {
            let _ = self.reserve_and_return(out);
        }
        // Any reserved-but-unfilled slots stay as zero placeholders. The
        // decoder will read them as bits and treat them as garbage trailing
        // codes — which is fine because the decoder stops on
        // `output_emitted == total_output` (our framing header).
        self.slots.clear();
    }
}
