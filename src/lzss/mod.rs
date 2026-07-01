//! LZSS (Storer–Szymanski LZ77 variant) — Okumura's reference layout.
//!
//! The variant implemented here is the canonical "LZSS.C" flavour from
//! Haruhiko Okumura's public-domain `lzss.c` reference, used as the
//! interchange format by countless game / embedded codebases:
//!
//! - Ring buffer size `N = 4096` bytes, **initialized to `0x20` (ASCII
//!   space)**. This dict-init-with-spaces convention is the single
//!   source of the most common interop bug — a stream encoded against
//!   a zero-initialized dictionary decodes to garbage at every match
//!   that reaches into the still-untouched part of the window. Both
//!   sides MUST start with the same 0x20 fill.
//! - Maximum match length `F = 18`, minimum match length `THRESHOLD + 1
//!   = 3`. The on-wire 4-bit length field stores `len − 3`, so values
//!   `0..=15` map to actual match lengths `3..=18`.
//! - Tokens come in groups of 8, each group preceded by a single
//!   "flag byte". Within the flag byte the bits are walked LSB-first:
//!   bit set = literal (1 byte body), bit clear = match (2 byte body).
//! - Match body is two bytes laid out as
//!   `low8(pos)` then `((pos >> 4) & 0xF0) | (len − 3)`.
//!   That packs a 12-bit absolute ring-buffer index `pos` and a 4-bit
//!   length minus-three.
//!
//! ## Wire framing
//!
//! Raw Okumura LZSS streams carry no in-band length: the decoder
//! traditionally relies on an out-of-band `uncompressed_size` or on
//! input exhaustion. This crate prepends a **4-byte little-endian
//! uncompressed length** before the LZSS payload so callers can tell
//! cleanly where a stream ends:
//!
//! ```text
//! +----------------------+================+
//! | uncompressed_len_le4 | LZSS payload   |
//! +----------------------+================+
//! ```
//!
//! Callers integrating with a third-party byte stream that has its own
//! length framing should pre-strip that framing and prepend our 4-byte
//! header, or wrap their own framing layer around the raw payload that
//! [`Decoder`] accepts after consuming the four header bytes.
//!
//! ## Interop notes
//!
//! The ring buffer index encoded into the match token is an **absolute
//! position** inside the 4 KiB ring, not a back-distance. Some derived
//! formats (e.g. ADC, parts of LZS) shift to a back-distance encoding
//! — they are NOT bytewise compatible with Okumura's LZSS even at the
//! same window size. This module implements Okumura exactly.
//!
//! References:
//! - Storer, J. A.; Szymanski, T. G. (1982), "Data compression via
//!   textual substitution", JACM 29(4).
//! - Okumura's reference: <https://oku.edu.mie-u.ac.jp/~okumura/compression/>
//!   (public domain).
//! - Wikipedia: <https://en.wikipedia.org/wiki/LZSS>.

#![cfg_attr(docsrs, doc(cfg(feature = "lzss")))]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for LZSS (Okumura layout).
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzss;

impl Algorithm for Lzss {
    const NAME: &'static str = "lzss";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

// ─── shared constants ─────────────────────────────────────────────────────

/// Ring buffer size (4 KiB).
const N: usize = 4096;
/// Maximum match length.
const F: usize = 18;
/// Threshold: matches of length `<= THRESHOLD` are emitted as literals.
const THRESHOLD: usize = 2;
/// Fill byte for the initial ring buffer state — ASCII space, per Okumura.
const NUL: u8 = 0x20;

// ─── encoder ──────────────────────────────────────────────────────────────

/// Streaming LZSS encoder.
///
/// Implementation strategy: buffer the full input across `raw_encode`
/// calls, then produce the encoded payload (including the 4-byte length
/// header) inside `raw_finish`. This matches what other "no in-band
/// framing" codecs in this crate do (snappy, adc) and sidesteps the
/// otherwise-tricky problem of carrying a partial 8-token group plus a
/// half-resolved match across encode calls. Memory cost is `O(input)`;
/// LZSS is typically used on small payloads (resource forks, level
/// data, embedded firmware) where that is fine.
#[derive(Debug)]
pub struct Encoder {
    /// Raw input accumulated so far.
    input: Vec<u8>,
    /// Encoded payload, built lazily by `finalize`.
    output: Vec<u8>,
    /// Read cursor into `output` for streaming drains.
    out_cursor: usize,
    /// True once `finalize` has been run.
    finalized: bool,
}

impl Encoder {
    /// Construct a fresh encoder.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            finalized: false,
        }
    }

    /// Encode `self.input` into `self.output`. Called once from `raw_finish`.
    fn finalize(&mut self) {
        // 4-byte LE uncompressed length header.
        let n_data = self.input.len() as u32;
        self.output.extend_from_slice(&n_data.to_le_bytes());

        if self.input.is_empty() {
            return;
        }

        // Match finding runs over the raw input with a hash chain instead of
        // the Okumura ring's O(N) brute-force scan per position. The decoder's
        // ring is byte-identical to what a matching Okumura encoder would build,
        // so a match whose source is input position `cand` is encoded with the
        // ring index the decoder expects: `(cand + N - F) & (N - 1)`. The
        // reachable dictionary is the `N - F` bytes before the current position.
        //
        // The output size depends only on the match *lengths* (every match is a
        // 2-byte token, every literal a 1-byte token), so finding the same
        // longest length — via a fully-walked chain of same-prefix candidates —
        // reproduces the brute-force ratio while cutting encode from O(N·n) to
        // O(n · chain). (The only difference is the initial `0x20` ring fill,
        // which the input-based finder can't reference; its ratio effect is
        // negligible.)
        let input = core::mem::take(&mut self.input);
        let data = input.as_slice();
        let n = data.len();
        const MIN_MATCH: usize = THRESHOLD + 1;

        const HASH_BITS: u32 = 15;
        const HASH_SIZE: usize = 1 << HASH_BITS;
        // `u32` positions (halving the `prev` ring vs `usize`) — the reachable
        // window is 4 KiB and inputs this codec sees fit in 32 bits; the smaller
        // array is markedly cheaper to allocate/zero on match-heavy input where
        // the finder itself does almost no work.
        const NIL: u32 = u32::MAX;
        let mut head = vec![NIL; HASH_SIZE];
        let mut prev = vec![NIL; n];
        let hash3 = |i: usize| -> usize {
            let a = data[i] as usize;
            let b = data[i + 1] as usize;
            let c = data[i + 2] as usize;
            ((a << 10) ^ (b << 5) ^ c).wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)
                & (HASH_SIZE - 1)
        };

        // Group buffer: 1 flag byte + up to 8 tokens × 2 bytes = 17.
        let mut code_buf = [0u8; 17];
        let mut code_ptr: usize = 1;
        let mut mask: u8 = 1;

        let mut cur = 0usize;
        // Positions `[0, inserted)` are already spliced into the chains.
        let mut inserted = 0usize;
        while cur < n {
            let mut best_len = 0usize;
            let mut best_cand = 0usize;
            if cur + MIN_MATCH <= n {
                let max_len = F.min(n - cur);
                let min_pos = cur.saturating_sub(N - F);
                let h = hash3(cur);
                let mut cand = head[h];
                // Walk the whole chain (candidates share the 3-byte prefix) so
                // the longest match equals the brute-force result; only stop
                // early once we hit the max length `F`.
                while cand != NIL && (cand as usize) >= min_pos {
                    let cp = cand as usize;
                    let mut k = 0usize;
                    while k < max_len && data[cp + k] == data[cur + k] {
                        k += 1;
                    }
                    if k > best_len {
                        best_len = k;
                        best_cand = cp;
                        if best_len >= F {
                            break;
                        }
                    }
                    cand = prev[cp];
                }
            }

            let advance;
            if best_len <= THRESHOLD {
                advance = 1;
                code_buf[0] |= mask;
                code_buf[code_ptr] = data[cur];
                code_ptr += 1;
            } else {
                advance = best_len;
                let best_pos = (best_cand + N - F) & (N - 1);
                code_buf[code_ptr] = (best_pos & 0xFF) as u8;
                code_ptr += 1;
                code_buf[code_ptr] =
                    (((best_pos >> 4) & 0xF0) | ((best_len - (THRESHOLD + 1)) & 0x0F)) as u8;
                code_ptr += 1;
            }

            mask = mask.wrapping_shl(1);
            if mask == 0 {
                self.output.extend_from_slice(&code_buf[..code_ptr]);
                code_buf[0] = 0;
                code_ptr = 1;
                mask = 1;
            }

            // Splice every passed-over position into the chains (including
            // match interiors) so later positions can reference them.
            let insert_end = cur + advance;
            while inserted < insert_end {
                if inserted + MIN_MATCH <= n {
                    let h = hash3(inserted);
                    prev[inserted] = head[h];
                    head[h] = inserted as u32;
                }
                inserted += 1;
            }
            cur += advance;
        }

        if code_ptr > 1 {
            self.output.extend_from_slice(&code_buf[..code_ptr]);
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finalized {
            self.finalize();
            self.finalized = true;
        }
        let remaining = self.output.len() - self.out_cursor;
        let n = remaining.min(output.len());
        output[..n].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + n]);
        self.out_cursor += n;
        let done = self.out_cursor >= self.output.len();
        Ok(RawProgress {
            consumed: 0,
            written: n,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.finalized = false;
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Streaming decoder phase. The match-decoding states carry their own
/// pos/len so an output-full pause leaves them resumable byte-by-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Consuming the 4-byte little-endian length header.
    Header,
    /// Need a flag byte introducing the next 8-token group.
    Flags,
    /// Mid-group, looking at the next bit of the flag byte.
    Token,
    /// Need the literal byte for the current literal token.
    NeedLiteral,
    /// Have a literal stashed in `pending_literal`, waiting on output room.
    PendingLiteral,
    /// Need the first byte of a 2-byte match token.
    NeedMatch1,
    /// Have first byte (`match_first`), need the second.
    NeedMatch2,
    /// Emitting a match copy: `len` bytes left, current ring read offset `pos`.
    EmitMatch,
    /// Stream complete (declared length reached).
    Done,
}

/// Streaming LZSS decoder.
#[derive(Debug)]
pub struct Decoder {
    phase: DecPhase,
    header_buf: [u8; 4],
    header_pos: u8,
    expected_len: u32,
    emitted: u32,
    /// Current 8-token flag byte; LSB walked as tokens fire.
    flags: u8,
    /// Bits remaining in `flags` (0..=8).
    flags_left: u8,
    /// First byte of a pending match token, captured while waiting for the second.
    match_first: u8,
    /// In `EmitMatch`, the ring buffer read position for the next byte.
    match_pos: u16,
    /// In `EmitMatch`, bytes remaining in the current copy.
    match_len: u8,
    /// In `PendingLiteral`, the byte that didn't fit in the caller's output.
    pending_literal: u8,
    /// 4 KiB ring buffer of recently-emitted output.
    ring: Vec<u8>,
    /// Write cursor inside the ring buffer.
    ring_w: usize,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            phase: DecPhase::Header,
            header_buf: [0u8; 4],
            header_pos: 0,
            expected_len: 0,
            emitted: 0,
            flags: 0,
            flags_left: 0,
            match_first: 0,
            match_pos: 0,
            match_len: 0,
            pending_literal: 0,
            ring: vec![NUL; N],
            ring_w: N - F,
        }
    }

    /// Emit `b` into `output[*written]`, advance the ring buffer, and
    /// flip `phase` to `Done` once the declared length is reached.
    /// Returns `false` if the caller's output is full.
    fn emit(&mut self, b: u8, output: &mut [u8], written: &mut usize) -> bool {
        if *written >= output.len() {
            return false;
        }
        output[*written] = b;
        *written += 1;
        self.ring[self.ring_w] = b;
        self.ring_w = (self.ring_w + 1) & (N - 1);
        self.emitted = self.emitted.saturating_add(1);
        if self.emitted >= self.expected_len {
            self.phase = DecPhase::Done;
        }
        true
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                DecPhase::Header => {
                    while self.header_pos < 4 && consumed < input.len() {
                        self.header_buf[self.header_pos as usize] = input[consumed];
                        self.header_pos += 1;
                        consumed += 1;
                    }
                    if self.header_pos < 4 {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.expected_len = u32::from_le_bytes(self.header_buf);
                    if self.expected_len == 0 {
                        self.phase = DecPhase::Done;
                    } else {
                        self.phase = DecPhase::Flags;
                    }
                }
                DecPhase::Flags => {
                    if consumed >= input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.flags = input[consumed];
                    consumed += 1;
                    self.flags_left = 8;
                    self.phase = DecPhase::Token;
                }
                DecPhase::Token => {
                    if self.flags_left == 0 {
                        self.phase = DecPhase::Flags;
                        continue;
                    }
                    let is_literal = (self.flags & 1) != 0;
                    self.flags >>= 1;
                    self.flags_left -= 1;
                    self.phase = if is_literal {
                        DecPhase::NeedLiteral
                    } else {
                        DecPhase::NeedMatch1
                    };
                }
                DecPhase::NeedLiteral => {
                    if consumed >= input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let b = input[consumed];
                    consumed += 1;
                    if !self.emit(b, output, &mut written) {
                        // No room in caller's output: stash and pause.
                        self.pending_literal = b;
                        self.phase = DecPhase::PendingLiteral;
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if !matches!(self.phase, DecPhase::Done) {
                        self.phase = DecPhase::Token;
                    }
                }
                DecPhase::PendingLiteral => {
                    let b = self.pending_literal;
                    if !self.emit(b, output, &mut written) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if !matches!(self.phase, DecPhase::Done) {
                        self.phase = DecPhase::Token;
                    }
                }
                DecPhase::NeedMatch1 => {
                    if consumed >= input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.match_first = input[consumed];
                    consumed += 1;
                    self.phase = DecPhase::NeedMatch2;
                }
                DecPhase::NeedMatch2 => {
                    if consumed >= input.len() {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let b2 = input[consumed];
                    consumed += 1;
                    let pos = (self.match_first as u16) | (((b2 as u16) & 0xF0) << 4);
                    self.match_pos = pos & (N as u16 - 1);
                    // 4-bit length field maps 0..=15 → 3..=18 (= +THRESHOLD+1).
                    self.match_len = (b2 & 0x0F) + (THRESHOLD as u8) + 1;
                    self.phase = DecPhase::EmitMatch;
                }
                DecPhase::EmitMatch => {
                    while self.match_len > 0 {
                        let b = self.ring[self.match_pos as usize & (N - 1)];
                        if !self.emit(b, output, &mut written) {
                            // Output full mid-copy: state is already
                            // saved in `match_pos` / `match_len`.
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        self.match_pos = (self.match_pos + 1) & (N as u16 - 1);
                        self.match_len -= 1;
                        if matches!(self.phase, DecPhase::Done) {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: true,
                            });
                        }
                    }
                    self.phase = DecPhase::Token;
                }
                DecPhase::Done => {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        match self.phase {
            DecPhase::Done => Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            }),
            DecPhase::Header if self.header_pos == 0 => {
                // Empty input is a zero-length stream by convention.
                self.phase = DecPhase::Done;
                Ok(RawProgress {
                    consumed: 0,
                    written: 0,
                    done: true,
                })
            }
            _ => Err(Error::UnexpectedEnd),
        }
    }

    fn raw_reset(&mut self) {
        self.phase = DecPhase::Header;
        self.header_buf = [0u8; 4];
        self.header_pos = 0;
        self.expected_len = 0;
        self.emitted = 0;
        self.flags = 0;
        self.flags_left = 0;
        self.match_first = 0;
        self.match_pos = 0;
        self.match_len = 0;
        self.pending_literal = 0;
        for b in self.ring.iter_mut() {
            *b = NUL;
        }
        self.ring_w = N - F;
    }
}
