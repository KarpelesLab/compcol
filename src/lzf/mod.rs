//! LZF — Marc Lehmann's `liblzf` raw format.
//!
//! This module implements the byte stream produced by `lzf_compress` and
//! consumed by `lzf_decompress` in the reference
//! [liblzf](http://software.schmorp.de/pkg/liblzf.html) (3.x). The same raw
//! format is what Redis uses for compressed RDB strings, and what the PHP
//! `lzf` extension and Python's `python-lzf` read and write.
//!
//! The stream is a plain sequence of tokens, with no header, length or end
//! marker (the end of the input is the end of the stream). Each token starts
//! with a control byte `ctrl`:
//!
//! * `ctrl < 0x20` — literal run: the next `ctrl + 1` bytes (1..=32) are
//!   copied to the output verbatim.
//! * otherwise — back-reference. `len = ctrl >> 5` (1..=7); when `len == 7`
//!   one extra byte follows and is added to it. Then one byte `lo` follows,
//!   and the match copies `len + 2` bytes (3..=264) from
//!   `((ctrl & 0x1F) << 8 | lo) + 1` bytes back (1..=8192). Copies may
//!   overlap their own output (RLE-style).
//!
//! The `lzf(1)` command-line tool's `ZV`-blocked file container is *not*
//! implemented here, only the raw token stream it wraps.
//!
//! ## Streaming model
//!
//! Both directions stream for real. The decoder keeps an 8 KiB history ring
//! (the largest distance a back-reference can reach) and decodes tokens as
//! their bytes arrive, even when a token is split across `decode` calls. The
//! encoder keeps the last 8 KiB of input plus a bounded lookahead, and holds
//! back only the final [`MAX_MATCH`] bytes of each chunk so a match is never
//! cut short by the chunk boundary.
//!
//! Since the format has no end marker, any token boundary is a valid stream
//! end, so [`Flush::Sync`] is supported: it emits everything buffered and
//! keeps the history. [`Flush::Full`] also forgets the history, so the output
//! after it decodes without what came before.
//!
//! ## Encoder
//!
//! A single-probe hash table over 3-byte prefixes (16-bit index, like
//! liblzf's default `HLOG`) finds the candidate match. Matches are taken
//! greedily, and every position inside an emitted match is inserted back
//! into the table.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, Flush, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for LZF.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzf;

impl Algorithm for Lzf {
    const NAME: &'static str = "lzf";
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

/// Largest back-reference distance (13-bit offset, plus one).
pub const WINDOW: usize = 1 << 13;
/// Longest literal run one control byte can carry.
pub const MAX_LITERAL: usize = 1 << 5;
/// Longest match one back-reference can carry (`7 + 255 + 2`).
pub const MAX_MATCH: usize = (1 << 8) + (1 << 3);
/// Shortest match the format can express.
const MIN_MATCH: usize = 3;

// ─── encoder ──────────────────────────────────────────────────────────────

const HASH_BITS: u32 = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
/// Input taken into the window per step of `raw_encode`, which bounds how
/// much compressed output can pile up before it is handed back.
const CHUNK: usize = 32 * 1024;
/// Already-encoded bytes kept past [`WINDOW`] before the window slides, so
/// sliding (and rebasing the hash table) happens once per this many bytes.
const SLIDE: usize = 64 * 1024;

/// Hash of the 3 bytes at `buf[pos..pos + 3]`.
#[inline]
fn hash3(buf: &[u8], pos: usize) -> usize {
    let v = (buf[pos] as u32) | ((buf[pos + 1] as u32) << 8) | ((buf[pos + 2] as u32) << 16);
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// Streaming LZF encoder.
#[derive(Debug, Default)]
pub struct Encoder {
    /// Recent history (up to [`WINDOW`] bytes, plus slack) followed by the
    /// input not yet encoded.
    win: Vec<u8>,
    /// Next byte of `win` to encode.
    pos: usize,
    /// Start of the pending literal run, `win[lit..pos]` (< [`MAX_LITERAL`]).
    lit: usize,
    /// `index + 1` into `win` of the last position with each hash, 0 = none.
    /// Allocated on first use.
    table: Vec<u32>,
    /// Encoded bytes not yet handed back to the caller.
    out: Vec<u8>,
    /// Bytes of `out` already handed back.
    out_pos: usize,
    /// Set once `finish` has encoded the tail of the input.
    finished: bool,
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            win: Vec::new(),
            pos: 0,
            lit: 0,
            table: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            finished: false,
        }
    }

    /// Copy as much pending output as fits into `output`.
    fn drain(&mut self, output: &mut [u8]) -> usize {
        let n = (self.out.len() - self.out_pos).min(output.len());
        output[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
        n
    }

    /// Drop history the encoder can no longer reference, once enough of it
    /// has built up, and rebase the hash table to the new window start.
    fn slide(&mut self) {
        if self.pos <= WINDOW + SLIDE {
            return;
        }
        let drop = (self.pos - WINDOW).min(self.lit);
        self.win.drain(..drop);
        self.pos -= drop;
        self.lit -= drop;
        let drop = drop as u32;
        for e in self.table.iter_mut() {
            *e = e.saturating_sub(drop);
        }
    }

    /// Encode `win[pos..]` into `out`. Unless `all`, the last [`MAX_MATCH`]
    /// bytes are held back so the next chunk can extend a match into them.
    /// Literals still pending afterwards stay in `win[lit..pos]`.
    fn compress(&mut self, all: bool) {
        if self.table.is_empty() {
            self.table.resize(HASH_SIZE, 0);
        }
        let end = self.win.len();
        let limit = if all {
            end
        } else {
            end.saturating_sub(MAX_MATCH)
        };
        let win = &self.win;
        let table = &mut self.table;
        let out = &mut self.out;
        let mut ip = self.pos;
        let mut lit = self.lit;

        while ip < limit {
            if ip + MIN_MATCH <= end {
                let h = hash3(win, ip);
                let cand = table[h] as usize;
                table[h] = ip as u32 + 1;
                if cand != 0 {
                    let r = cand - 1;
                    let off = ip - r - 1;
                    if off < WINDOW && win[r..r + MIN_MATCH] == win[ip..ip + MIN_MATCH] {
                        let maxlen = MAX_MATCH.min(end - ip);
                        let mut len = MIN_MATCH;
                        while len < maxlen && win[r + len] == win[ip + len] {
                            len += 1;
                        }
                        if lit < ip {
                            emit_literal(&win[lit..ip], out);
                        }
                        emit_match(off, len, out);
                        for p in ip + 1..(ip + len).min(end - (MIN_MATCH - 1)) {
                            table[hash3(win, p)] = p as u32 + 1;
                        }
                        ip += len;
                        lit = ip;
                        continue;
                    }
                }
            }
            ip += 1;
            if ip - lit == MAX_LITERAL {
                emit_literal(&win[lit..ip], out);
                lit = ip;
            }
        }
        self.pos = ip;
        self.lit = lit;
    }

    /// Encode everything buffered, including the held-back tail, and emit
    /// the pending literal run.
    fn compress_all(&mut self) {
        self.compress(true);
        if self.lit < self.pos {
            emit_literal(&self.win[self.lit..self.pos], &mut self.out);
            self.lit = self.pos;
        }
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = self.drain(output);
        let mut consumed = 0;
        while self.out.is_empty() && consumed < input.len() {
            let take = (input.len() - consumed).min(CHUNK);
            self.slide();
            self.win
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;
            self.compress(false);
            written += self.drain(&mut output[written..]);
        }
        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finished {
            self.compress_all();
            self.finished = true;
        }
        let written = self.drain(output);
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.out.is_empty(),
        })
    }

    fn raw_reset(&mut self) {
        self.win.clear();
        self.pos = 0;
        self.lit = 0;
        self.table.fill(0);
        self.out.clear();
        self.out_pos = 0;
        self.finished = false;
    }

    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        // Output from earlier calls goes first; the buffered input is only
        // encoded once nothing is queued ahead of it.
        let mut written = self.drain(output);
        if self.out.is_empty() && self.pos < self.win.len() {
            self.compress_all();
            written += self.drain(&mut output[written..]);
        }
        if mode == Flush::Full {
            self.table.fill(0);
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.out.is_empty(),
        })
    }
}

/// Emit `data` (1..=[`MAX_LITERAL`] bytes) as one literal run.
fn emit_literal(data: &[u8], out: &mut Vec<u8>) {
    debug_assert!((1..=MAX_LITERAL).contains(&data.len()));
    out.push((data.len() - 1) as u8);
    out.extend_from_slice(data);
}

/// Emit a back-reference of `len` ([`MIN_MATCH`]..=[`MAX_MATCH`]) bytes at
/// `off + 1` bytes back.
fn emit_match(off: usize, len: usize, out: &mut Vec<u8>) {
    debug_assert!(off < WINDOW && (MIN_MATCH..=MAX_MATCH).contains(&len));
    let len = len - 2;
    let hi = (off >> 8) as u8;
    if len < 7 {
        out.push(hi | ((len as u8) << 5));
    } else {
        out.push(hi | (7 << 5));
        out.push((len - 7) as u8);
    }
    out.push(off as u8);
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Streaming LZF decoder.
#[derive(Debug, Default)]
pub struct Decoder {
    /// The last [`WINDOW`] output bytes, as a ring. Allocated on first use.
    hist: Vec<u8>,
    /// Next write position in `hist`.
    hpos: usize,
    /// Valid bytes in `hist` (total output so far, capped at [`WINDOW`]).
    filled: usize,
    /// Bytes of a control sequence split across calls.
    hdr: [u8; 3],
    hdr_len: usize,
    /// Literal bytes still to copy from the input.
    lit: usize,
    /// Match bytes still to copy, and their distance back.
    mlen: usize,
    mdist: usize,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            hist: Vec::new(),
            hpos: 0,
            filled: 0,
            hdr: [0; 3],
            hdr_len: 0,
            lit: 0,
            mlen: 0,
            mdist: 0,
        }
    }

    /// Append `data` to the history ring.
    fn push_hist(&mut self, mut data: &[u8]) {
        self.filled = (self.filled + data.len()).min(WINDOW);
        while !data.is_empty() {
            let n = data.len().min(WINDOW - self.hpos);
            self.hist[self.hpos..self.hpos + n].copy_from_slice(&data[..n]);
            self.hpos = (self.hpos + n) & (WINDOW - 1);
            data = &data[n..];
        }
    }

    /// Copy as much of the pending match as fits into `output`.
    fn copy_match(&mut self, output: &mut [u8]) -> usize {
        let mut op = 0;
        while self.mlen > 0 && op < output.len() {
            let src = (self.hpos + WINDOW - self.mdist) & (WINDOW - 1);
            // At most `mdist` bytes per step, so every byte read is already
            // in the ring, and never across the ring's end on either side.
            let n = self
                .mlen
                .min(output.len() - op)
                .min(self.mdist)
                .min(WINDOW - src)
                .min(WINDOW - self.hpos);
            output[op..op + n].copy_from_slice(&self.hist[src..src + n]);
            self.hist.copy_within(src..src + n, self.hpos);
            self.hpos = (self.hpos + n) & (WINDOW - 1);
            self.mlen -= n;
            op += n;
        }
        self.filled = (self.filled + op).min(WINDOW);
        op
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.hist.is_empty() {
            self.hist.resize(WINDOW, 0);
        }
        let mut ip = 0;
        let mut op = 0;
        loop {
            if self.mlen > 0 {
                if op == output.len() {
                    break;
                }
                op += self.copy_match(&mut output[op..]);
                continue;
            }
            if self.lit > 0 {
                if op == output.len() || ip == input.len() {
                    break;
                }
                let n = self.lit.min(input.len() - ip).min(output.len() - op);
                let data = &input[ip..ip + n];
                output[op..op + n].copy_from_slice(data);
                self.push_hist(data);
                self.lit -= n;
                ip += n;
                op += n;
                continue;
            }
            if ip == input.len() {
                break;
            }

            self.hdr[self.hdr_len] = input[ip];
            self.hdr_len += 1;
            ip += 1;
            let ctrl = self.hdr[0] as usize;
            if ctrl < MAX_LITERAL {
                self.lit = ctrl + 1;
                self.hdr_len = 0;
                continue;
            }
            let short = ctrl >> 5;
            let need = if short == 7 { 3 } else { 2 };
            if self.hdr_len < need {
                continue;
            }
            let len = if short == 7 {
                7 + self.hdr[1] as usize
            } else {
                short
            };
            let dist = (((ctrl & 0x1F) << 8) | self.hdr[need - 1] as usize) + 1;
            self.hdr_len = 0;
            if dist > self.filled {
                return Err(Error::InvalidDistance);
            }
            self.mlen = len + 2;
            self.mdist = dist;
        }
        Ok(RawProgress {
            consumed: ip,
            written: op,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let written = self.copy_match(output);
        if self.mlen == 0 && (self.lit > 0 || self.hdr_len > 0) {
            return Err(Error::UnexpectedEnd);
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.mlen == 0,
        })
    }

    fn raw_reset(&mut self) {
        self.hpos = 0;
        self.filled = 0;
        self.hdr_len = 0;
        self.lit = 0;
        self.mlen = 0;
    }
}
