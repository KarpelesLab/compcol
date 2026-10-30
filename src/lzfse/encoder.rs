//! Streaming LZFSE encoder.
//!
//! Produces the same stream shape as Apple's reference `lzfse_encode`:
//!
//! - an input shorter than [`LZVN_THRESHOLD`] bytes becomes a single `bvxn`
//!   (LZVN) block, or a `bvx-` (stored) block when LZVN does not shrink it;
//! - anything longer is parsed into LZ77 commands which are entropy-coded
//!   in `bvx2` blocks (each at most [`MAX_MATCHES_PER_BLOCK`] commands and
//!   [`MAX_LITERALS_PER_BLOCK`] literals). A block that FSE would make larger
//!   than the bytes it covers is stored as `bvx-` instead;
//! - the stream ends with the `bvx$` marker.
//!
//! Matches reach back up to [`MAX_D_VALUE`] bytes, across block boundaries,
//! exactly as Apple's decoder allows. The encoder keeps that much history
//! plus one parse segment buffered, so its memory use is bounded (a few
//! MiB) regardless of the stream length.
//!
//! The parser is a hash-chain match finder with one step of lazy matching
//! and a repeat-distance check (a repeated distance is coded as `D = 0`,
//! which is nearly free in the FSE stream).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lzfse::lzfse_v2::{
    self, Cmd, MAX_D_VALUE, MAX_L_VALUE, MAX_LITERALS_PER_BLOCK, MAX_M_VALUE, MAX_MATCHES_PER_BLOCK,
};
use crate::lzfse::lzvn;
use crate::traits::{Flush, RawEncoder, RawProgress};

/// Inputs shorter than this are coded as one LZVN block, as Apple's
/// encoder does (`LZFSE_ENCODE_LZVN_THRESHOLD`).
pub(crate) const LZVN_THRESHOLD: usize = 4096;

const MIN_MATCH: usize = 4;
/// A match at least this long is taken without looking one byte ahead.
const NICE_MATCH: usize = 64;
/// Hash-chain candidates examined per position.
const MAX_CHAIN: usize = 24;
/// Bits of the 4-byte-prefix hash used by the `bvx2` parser.
const HASH_BITS: u32 = 16;
/// History kept behind the parse position: the largest distance a `bvx2`
/// command can encode, rounded up.
const WINDOW: usize = 1 << 18;
/// Input parsed per step while streaming.
const SEGMENT: usize = 1 << 18;
/// Bytes kept unparsed at the end of the buffer while more input may come,
/// so a match is not cut short merely because the rest of it has not
/// arrived yet.
const LOOKAHEAD: usize = 4096;
/// A block covering this many input bytes is closed even if it is under the
/// command and literal limits, bounding how much input is held back.
const BLOCK_RAW_MAX: usize = 4 << 20;

const NONE: u32 = u32::MAX;

/// Length of the common prefix of `buf[a..]` and `buf[b..]`, capped at
/// `max` (callers guarantee `b + max <= buf.len()` and `a < b`).
#[inline]
pub(crate) fn common_len(buf: &[u8], a: usize, b: usize, max: usize) -> usize {
    let mut n = 0usize;
    while n + 8 <= max {
        let x = u64::from_le_bytes(buf[a + n..a + n + 8].try_into().unwrap());
        let y = u64::from_le_bytes(buf[b + n..b + n + 8].try_into().unwrap());
        let diff = x ^ y;
        if diff != 0 {
            return n + (diff.trailing_zeros() / 8) as usize;
        }
        n += 8;
    }
    while n < max && buf[a + n] == buf[b + n] {
        n += 1;
    }
    n
}

/// Hash-chain match finder over 4-byte prefixes. Positions are indices into
/// the caller's buffer; [`MatchFinder::rebase`] follows the buffer when its
/// front is discarded.
pub(crate) struct MatchFinder {
    bits: u32,
    head: Vec<u32>,
    prev: Vec<u32>,
}

impl MatchFinder {
    pub(crate) const fn new(bits: u32) -> Self {
        Self {
            bits,
            head: Vec::new(),
            prev: Vec::new(),
        }
    }

    /// Make room for positions up to `len` (and allocate the head table on
    /// first use).
    pub(crate) fn prepare(&mut self, len: usize) {
        if self.head.is_empty() {
            self.head = vec![NONE; 1 << self.bits];
        }
        if self.prev.len() < len {
            self.prev.resize(len, NONE);
        }
    }

    #[inline]
    fn hash(&self, buf: &[u8], p: usize) -> usize {
        let v = u32::from_le_bytes(buf[p..p + 4].try_into().unwrap());
        (v.wrapping_mul(0x9E37_79B1) >> (32 - self.bits)) as usize
    }

    /// Record position `p` (needs `p + 4 <= buf.len()` and a prior
    /// `prepare` covering `p`).
    #[inline]
    pub(crate) fn insert(&mut self, buf: &[u8], p: usize) {
        let h = self.hash(buf, p);
        self.prev[p] = self.head[h];
        self.head[h] = p as u32;
    }

    /// Longest match for `buf[p..]` among earlier recorded positions no
    /// further back than `max_dist` and not before `min_pos`, capped at
    /// `max_len`. Returns `(len, dist)`; `len < MIN_MATCH` means none.
    pub(crate) fn find(
        &self,
        buf: &[u8],
        p: usize,
        min_pos: usize,
        max_dist: usize,
        max_len: usize,
        chain: usize,
    ) -> (usize, usize) {
        let mut best_len = MIN_MATCH - 1;
        let mut best_dist = 0usize;
        if max_len < MIN_MATCH {
            return (0, 0);
        }
        let mut cand = self.head[self.hash(buf, p)];
        let mut depth = 0;
        while cand != NONE && depth < chain {
            let c = cand as usize;
            if c >= p || c < min_pos || p - c > max_dist {
                break;
            }
            // Cheap reject: a longer match must agree at `best_len`.
            if buf[c + best_len] == buf[p + best_len] {
                let len = common_len(buf, c, p, max_len);
                if len > best_len {
                    best_len = len;
                    best_dist = p - c;
                    if len >= max_len {
                        break;
                    }
                }
            }
            cand = self.prev[c];
            depth += 1;
        }
        if best_dist == 0 {
            (0, 0)
        } else {
            (best_len, best_dist)
        }
    }

    /// The caller dropped the first `shift` bytes of its buffer: move every
    /// recorded position down by `shift`, forgetting those that fell off.
    fn rebase(&mut self, shift: usize) {
        let shift = shift as u32;
        let fix = |v: &mut u32| {
            *v = if *v == NONE || *v < shift {
                NONE
            } else {
                *v - shift
            };
        };
        self.head.iter_mut().for_each(fix);
        let n = (shift as usize).min(self.prev.len());
        self.prev.drain(..n);
        self.prev.iter_mut().for_each(fix);
    }

    fn clear(&mut self) {
        self.head.fill(NONE);
        self.prev.clear();
    }
}

/// Streaming LZFSE encoder. See the [module docs](crate::lzfse) for the
/// stream format.
///
/// Output is produced a block at a time: `encode` buffers input and emits
/// whole `bvx2` / `bvx-` blocks as they fill, `flush` closes the current
/// block early, and `finish` writes the last block and the `bvx$`
/// end-of-stream marker.
pub struct Encoder {
    /// History window, then the input not yet parsed.
    buf: Vec<u8>,
    mf: MatchFinder,
    /// Next position to parse.
    cur: usize,
    /// Start of the literals not yet attached to a command.
    lit_start: usize,
    /// Start of the input covered by the current, unemitted block.
    block_start: usize,
    /// End of the input covered by the commands in `cmds`.
    block_end: usize,
    /// Matches may not reach before this position (stream start, or a full
    /// flush).
    min_pos: usize,
    /// Commands of the current block.
    cmds: Vec<Cmd>,
    /// Literal count of the current block.
    n_lits: usize,
    /// Distance of the most recent match.
    rep_d: usize,
    /// Set once any input has been parsed or any block emitted: the stream
    /// is then a `bvx2` stream rather than a candidate for a single LZVN
    /// block.
    blocks_mode: bool,
    /// Encoded bytes not yet handed to the caller.
    out: Vec<u8>,
    out_pos: usize,
    /// `finish` has queued the final block and the end-of-stream marker.
    finished: bool,
    /// Scratch for a block's literals.
    lit_scratch: Vec<u8>,
}

impl Encoder {
    /// A fresh encoder. Allocation is deferred until the first input.
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            mf: MatchFinder::new(HASH_BITS),
            cur: 0,
            lit_start: 0,
            block_start: 0,
            block_end: 0,
            min_pos: 0,
            cmds: Vec::new(),
            n_lits: 0,
            rep_d: 0,
            blocks_mode: false,
            out: Vec::new(),
            out_pos: 0,
            finished: false,
            lit_scratch: Vec::new(),
        }
    }

    /// Copy pending output into `output[*written..]`; true once all of it
    /// has been handed over.
    fn drain(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let n = (self.out.len() - self.out_pos).min(output.len() - *written);
        output[*written..*written + n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        *written += n;
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
            true
        } else {
            false
        }
    }

    /// Append a command to the current block, emitting the block first if
    /// the command would take it past a per-block limit.
    fn push_cmd(&mut self, l: usize, m: usize, d: usize) {
        if self.cmds.len() >= MAX_MATCHES_PER_BLOCK
            || self.n_lits + l + 3 > MAX_LITERALS_PER_BLOCK
            || self.block_end - self.block_start >= BLOCK_RAW_MAX
        {
            self.emit_block();
        }
        self.cmds.push(Cmd {
            l: l as u32,
            m: m as u32,
            d: d as u32,
        });
        self.n_lits += l;
        self.block_end += l + m;
    }

    /// Attach the pending literals up to `p` and an `len`-byte match at
    /// `dist` as commands, splitting values over the format's maxima.
    fn push_match(&mut self, p: usize, len: usize, dist: usize) {
        let mut l = p - self.lit_start;
        while l > MAX_L_VALUE as usize {
            self.push_cmd(MAX_L_VALUE as usize, 0, 0);
            l -= MAX_L_VALUE as usize;
        }
        let mut m = len;
        let mut first = true;
        while m > 0 {
            let chunk = m.min(MAX_M_VALUE as usize);
            self.push_cmd(if first { l } else { 0 }, chunk, dist);
            first = false;
            m -= chunk;
        }
        self.lit_start = p + len;
        self.rep_d = dist;
    }

    /// Turn the pending literals into literal-only commands.
    fn push_pending_literals(&mut self) {
        let mut l = self.cur - self.lit_start;
        while l > 0 {
            let chunk = l.min(MAX_L_VALUE as usize);
            self.push_cmd(chunk, 0, 0);
            l -= chunk;
        }
        self.lit_start = self.cur;
    }

    /// Longest match at `p`, preferring the repeat distance when it is
    /// (nearly) as long.
    fn best_match(&self, p: usize, end: usize) -> (usize, usize) {
        let max_len = end - p;
        let (mut len, mut dist) = self.mf.find(
            &self.buf,
            p,
            self.min_pos,
            MAX_D_VALUE as usize,
            max_len,
            MAX_CHAIN,
        );
        let r = self.rep_d;
        if r != 0 && p >= self.min_pos + r {
            let rl = common_len(&self.buf, p - r, p, max_len);
            if rl >= MIN_MATCH && rl + 1 >= len {
                (len, dist) = (rl, r);
            }
        }
        (len, dist)
    }

    /// Parse `buf[cur..limit)` into commands (a match starting before
    /// `limit` may run past it, up to the end of the buffer).
    fn parse(&mut self, limit: usize) {
        self.blocks_mode = true;
        let end = self.buf.len();
        self.mf.prepare(end);
        while self.cur < limit {
            let p = self.cur;
            if p + MIN_MATCH > end {
                self.cur = limit;
                break;
            }
            let (len, dist) = self.best_match(p, end);
            self.mf.insert(&self.buf, p);
            if len >= MIN_MATCH {
                // One step of lazy matching: if the next position has a
                // longer match, emit this byte as a literal instead.
                if len < NICE_MATCH && p + 1 < limit && p + 1 + MIN_MATCH <= end {
                    let (len2, _) = self.best_match(p + 1, end);
                    if len2 > len {
                        self.cur = p + 1;
                        self.after_literal();
                        continue;
                    }
                }
                self.push_match(p, len, dist);
                let stop = (p + len).min(end - MIN_MATCH + 1);
                for q in p + 1..stop {
                    self.mf.insert(&self.buf, q);
                }
                self.cur = p + len;
            } else {
                self.cur = p + 1;
                self.after_literal();
            }
        }
        if self.cur - self.lit_start >= MAX_L_VALUE as usize {
            self.after_literal();
        }
    }

    /// Keep the pending literal run under one command's `L` maximum.
    #[inline]
    fn after_literal(&mut self) {
        if self.cur - self.lit_start >= MAX_L_VALUE as usize {
            self.push_cmd(MAX_L_VALUE as usize, 0, 0);
            self.lit_start += MAX_L_VALUE as usize;
        }
    }

    /// Encode the current block's commands into `out`, as `bvx2` or, when
    /// that would be larger, as a stored `bvx-` block.
    fn emit_block(&mut self) {
        if self.cmds.is_empty() {
            return;
        }
        let raw = &self.buf[self.block_start..self.block_end];
        self.lit_scratch.clear();
        let mut pos = 0usize;
        for c in &self.cmds {
            self.lit_scratch
                .extend_from_slice(&raw[pos..pos + c.l as usize]);
            pos += (c.l + c.m) as usize;
        }
        debug_assert_eq!(pos, raw.len());
        let start = self.out.len();
        lzfse_v2::encode_block(
            &self.lit_scratch,
            &self.cmds,
            raw.len() as u32,
            &mut self.out,
        );
        if self.out.len() - start >= raw.len() + 8 {
            self.out.truncate(start);
            push_stored(&mut self.out, raw);
        }
        self.cmds.clear();
        self.n_lits = 0;
        self.block_start = self.block_end;
    }

    /// Drop history that no match or pending block can need any more.
    fn trim(&mut self) {
        let keep_from = self
            .block_start
            .min(self.lit_start)
            .min(self.cur.saturating_sub(WINDOW));
        if keep_from < SEGMENT {
            return;
        }
        self.buf.drain(..keep_from);
        self.mf.rebase(keep_from);
        self.cur -= keep_from;
        self.lit_start -= keep_from;
        self.block_start -= keep_from;
        self.block_end -= keep_from;
        self.min_pos = self.min_pos.saturating_sub(keep_from);
    }

    /// Parse everything buffered and emit it as a complete block.
    fn close_block(&mut self) {
        self.parse(self.buf.len());
        self.push_pending_literals();
        self.emit_block();
        self.trim();
    }

    /// Queue the whole stream's tail: the final block(s) and `bvx$`.
    fn queue_final(&mut self) {
        if !self.blocks_mode && self.buf.len() < LZVN_THRESHOLD {
            // Small input: one LZVN block, or stored if LZVN doesn't help.
            if !self.buf.is_empty() {
                let payload = lzvn::encode_block(&self.buf);
                if payload.len() + 12 < self.buf.len() + 8 {
                    self.out.extend_from_slice(b"bvxn");
                    self.out
                        .extend_from_slice(&(self.buf.len() as u32).to_le_bytes());
                    self.out
                        .extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    self.out.extend_from_slice(&payload);
                } else {
                    push_stored(&mut self.out, &self.buf);
                }
            }
        } else {
            self.close_block();
        }
        self.out.extend_from_slice(b"bvx$");
        self.finished = true;
    }
}

/// Append a stored (`bvx-`) block holding `raw`.
fn push_stored(out: &mut Vec<u8>, raw: &[u8]) {
    out.extend_from_slice(b"bvx-");
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(raw);
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("lzfse::Encoder")
            .field("buffered", &(self.buf.len() - self.cur))
            .field("pending_output", &(self.out.len() - self.out_pos))
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;
        loop {
            if !self.drain(output, &mut written) || self.finished {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
            let unparsed = self.buf.len() - self.cur;
            if unparsed >= SEGMENT + LOOKAHEAD {
                self.parse(self.buf.len() - LOOKAHEAD);
                self.trim();
                continue;
            }
            if consumed == input.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
            let take = (input.len() - consumed).min(SEGMENT + LOOKAHEAD - unparsed);
            self.buf
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if !self.drain(output, &mut written) {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: false,
            });
        }
        if !self.finished {
            self.queue_final();
        }
        let done = self.drain(output, &mut written);
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if !self.finished && self.cur < self.buf.len() {
            // Everything buffered becomes a complete block the peer can
            // decode. Small streams lose the LZVN option from here on.
            self.close_block();
        }
        if mode == Flush::Full && !self.finished {
            // Later matches may not reach back past this point.
            self.min_pos = self.buf.len();
            self.rep_d = 0;
        }
        let done = self.drain(output, &mut written);
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.buf.clear();
        self.mf.clear();
        self.cur = 0;
        self.lit_start = 0;
        self.block_start = 0;
        self.block_end = 0;
        self.min_pos = 0;
        self.cmds.clear();
        self.n_lits = 0;
        self.rep_d = 0;
        self.blocks_mode = false;
        self.out.clear();
        self.out_pos = 0;
        self.finished = false;
    }
}
