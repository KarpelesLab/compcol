//! PKZip Reduce (methods 2–5) — **decoder only**.
//!
//! Reduce was Phil Katz's compression scheme for PKZIP 1.x (1989–1993).
//! It combines a byte-oriented LZ77 (with a DLE-byte escape for runs and
//! match references) with a small per-previous-byte "follower set" code
//! that gives the most common successors of each byte a shorter binary
//! representation. Four sub-methods exist, called compression *factors*
//! 1..=4, which trade off length-vs-distance bit splits in the LZ77 back
//! reference encoding:
//!
//! ```text
//!     factor   match_length_bits_in_V   match_distance_high_bits
//!       1            7                         1
//!       2            6                         2
//!       3            5                         3
//!       4            4                         4
//! ```
//!
//! Higher factors mean longer reachable distances (max distance =
//! `((1 << factor) - 1) * 256 + 255 + 1`) but shorter inline lengths.
//!
//! ## Reference
//!
//! Hans Wennborg's `hwzip` `reduce.c`
//! (<https://www.hanshq.net/zip2.html>, public domain) is the cleanest
//! published implementation and was used as the algorithmic reference
//! here. PKWARE APPNOTE.TXT (pre-2.0 versions) describes the same
//! algorithm in prose. The decoder below preserves the byte-level
//! semantics of hwzip's `hwexpand` while wrapping the algorithm in the
//! crate's streaming `RawDecoder` shape.
//!
//! ## Wire format used by this crate
//!
//! The raw Reduce payload as produced by PKZIP carries neither a
//! compression factor nor an uncompressed length — both live in the ZIP
//! central directory. This crate's [`Decoder`] therefore consumes a
//! minimal 5-byte container header it can drive itself:
//!
//! ```text
//!     +--------+---------------------+---------------------------+
//!     | factor | uncompressed length |   raw reduce payload      |
//!     |  u8    | u32 LE              |   (variable length)       |
//!     +--------+---------------------+---------------------------+
//! ```
//!
//! - `factor` must be in `1..=4`.
//! - `uncompressed length` is the exact number of bytes the payload
//!   decompresses to (PKZIP's CDFH `Uncompressed Size`).
//! - The raw payload starts with 256 follower sets (6 bits of count + up
//!   to 32 × 8 bits of follower bytes, indexed `255..=0`), followed by
//!   the LZ77-encoded byte stream.
//!
//! Callers extracting Reduce-compressed entries from real PKZIP archives
//! should prepend this 5-byte header before feeding bytes to
//! [`crate::Decoder::decode`].
//!
//! ## Scope
//!
//! - Decoder for all four factors (ZIP methods 2, 3, 4, 5).
//! - The [`Encoder`] returns [`Error::Unsupported`] from every method:
//!   producing Reduce streams is out of scope for this build (it would
//!   require an entire LZ77 matcher plus the offline follower-set cost
//!   optimisation that the original PKZIP performs after seeing the
//!   first 64 KiB of input).

#![cfg_attr(docsrs, doc(cfg(feature = "zip_reduce")))]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for PKZip Reduce.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZipReduce;

impl Algorithm for ZipReduce {
    const NAME: &'static str = "zip-reduce";
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

// ─── encoder stub ────────────────────────────────────────────────────────

/// Encoder stub. Reduce encoding is intentionally not implemented in this
/// crate; every method here returns [`Error::Unsupported`].
#[derive(Debug, Default)]
pub struct Encoder;

impl Encoder {
    pub const fn new() -> Self {
        Self
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_reset(&mut self) {}
}

// ─── follower sets ───────────────────────────────────────────────────────

/// Number of bits used to represent indices into a follower set of size
/// `n` (per hwzip's `follower_idx_bw`). The encoding spends `1 + idx_bw`
/// bits per "use-follower" decision: one selector bit plus the index.
const fn follower_idx_bw(n: u8) -> u8 {
    match n {
        17..=32 => 5,
        9..=16 => 4,
        5..=8 => 3,
        3..=4 => 2,
        1..=2 => 1,
        _ => 0,
    }
}

/// One follower set: up to 32 candidate "next bytes" for a given
/// previous byte, plus the cached `idx_bw` so we don't recompute it per
/// byte decoded.
#[derive(Debug, Clone, Copy)]
struct FollowerSet {
    size: u8,
    idx_bw: u8,
    followers: [u8; 32],
}

impl FollowerSet {
    const fn empty() -> Self {
        Self {
            size: 0,
            idx_bw: 0,
            followers: [0u8; 32],
        }
    }
}

// ─── LSB-first bit reader over a byte slice ───────────────────────────────

/// LSB-first bit reader. Matches hwzip's `istream_t` semantics:
/// bytes are read low-byte-first, low-bit-first within each byte.
/// All state is in terms of an absolute bit position that increases
/// monotonically; the underlying buffer is whatever has been accumulated
/// into the decoder's `input_buf`.
#[derive(Debug, Clone, Copy)]
struct BitReader {
    /// Position of the next bit to read, measured in bits from the
    /// start of `input_buf`.
    bitpos: u64,
}

impl BitReader {
    const fn new() -> Self {
        Self { bitpos: 0 }
    }

    /// Bit position rebased after the decoder drops a fully-consumed
    /// prefix of `input_buf`.
    fn rebase(&mut self, dropped_bytes: usize) {
        self.bitpos -= (dropped_bytes as u64) * 8;
    }

    /// Current byte-aligned read position (rounded down), used to
    /// decide which prefix of `input_buf` is safe to drop.
    fn byte_pos(&self) -> usize {
        (self.bitpos / 8) as usize
    }

    /// True if the next byte boundary lies inside `buf`.
    fn has_bits(&self, buf: &[u8], n: u32) -> bool {
        // Need `n` bits starting at `self.bitpos`; the end position is
        // `bitpos + n` and must lie within `buf.len() * 8`.
        let end_bits = self.bitpos.saturating_add(n as u64);
        end_bits <= (buf.len() as u64) * 8
    }

    /// Read `n` bits LSB-first without advancing. `n` must be `<= 32`.
    /// Returns [`Error::UnexpectedEnd`] if `buf` doesn't yet have them.
    fn peek_bits(&self, buf: &[u8], n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        if !self.has_bits(buf, n) {
            return Err(Error::UnexpectedEnd);
        }
        if n == 0 {
            return Ok(0);
        }
        let byte = (self.bitpos / 8) as usize;
        let shift = (self.bitpos % 8) as u32;
        // Pull up to 5 bytes (covers the worst-case shift of 7 + 32 bits
        // = 39 bits spread across 5 bytes).
        let mut acc: u64 = 0;
        let take = (n + shift).div_ceil(8);
        for i in 0..take as usize {
            if byte + i < buf.len() {
                acc |= (buf[byte + i] as u64) << (i * 8);
            }
        }
        let mask: u64 = if n == 32 {
            0xFFFF_FFFF
        } else {
            (1u64 << n) - 1
        };
        Ok(((acc >> shift) & mask) as u32)
    }

    /// Read and consume `n` bits. Atomic: on error, position is left
    /// unchanged so the caller can rewind without explicit snapshots.
    fn read_bits(&mut self, buf: &[u8], n: u32) -> Result<u32, Error> {
        let v = self.peek_bits(buf, n)?;
        self.bitpos += n as u64;
        Ok(v)
    }
}

// ─── decoder state machine ────────────────────────────────────────────────

/// One decoded back-reference left mid-flight when the caller's output
/// buffer ran out. `remaining` shrinks as bytes are copied to output.
#[derive(Debug, Clone, Copy)]
struct PendingMatch {
    dist: usize,
    remaining: usize,
}

/// Where the decoder currently is in the wire framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the 5-byte container header (factor + ucl).
    Header,
    /// Reading the 256 follower sets at the start of the raw payload.
    FollowerSets,
    /// Streaming the LZ77 payload, possibly mid-back-reference.
    Body,
    /// Finished: produced `uncomp_len` bytes.
    Done,
    /// A previous call returned `Err`; further calls also error.
    Poison,
}

/// Streaming Reduce decoder.
pub struct Decoder {
    // -- framing --------------------------------------------------------
    phase: Phase,
    factor: u8,
    uncomp_len: u32,

    // -- byte-buffered input (bit reader is positioned within this) ----
    input_buf: Vec<u8>,
    bits: BitReader,

    // -- follower-set parsing progress ---------------------------------
    /// Next follower-set index to read (counts down 255..=0, then -1).
    next_fset: i16,
    fsets: Vec<FollowerSet>,

    // -- LZ77 body progress --------------------------------------------
    /// Output buffer being filled. Reduce can self-reference, so we
    /// need the full produced stream available for back references.
    out: Vec<u8>,
    /// Cursor: next byte to emit from `out` to the caller. We retain
    /// already-emitted bytes in `out` because back references may reach
    /// arbitrarily far back into the stream.
    emit_cursor: usize,
    /// Last decoded byte ("prev_byte" in the spec). Initialised to 0.
    prev_byte: u8,
    /// Match copy left mid-flight from a previous call.
    pending: Option<PendingMatch>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Construct a fresh decoder expecting the 5-byte container header
    /// described at the module level.
    pub fn new() -> Self {
        Self {
            phase: Phase::Header,
            factor: 0,
            uncomp_len: 0,
            input_buf: Vec::new(),
            bits: BitReader::new(),
            next_fset: 255,
            fsets: Vec::new(),
            out: Vec::new(),
            emit_cursor: 0,
            prev_byte: 0,
            pending: None,
        }
    }

    /// Parse the 5-byte container header from the front of `input_buf`
    /// if present. Returns `Ok(())` once parsed, or `Err(UnexpectedEnd)`
    /// if more bytes are needed.
    fn parse_header(&mut self) -> Result<(), Error> {
        if self.input_buf.len() < 5 {
            return Err(Error::UnexpectedEnd);
        }
        let factor = self.input_buf[0];
        if !(1..=4).contains(&factor) {
            return Err(Error::BadHeader);
        }
        let ucl = u32::from_le_bytes([
            self.input_buf[1],
            self.input_buf[2],
            self.input_buf[3],
            self.input_buf[4],
        ]);
        self.factor = factor;
        self.uncomp_len = ucl;
        // Drop the header from input_buf and advance the bit reader.
        self.input_buf.drain(0..5);
        // Bit reader hasn't started yet so this is a no-op aside from
        // resetting the rebase accounting.
        self.bits = BitReader::new();
        // Allocate output buffer up front when feasible (caps oversize
        // to avoid a 4 GiB up-front alloc for adversarial headers).
        let cap = (ucl as usize).min(64 * 1024 * 1024);
        self.out = Vec::with_capacity(cap);
        // Build follower-sets vector lazily filled by `read_follower_sets`.
        self.fsets = vec![FollowerSet::empty(); 256];
        self.next_fset = 255;
        self.phase = Phase::FollowerSets;
        Ok(())
    }

    /// Read as many follower sets as the buffered input allows. Returns
    /// `Ok(())` when all 256 have been read, `Err(UnexpectedEnd)` if
    /// more input is needed mid-way.
    fn read_follower_sets(&mut self) -> Result<(), Error> {
        while self.next_fset >= 0 {
            let idx = self.next_fset as usize;
            // 6-bit count. Atomic peek-then-advance via read_bits.
            let saved = self.bits;
            let n = self.bits.read_bits(&self.input_buf, 6)? as u8;
            if n > 32 {
                // Spec caps follower-set size at 32.
                return Err(Error::Corrupt);
            }
            self.fsets[idx].size = n;
            self.fsets[idx].idx_bw = follower_idx_bw(n);
            // Read `n` follower bytes (8 bits each).
            for j in 0..n as usize {
                match self.bits.read_bits(&self.input_buf, 8) {
                    Ok(b) => self.fsets[idx].followers[j] = b as u8,
                    Err(Error::UnexpectedEnd) => {
                        // Rewind to before the count read so we redo
                        // the whole follower set when more data arrives.
                        self.bits = saved;
                        return Err(Error::UnexpectedEnd);
                    }
                    Err(e) => return Err(e),
                }
            }
            self.next_fset -= 1;
        }
        self.phase = Phase::Body;
        Ok(())
    }

    /// Read one "next byte" using the follower-set state machine.
    /// Atomic: on `UnexpectedEnd` the bit reader is rewound.
    fn read_next_byte(&mut self) -> Result<u8, Error> {
        let prev = self.prev_byte as usize;
        let fset = self.fsets[prev];
        let saved = self.bits;
        if fset.size == 0 {
            // No followers; literal byte.
            match self.bits.read_bits(&self.input_buf, 8) {
                Ok(b) => Ok(b as u8),
                Err(e) => {
                    self.bits = saved;
                    Err(e)
                }
            }
        } else {
            // 1 selector bit.
            let sel = match self.bits.read_bits(&self.input_buf, 1) {
                Ok(v) => v,
                Err(e) => {
                    self.bits = saved;
                    return Err(e);
                }
            };
            if sel == 1 {
                // Literal byte.
                match self.bits.read_bits(&self.input_buf, 8) {
                    Ok(b) => Ok(b as u8),
                    Err(e) => {
                        self.bits = saved;
                        Err(e)
                    }
                }
            } else {
                // Follower index.
                let idx_bw = fset.idx_bw as u32;
                let idx = match self.bits.read_bits(&self.input_buf, idx_bw) {
                    Ok(v) => v as usize,
                    Err(e) => {
                        self.bits = saved;
                        return Err(e);
                    }
                };
                if idx >= fset.size as usize {
                    // Bad encoded data — index beyond the declared
                    // follower-set size.
                    Err(Error::Corrupt)
                } else {
                    Ok(fset.followers[idx])
                }
            }
        }
    }

    /// Drive the LZ77 body until output produces `uncomp_len` bytes,
    /// the bit reader needs more input, or the output buffer is full.
    /// Bytes are appended to `self.out` here; the caller's slice is
    /// filled via [`flush_emit`] which advances `emit_cursor`.
    ///
    /// We bound how many bytes we'll buffer ahead of the caller's
    /// emit cursor — without that bound, a one-byte caller output slice
    /// against a 60 MB stream would still buffer the full 60 MB in
    /// `self.out` before yielding. The window has to stay at least as
    /// large as the worst-case back-reference distance for the active
    /// factor (`max_dist`); we use a generous 4 × max_dist so a single
    /// `decode_body` call still makes meaningful progress without
    /// stalling on every match boundary.
    fn decode_body(&mut self, output: &mut [u8], written: &mut usize) -> Result<(), Error> {
        // Compute how much we're willing to buffer past the emit cursor.
        let max_dist = ((1usize << self.factor) - 1) * 256 + 255 + 1;
        let buffer_ahead = max_dist * 4;

        // Drain a pending mid-match copy first.
        if let Some(mut pm) = self.pending.take() {
            while pm.remaining > 0 {
                self.flush_emit(output, written);
                if self.out.len() - self.emit_cursor >= buffer_ahead && *written >= output.len() {
                    self.pending = Some(pm);
                    return Ok(());
                }
                let pos = self.out.len();
                let b = if pm.dist > pos {
                    0u8
                } else {
                    self.out[pos - pm.dist]
                };
                self.out.push(b);
                pm.remaining -= 1;
                if (self.out.len() as u32) >= self.uncomp_len && pm.remaining > 0 {
                    return Err(Error::Corrupt);
                }
            }
        }

        let v_len_bits: u32 = (8 - self.factor) as u32;
        let len_mask: u32 = (1u32 << v_len_bits) - 1;

        while (self.out.len() as u32) < self.uncomp_len {
            // Periodically drain to the caller and stop early if we've
            // buffered too far ahead.
            self.flush_emit(output, written);
            if self.out.len() - self.emit_cursor >= buffer_ahead && *written >= output.len() {
                return Ok(());
            }

            let saved_bits = self.bits;
            let saved_prev = self.prev_byte;

            // Step 1: literal or DLE marker.
            let cur = match self.read_next_byte() {
                Ok(b) => b,
                Err(Error::UnexpectedEnd) => {
                    self.bits = saved_bits;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            self.prev_byte = cur;
            if cur != DLE_BYTE {
                self.out.push(cur);
                continue;
            }

            // Step 2: V byte (post-DLE).
            let v = match self.read_next_byte() {
                Ok(b) => b,
                Err(Error::UnexpectedEnd) => {
                    self.bits = saved_bits;
                    self.prev_byte = saved_prev;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            self.prev_byte = v;
            if v == 0 {
                self.out.push(DLE_BYTE);
                continue;
            }

            let mut len = (v as u32 & len_mask) as usize;
            if (len as u32) == len_mask {
                let elb = match self.read_next_byte() {
                    Ok(b) => b,
                    Err(Error::UnexpectedEnd) => {
                        self.bits = saved_bits;
                        self.prev_byte = saved_prev;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };
                self.prev_byte = elb;
                len += elb as usize;
            }
            len += 3;

            let w = match self.read_next_byte() {
                Ok(b) => b,
                Err(Error::UnexpectedEnd) => {
                    self.bits = saved_bits;
                    self.prev_byte = saved_prev;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            self.prev_byte = w;

            let dist_hi = (v as usize) >> v_len_bits;
            let dist = dist_hi * 256 + w as usize + 1;

            let remaining_out = (self.uncomp_len as usize) - self.out.len();
            if len > remaining_out {
                return Err(Error::Corrupt);
            }

            // Materialise the match. Note: `self.prev_byte` is NOT
            // updated to the copied bytes — per the hwzip reference the
            // "previous byte" for the next follower-set lookup is the
            // last byte read from the *bitstream* (which is W here),
            // not the last byte emitted by the match. Keeping prev =
            // W is what real PKZIP-1.x streams expect.
            let mut pm = PendingMatch {
                dist,
                remaining: len,
            };
            while pm.remaining > 0 {
                let pos = self.out.len();
                let b = if pm.dist > pos {
                    0u8
                } else {
                    self.out[pos - pm.dist]
                };
                self.out.push(b);
                pm.remaining -= 1;
            }
        }
        Ok(())
    }

    /// Forward bytes that have been appended to `out` past `emit_cursor`
    /// to the caller's slice. Returns when either output fills or all
    /// produced bytes have been forwarded.
    fn flush_emit(&mut self, output: &mut [u8], written: &mut usize) {
        while self.emit_cursor < self.out.len() && *written < output.len() {
            output[*written] = self.out[self.emit_cursor];
            *written += 1;
            self.emit_cursor += 1;
        }
    }

    /// Compact `input_buf` by dropping the prefix already consumed by
    /// the bit reader.
    fn compact_input(&mut self) {
        let bp = self.bits.byte_pos();
        if bp == 0 {
            return;
        }
        self.input_buf.drain(0..bp);
        self.bits.rebase(bp);
    }
}

/// PKZIP's DLE escape byte. A standalone DLE in the encoded stream is
/// the start of either a real DLE literal (when the following V byte is
/// 0) or a back reference (when V is non-zero).
const DLE_BYTE: u8 = 0x90;

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if matches!(self.phase, Phase::Poison) {
            return Err(Error::Corrupt);
        }
        self.input_buf.extend_from_slice(input);
        let mut written = 0usize;

        // Drain any already-produced bytes from `out` first.
        self.flush_emit(output, &mut written);
        if written == output.len() {
            return Ok(RawProgress {
                consumed: input.len(),
                written,
                done: false,
            });
        }

        if matches!(self.phase, Phase::Header) {
            match self.parse_header() {
                Ok(()) => {}
                Err(Error::UnexpectedEnd) => {
                    return Ok(RawProgress {
                        consumed: input.len(),
                        written,
                        done: false,
                    });
                }
                Err(e) => {
                    self.phase = Phase::Poison;
                    return Err(e);
                }
            }
        }

        if matches!(self.phase, Phase::FollowerSets) {
            match self.read_follower_sets() {
                Ok(()) => {}
                Err(Error::UnexpectedEnd) => {
                    self.compact_input();
                    return Ok(RawProgress {
                        consumed: input.len(),
                        written,
                        done: false,
                    });
                }
                Err(e) => {
                    self.phase = Phase::Poison;
                    return Err(e);
                }
            }
        }

        // Edge case: zero-length stream. The follower-set header is
        // still present and parsed; we go straight to Done.
        if (self.out.len() as u32) >= self.uncomp_len && matches!(self.phase, Phase::Body) {
            self.phase = Phase::Done;
        }

        if matches!(self.phase, Phase::Body) {
            match self.decode_body(output, &mut written) {
                Ok(()) => {}
                Err(e) => {
                    self.phase = Phase::Poison;
                    return Err(e);
                }
            }
            // Forward any leftover internal-buffer bytes to the caller.
            self.flush_emit(output, &mut written);
            if (self.out.len() as u32) >= self.uncomp_len && self.emit_cursor == self.out.len() {
                self.phase = Phase::Done;
            }
        }

        self.compact_input();
        Ok(RawProgress {
            consumed: input.len(),
            written,
            done: matches!(self.phase, Phase::Done),
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if matches!(self.phase, Phase::Poison) {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        self.flush_emit(output, &mut written);
        if matches!(self.phase, Phase::Body) {
            match self.decode_body(output, &mut written) {
                Ok(()) => {}
                Err(e) => {
                    self.phase = Phase::Poison;
                    return Err(e);
                }
            }
            self.flush_emit(output, &mut written);
            if (self.out.len() as u32) >= self.uncomp_len && self.emit_cursor == self.out.len() {
                self.phase = Phase::Done;
            }
        }
        // If we're stuck mid-stream waiting for more input, that's
        // truncation.
        let done = matches!(self.phase, Phase::Done);
        if !done && written == 0 {
            // Distinguish "still emitting" from "stalled on input".
            // If the caller's buffer isn't full *and* we wrote nothing
            // *and* we're not already done, the stream is truncated.
            if self.emit_cursor == self.out.len() && !matches!(self.phase, Phase::Done) {
                self.phase = Phase::Poison;
                return Err(Error::UnexpectedEnd);
            }
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.phase = Phase::Header;
        self.factor = 0;
        self.uncomp_len = 0;
        self.input_buf.clear();
        self.bits = BitReader::new();
        self.next_fset = 255;
        self.fsets.clear();
        self.out.clear();
        self.emit_cursor = 0;
        self.prev_byte = 0;
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follower_idx_bw_matches_reference() {
        // Sample the four boundaries from hwzip's reduce.c.
        assert_eq!(follower_idx_bw(0), 0);
        assert_eq!(follower_idx_bw(1), 1);
        assert_eq!(follower_idx_bw(2), 1);
        assert_eq!(follower_idx_bw(3), 2);
        assert_eq!(follower_idx_bw(4), 2);
        assert_eq!(follower_idx_bw(5), 3);
        assert_eq!(follower_idx_bw(8), 3);
        assert_eq!(follower_idx_bw(9), 4);
        assert_eq!(follower_idx_bw(16), 4);
        assert_eq!(follower_idx_bw(17), 5);
        assert_eq!(follower_idx_bw(32), 5);
    }

    #[test]
    fn bit_reader_reads_lsb_first() {
        // 0b10110011 0b11110000 → reading 4-bit groups gives 0x3, 0xB, 0x0, 0xF.
        let buf = [0b1011_0011u8, 0b1111_0000u8];
        let mut br = BitReader::new();
        assert_eq!(br.read_bits(&buf, 4).unwrap(), 0x3);
        assert_eq!(br.read_bits(&buf, 4).unwrap(), 0xB);
        assert_eq!(br.read_bits(&buf, 4).unwrap(), 0x0);
        assert_eq!(br.read_bits(&buf, 4).unwrap(), 0xF);
    }
}
