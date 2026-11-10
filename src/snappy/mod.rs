//! Google Snappy — raw block format.
//!
//! This module implements the **Snappy raw block format** described in
//! <https://github.com/google/snappy/blob/main/format_description.txt>.
//!
//! A raw Snappy block is a single self-delimiting unit:
//!
//! 1. The uncompressed length encoded as a Base-128 varint (1–5 bytes).
//! 2. A stream of tag bytes followed by their payloads:
//!    * `00` — literal. The high 6 bits hold `length-1` when in `0..=59`;
//!      values `60..=63` mean the length minus one is stored in 1, 2, 3 or 4
//!      little-endian bytes that follow the tag.
//!    * `01` — copy with a 1-byte offset. Bits `[2:4]` hold `length-4`
//!      (length is 4..=11), bits `[5:7]` hold the high three bits of the
//!      11-bit offset, followed by a 1-byte little-endian low offset.
//!    * `10` — copy with a 2-byte offset. Bits `[2:7]` hold `length-1`
//!      (length is 1..=64), followed by a 2-byte little-endian offset.
//!    * `11` — copy with a 4-byte offset. Bits `[2:7]` hold `length-1`
//!      (length is 1..=64), followed by a 4-byte little-endian offset.
//!
//! The framed `snzip` format (`framing_format.txt`) is *not* implemented —
//! the raw block format is what `Snappy_Compress` / `Snappy_Uncompress` in
//! the reference library produce and consume.
//!
//! ## Streaming model
//!
//! Snappy is a whole-block codec: the encoder must know the total
//! uncompressed length before it can emit the leading varint, and the
//! decoder may follow back-references that reach anywhere in the produced
//! output. Both sides therefore buffer their input on `encode` / `decode`
//! and do the actual work in `finish`, draining the compressed (or
//! decompressed) result across as many `finish` calls as the caller needs
//! to consume it.
//!
//! ## Encoder
//!
//! The encoder uses a small fixed-size hash table (14-bit index, 16 KiB
//! `u32` entries) to find back-references — the same general shape as the
//! reference `snappy::CompressFragment` implementation. Matches are
//! emitted greedily; runs that cannot find a back-reference are folded
//! into literal tags. The maximum match length per copy tag is 64 bytes,
//! and longer matches are split across multiple copy tags.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for Snappy.
#[derive(Debug, Clone, Copy, Default)]
pub struct Snappy;

impl Algorithm for Snappy {
    const NAME: &'static str = "snappy";
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

// ─── varint helpers ───────────────────────────────────────────────────────

/// Append the Base-128 varint encoding of `value` to `out`. Up to 5 bytes
/// for a `u32`-sized length.
fn write_varint_u32(value: u32, out: &mut Vec<u8>) {
    let mut v = value;
    while v >= 0x80 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Read a Base-128 varint from `buf`. Returns `(value, bytes_read)` on
/// success, or `Error::Corrupt` if the varint runs past 5 bytes or
/// `Error::UnexpectedEnd` if the buffer is exhausted mid-varint.
fn read_varint_u32(buf: &[u8]) -> Result<(u32, usize), Error> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == 5 {
            // Snappy lengths are u32; a 6th continuation byte means overflow.
            return Err(Error::Corrupt);
        }
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            if result > u32::MAX as u64 {
                return Err(Error::Corrupt);
            }
            return Ok((result as u32, i + 1));
        }
        shift += 7;
    }
    Err(Error::UnexpectedEnd)
}

// ─── encoder ──────────────────────────────────────────────────────────────

/// Streaming Snappy encoder.
///
/// Buffers the entire input on `encode`, then emits the compressed block
/// across one or more `finish` calls.
#[derive(Debug, Default)]
pub struct Encoder {
    /// Raw input buffered across `encode` calls.
    input: Vec<u8>,
    /// Compressed output produced once `finish` first runs.
    output: Vec<u8>,
    /// Bytes of `output` already handed back to the caller.
    out_pos: usize,
    /// Set the first time `finish` actually compresses the buffered input.
    compressed: bool,
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            out_pos: 0,
            compressed: false,
        }
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        // Snappy's raw block format prefixes the stream with the uncompressed
        // length as a 32-bit varint, and the match finder addresses positions
        // with `u32`, so a block can hold at most `u32::MAX` bytes. Reject an
        // over-length stream with a clean error instead of silently truncating
        // the length field into a corrupt, undecodable stream.
        if self.input.len() as u64 + input.len() as u64 > u32::MAX as u64 {
            return Err(Error::Unsupported);
        }
        // Buffer the whole input — Snappy needs the total length up front,
        // and back-references can reach anywhere within the block, so we
        // can't emit anything until the caller signals end of input.
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.compressed {
            compress_block(&self.input, &mut self.output);
            self.compressed = true;
        }
        let remaining = self.output.len() - self.out_pos;
        let n = remaining.min(output.len());
        output[..n].copy_from_slice(&self.output[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        let done = self.out_pos == self.output.len();
        Ok(RawProgress {
            consumed: 0,
            written: n,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_pos = 0;
        self.compressed = false;
    }
}

/// Count bytes matching at `input[a..]` and `input[b..]`, advancing the `a`
/// cursor up to (not reaching) `a_limit`. `b` is always behind `a`, so `b+len`
/// stays in bounds whenever `a+len` does. Compares 8 bytes per step via an LE
/// `u64` load + XOR + `trailing_zeros`; identical result to the scalar loop, so
/// the emitted match length (and the wire bytes) are unchanged.
#[inline]
fn match_forward(input: &[u8], a: usize, b: usize, a_limit: usize) -> usize {
    let mut len = 0usize;
    while a + len + 8 <= a_limit {
        let mut xa = [0u8; 8];
        let mut xb = [0u8; 8];
        xa.copy_from_slice(&input[a + len..a + len + 8]);
        xb.copy_from_slice(&input[b + len..b + len + 8]);
        let x = u64::from_le_bytes(xa) ^ u64::from_le_bytes(xb);
        if x != 0 {
            return len + (x.trailing_zeros() as usize >> 3);
        }
        len += 8;
    }
    while a + len < a_limit && input[a + len] == input[b + len] {
        len += 1;
    }
    len
}

/// Compress `input` into `out` as a single Snappy raw block.
///
/// Layout:
/// * Varint-encoded `input.len()`.
/// * A literal+copy tag stream covering every byte of `input`.
fn compress_block(input: &[u8], out: &mut Vec<u8>) {
    out.clear();
    write_varint_u32(input.len() as u32, out);

    if input.is_empty() {
        return;
    }
    // For very short inputs there's no room for a 4-byte back-reference
    // anchor, so just emit one literal tag and return. This also keeps the
    // hash-matcher loop below from indexing past the end.
    if input.len() < 4 {
        emit_literal(input, out);
        return;
    }

    // Sized to roughly match the reference implementation's small-input
    // path. 14-bit index ⇒ 16384 slots, each a u32 byte position.
    const HASH_BITS: u32 = 14;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    const NIL: u32 = u32::MAX;

    let mut table = alloc::vec![NIL; HASH_SIZE];

    let input_end = input.len();
    // The reference encoder reserves the last few bytes for a final
    // literal so that match probes never read past the buffer.
    let match_limit = input_end.saturating_sub(4);

    let mut next_emit = 0usize; // first byte not yet covered by a tag
    let mut ip = 0usize; // current position being hashed

    // Helper: produce a 32-bit hash of the 4-byte sequence at `pos`.
    let hash = |bytes: &[u8], pos: usize| -> usize {
        // Multiplicative hash with the canonical Snappy 0x1E35A7BD constant.
        let v = (bytes[pos] as u32)
            | ((bytes[pos + 1] as u32) << 8)
            | ((bytes[pos + 2] as u32) << 16)
            | ((bytes[pos + 3] as u32) << 24);
        ((v.wrapping_mul(0x1E35A7BD)) >> (32 - HASH_BITS)) as usize
    };

    // Match-or-literal main loop.
    // Skip-step accelerator: advance faster the longer the matcher goes
    // without a hit, so incompressible regions are scanned in large strides
    // (mirrors the reference encoder's `skip`/`bytes_between_hash_lookups`).
    // A hit resets the stride to 1 byte.
    let mut search_match_nb: u32 = 1 << 5;

    while ip < match_limit {
        let h = hash(input, ip);
        let candidate = table[h] as usize;
        table[h] = ip as u32;

        // A candidate is valid if the 4 bytes at `candidate` equal the
        // 4 bytes at `ip` and the offset fits in u32. Offset 0 means
        // "no candidate yet" — guarded by the NIL sentinel above.
        let four_match = (table[h] != NIL)
            && (candidate < ip)
            && candidate + 3 < input_end
            && input[candidate] == input[ip]
            && input[candidate + 1] == input[ip + 1]
            && input[candidate + 2] == input[ip + 2]
            && input[candidate + 3] == input[ip + 3];

        if !four_match {
            let step = (search_match_nb >> 5) as usize;
            search_match_nb += 1;
            ip += step;
            continue;
        }
        search_match_nb = 1 << 5;

        // Found a 4-byte match. First, flush any pending literal.
        if next_emit < ip {
            emit_literal(&input[next_emit..ip], out);
        }

        // Extend the match as far as it'll go, 8 bytes at a time.
        let mut match_len = 4 + match_forward(input, ip + 4, candidate + 4, input_end);
        let offset = (ip - candidate) as u32;

        // Emit one or more copy tags (max 64 bytes per tag).
        let mut emitted = 0usize;
        while match_len > 0 {
            // Snappy copy tags need length >= 4. The remainder logic below
            // guarantees that: a length-extending loop pass either takes a
            // full 64-byte copy, or — for the final one — splits so that
            // both pieces are >= 4 bytes.
            let take = if match_len <= 64 {
                match_len
            } else if match_len < 68 {
                // Avoid leaving a < 4 byte remainder.
                match_len - 4
            } else {
                64
            };
            emit_copy(offset, take as u32, out);
            // Insert the position-after-emit into the hash table so that
            // subsequent passes can chain through the middle of long
            // matches (mirrors the reference encoder).
            let pos_after = ip + emitted + take;
            if pos_after + 3 < input_end {
                let h2 = hash(input, pos_after - 1);
                table[h2] = (pos_after - 1) as u32;
            }
            emitted += take;
            match_len -= take;
        }

        ip += emitted;
        next_emit = ip;
        // Seed the hash table with the position just before `ip` so the
        // next iteration can immediately find a match starting there.
        if ip + 3 < input_end {
            let h2 = hash(input, ip - 1);
            table[h2] = (ip - 1) as u32;
        }
    }

    // Flush trailing literal.
    if next_emit < input_end {
        emit_literal(&input[next_emit..], out);
    }
}

/// Emit a literal tag covering `data`.
fn emit_literal(data: &[u8], out: &mut Vec<u8>) {
    debug_assert!(!data.is_empty());
    let n = data.len();
    let n_minus_1 = (n - 1) as u32;
    // Tag byte's low 2 bits are 0b00 for a literal, so we just shift the
    // length-class bits into the upper 6 bits.
    if n_minus_1 < 60 {
        out.push((n_minus_1 as u8) << 2);
    } else if n_minus_1 < 1 << 8 {
        out.push(60 << 2);
        out.push(n_minus_1 as u8);
    } else if n_minus_1 < 1 << 16 {
        out.push(61 << 2);
        out.push(n_minus_1 as u8);
        out.push((n_minus_1 >> 8) as u8);
    } else if n_minus_1 < 1 << 24 {
        out.push(62 << 2);
        out.push(n_minus_1 as u8);
        out.push((n_minus_1 >> 8) as u8);
        out.push((n_minus_1 >> 16) as u8);
    } else {
        out.push(63 << 2);
        out.push(n_minus_1 as u8);
        out.push((n_minus_1 >> 8) as u8);
        out.push((n_minus_1 >> 16) as u8);
        out.push((n_minus_1 >> 24) as u8);
    }
    out.extend_from_slice(data);
}

/// Emit a single copy tag with `length` (4..=64) and `offset` (1..=u32::MAX).
fn emit_copy(offset: u32, length: u32, out: &mut Vec<u8>) {
    debug_assert!((4..=64).contains(&length));
    debug_assert!(offset >= 1);
    if length <= 11 && offset < (1 << 11) {
        // Tag 01: 1-byte offset.
        let len_bits = ((length - 4) as u8) << 2;
        let off_hi = ((offset >> 8) as u8) << 5;
        out.push(0b01 | len_bits | off_hi);
        out.push(offset as u8);
    } else if offset < (1 << 16) {
        // Tag 10: 2-byte offset.
        let len_bits = ((length - 1) as u8) << 2;
        out.push(0b10 | len_bits);
        out.push(offset as u8);
        out.push((offset >> 8) as u8);
    } else {
        // Tag 11: 4-byte offset.
        let len_bits = ((length - 1) as u8) << 2;
        out.push(0b11 | len_bits);
        out.push(offset as u8);
        out.push((offset >> 8) as u8);
        out.push((offset >> 16) as u8);
        out.push((offset >> 24) as u8);
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// Streaming Snappy decoder.
///
/// Buffers the entire compressed stream on `decode`, then emits the
/// decompressed bytes across one or more `finish` calls.
///
/// With an output limit set
/// ([`Decoder::set_output_limit`](crate::Decoder::set_output_limit), which
/// [`LimitedDecoder`](crate::limit::LimitedDecoder) calls), a block whose
/// leading length varint declares more than the limit is refused with
/// [`Error::OutputLimitExceeded`] by the `decode` call that completes the
/// varint, before the block is buffered or any output is built.
#[derive(Debug)]
pub struct Decoder {
    /// Raw compressed bytes buffered across `decode` calls.
    input: Vec<u8>,
    /// Decompressed output produced once `finish` first runs.
    output: Vec<u8>,
    /// Bytes of `output` already handed back to the caller.
    out_pos: usize,
    /// Set the first time `finish` actually decompresses the buffered input.
    decompressed: bool,
    /// Most bytes the caller will take; `u64::MAX` means no limit.
    /// Configuration: survives `reset`.
    output_limit: u64,
    /// The length varint has been looked at against `output_limit` (or is
    /// malformed, which `finish` reports).
    header_checked: bool,
    /// The block declares more than `output_limit`; every call fails until
    /// `reset`.
    over_limit: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            out_pos: 0,
            decompressed: false,
            output_limit: u64::MAX,
            header_checked: false,
            over_limit: false,
        }
    }

    /// Check the block's declared length against the output limit as soon
    /// as the varint is complete, looking at the bytes already buffered
    /// followed by `incoming` (which is not buffered yet).
    fn check_header(&mut self, incoming: &[u8]) -> Result<(), Error> {
        if self.over_limit {
            return Err(Error::OutputLimitExceeded);
        }
        if self.header_checked || self.output_limit == u64::MAX {
            return Ok(());
        }
        // A u32 varint is at most 5 bytes; a 6th lets `read_varint_u32`
        // tell an overlong one from an incomplete one.
        let mut head = [0u8; 6];
        let mut n = 0;
        for &b in self.input.iter().chain(incoming).take(head.len()) {
            head[n] = b;
            n += 1;
        }
        match read_varint_u32(&head[..n]) {
            Ok((declared, _)) => {
                if u64::from(declared) > self.output_limit {
                    self.over_limit = true;
                    return Err(Error::OutputLimitExceeded);
                }
                self.header_checked = true;
            }
            // Varint not complete yet: look again when more input arrives.
            Err(Error::UnexpectedEnd) => {}
            // Malformed: `finish` reports it, as it does without a limit.
            Err(_) => self.header_checked = true,
        }
        Ok(())
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        // Before buffering: a block over the limit is not worth keeping.
        self.check_header(input)?;
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.over_limit {
            return Err(Error::OutputLimitExceeded);
        }
        if !self.decompressed {
            decompress_block(&self.input, &mut self.output, self.output_limit)?;
            self.decompressed = true;
        }
        let remaining = self.output.len() - self.out_pos;
        let n = remaining.min(output.len());
        output[..n].copy_from_slice(&self.output[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        let done = self.out_pos == self.output.len();
        Ok(RawProgress {
            consumed: 0,
            written: n,
            done,
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_pos = 0;
        self.decompressed = false;
        // `output_limit` is configuration and is kept.
        self.header_checked = false;
        self.over_limit = false;
    }

    fn raw_set_output_limit(&mut self, max_output_bytes: u64) {
        self.output_limit = max_output_bytes;
        // Look at the header again under the new limit.
        self.header_checked = false;
    }
}

/// Upper bound on the output `payload_len` bytes of Snappy tags can
/// produce.
///
/// The densest element of the format is a copy with a 2-byte offset: 3
/// bytes of input for up to 64 bytes of output (64/3 ≈ 21.3×). Every other
/// element is worse — a 2-byte copy with a 1-byte offset yields at most 11
/// bytes (5.5×), a 5-byte copy with a 4-byte offset at most 64 (12.8×), and
/// a literal never expands at all — so no block can exceed
/// `ceil(payload_len * 64 / 3)`. Computed in `u64` so it cannot overflow a
/// 32-bit `usize`.
fn max_uncompressed_len(payload_len: usize) -> u64 {
    (payload_len as u64).saturating_mul(64).div_ceil(3)
}

/// First allocation made for a block's output, however large the header
/// claims it is.
const INITIAL_OUTPUT_CAPACITY: usize = 64 * 1024;

/// Make room for `additional` more bytes in `out`.
///
/// The caller has already checked `out.len() + additional <=
/// uncompressed_len`. The buffer is grown geometrically, only as real
/// output is produced, and never past `uncompressed_len`; an allocation
/// the platform cannot satisfy (e.g. more than `isize::MAX` bytes on a
/// 32-bit target) is reported as an error rather than a panic.
#[inline]
fn reserve_output(
    out: &mut Vec<u8>,
    additional: usize,
    uncompressed_len: usize,
) -> Result<(), Error> {
    let needed = out.len() + additional;
    if needed <= out.capacity() {
        return Ok(());
    }
    grow_output(out, needed, uncompressed_len)
}

#[cold]
fn grow_output(out: &mut Vec<u8>, needed: usize, uncompressed_len: usize) -> Result<(), Error> {
    let target = out
        .capacity()
        .saturating_mul(2)
        .max(INITIAL_OUTPUT_CAPACITY)
        .max(needed)
        .min(uncompressed_len);
    out.try_reserve_exact(target - out.len())
        .map_err(|_| Error::Corrupt)
}

/// Decompress one Snappy raw block into `out`, refusing a block that
/// declares more than `output_limit` bytes before producing any of them.
fn decompress_block(input: &[u8], out: &mut Vec<u8>, output_limit: u64) -> Result<(), Error> {
    out.clear();

    if input.is_empty() {
        return Err(Error::UnexpectedEnd);
    }

    let (uncompressed_len, vi_len) = read_varint_u32(input)?;
    if u64::from(uncompressed_len) > output_limit {
        return Err(Error::OutputLimitExceeded);
    }
    // The varint is attacker-controlled (up to 4 GiB) and is read before a
    // single tag has been validated, so reject any length the remaining
    // input could not possibly expand to. This is the format's exact
    // ceiling, so it never rejects a valid block.
    if u64::from(uncompressed_len) > max_uncompressed_len(input.len() - vi_len) {
        return Err(Error::Corrupt);
    }
    let uncompressed_len = usize::try_from(uncompressed_len).map_err(|_| Error::Corrupt)?;
    // Deliberately no `reserve(uncompressed_len)` here: even a plausible
    // claim is ~21× the input, so the buffer is grown by `reserve_output`
    // as output is actually produced.

    let mut ip = vi_len;
    let input_end = input.len();

    while ip < input_end {
        let tag = input[ip];
        ip += 1;
        match tag & 0b11 {
            0b00 => {
                // Literal.
                let upper = (tag >> 2) as u32;
                let length = if upper < 60 {
                    upper + 1
                } else {
                    let extra = (upper - 59) as usize; // 1..=4
                    if ip + extra > input_end {
                        return Err(Error::UnexpectedEnd);
                    }
                    let mut len_minus_1: u32 = 0;
                    for i in 0..extra {
                        len_minus_1 |= (input[ip + i] as u32) << (8 * i);
                    }
                    ip += extra;
                    // A length of 2^32 cannot fit a block whose total
                    // uncompressed length is a u32; never let it wrap to 0.
                    len_minus_1.checked_add(1).ok_or(Error::Corrupt)?
                };
                // `length` is attacker-controlled and can be close to
                // `u32::MAX`, so on a 32-bit target `ip + length` and
                // `out.len() + length` could wrap. Compare against the
                // space that is left instead (`ip <= input_end` and
                // `out.len() <= uncompressed_len` always hold here).
                let length = usize::try_from(length).map_err(|_| Error::Corrupt)?;
                if length > input_end - ip {
                    return Err(Error::UnexpectedEnd);
                }
                if length > uncompressed_len - out.len() {
                    return Err(Error::Corrupt);
                }
                reserve_output(out, length, uncompressed_len)?;
                out.extend_from_slice(&input[ip..ip + length]);
                ip += length;
            }
            0b01 => {
                // Copy with 1-byte offset.
                if ip >= input_end {
                    return Err(Error::UnexpectedEnd);
                }
                let length = (((tag >> 2) & 0x07) as usize) + 4;
                let off_hi = ((tag >> 5) & 0x07) as usize;
                let offset = (off_hi << 8) | (input[ip] as usize);
                ip += 1;
                copy_from_back(out, offset, length, uncompressed_len)?;
            }
            0b10 => {
                // Copy with 2-byte offset.
                if ip + 2 > input_end {
                    return Err(Error::UnexpectedEnd);
                }
                let length = (((tag >> 2) & 0x3F) as usize) + 1;
                let offset = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
                ip += 2;
                copy_from_back(out, offset, length, uncompressed_len)?;
            }
            0b11 => {
                // Copy with 4-byte offset.
                if ip + 4 > input_end {
                    return Err(Error::UnexpectedEnd);
                }
                let length = (((tag >> 2) & 0x3F) as usize) + 1;
                let offset = (input[ip] as usize)
                    | ((input[ip + 1] as usize) << 8)
                    | ((input[ip + 2] as usize) << 16)
                    | ((input[ip + 3] as usize) << 24);
                ip += 4;
                copy_from_back(out, offset, length, uncompressed_len)?;
            }
            _ => unreachable!(),
        }
    }

    if out.len() != uncompressed_len {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// Copy `length` bytes from `offset` bytes behind the current end of `out`
/// to the current end of `out`. Self-overlapping copies (offset < length)
/// are allowed and produce an LZ77-style RLE-style fill.
fn copy_from_back(
    out: &mut Vec<u8>,
    offset: usize,
    length: usize,
    uncompressed_len: usize,
) -> Result<(), Error> {
    if offset == 0 || offset > out.len() {
        return Err(Error::InvalidDistance);
    }
    // Subtraction form: `out.len() <= uncompressed_len` is an invariant, so
    // this cannot wrap the way `out.len() + length` could.
    if length > uncompressed_len - out.len() {
        return Err(Error::Corrupt);
    }
    reserve_output(out, length, uncompressed_len)?;
    let start = out.len() - offset;
    if offset >= length {
        // Non-overlapping: collapses to memcpy.
        out.extend_from_within(start..start + length);
    } else if offset == 1 {
        // Byte-splat: replicate a single byte.
        let b = out[start];
        out.resize(out.len() + length, b);
    } else {
        // Self-overlapping (RLE-style) — copy in `offset`-sized chunks. Each
        // round duplicates the tail produced so far, doubling the source
        // region, so the loop runs a logarithmic number of times.
        let mut remaining = length;
        while remaining > 0 {
            let chunk = remaining.min(offset);
            let s = out.len() - offset;
            out.extend_from_within(s..s + chunk);
            remaining -= chunk;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_uncompressed_len_is_the_format_ceiling() {
        assert_eq!(max_uncompressed_len(0), 0);
        // One 3-byte copy tag: 64 bytes.
        assert_eq!(max_uncompressed_len(3), 64);
        // A 2-byte copy tag can emit 11 bytes; the bound must allow it.
        assert!(max_uncompressed_len(2) >= 11);
        assert_eq!(max_uncompressed_len(3_000_000), 64_000_000);
        // No overflow at the top of the range, on any pointer width.
        assert!(max_uncompressed_len(usize::MAX) >= u64::from(u32::MAX));
    }

    #[test]
    fn over_limit_block_is_neither_buffered_nor_decompressed() {
        // Header claims 1 MiB; the tags behind it never get looked at.
        let mut block = Vec::new();
        write_varint_u32(1 << 20, &mut block);
        block.resize(64 * 1024, 0);

        let mut dec = Decoder::new();
        dec.raw_set_output_limit(4096);
        assert_eq!(
            dec.raw_decode(&block, &mut []),
            Err(Error::OutputLimitExceeded)
        );
        assert_eq!(dec.input.capacity(), 0, "refused input was buffered");
        assert_eq!(dec.output.capacity(), 0);

        // Same when the varint straddles two calls: only the bytes before
        // the one that completes it are kept.
        dec.raw_reset();
        assert!(dec.raw_decode(&block[..2], &mut []).is_ok());
        assert_eq!(
            dec.raw_decode(&block[2..], &mut []),
            Err(Error::OutputLimitExceeded)
        );
        assert_eq!(dec.input.len(), 2);
        assert_eq!(dec.raw_finish(&mut []), Err(Error::OutputLimitExceeded));
        assert_eq!(dec.output.capacity(), 0);

        // The `finish` path refuses before allocating too.
        let mut out = Vec::new();
        assert_eq!(
            decompress_block(&block, &mut out, 4096),
            Err(Error::OutputLimitExceeded)
        );
        assert_eq!(out.capacity(), 0);
    }

    #[test]
    fn output_buffer_is_not_reserved_from_the_header() {
        // A header that plausibly claims 16 MiB (the input is large enough
        // for that) followed by an invalid tag. The decoder must fail
        // without ever having sized its output buffer from the claim.
        let claimed: u32 = 16 * 1024 * 1024;
        let mut block = Vec::new();
        write_varint_u32(claimed, &mut block);
        block.extend_from_slice(&[0x00, b'a']);
        // Copy tags with offset 0: invalid as soon as the first is parsed.
        for _ in 0..512 * 1024 {
            block.extend_from_slice(&[0x01, 0x00]);
        }
        let mut out = Vec::new();
        assert_eq!(
            decompress_block(&block, &mut out, u64::MAX),
            Err(Error::InvalidDistance)
        );
        assert!(
            out.capacity() < 1024 * 1024,
            "output capacity {} was sized from the header",
            out.capacity()
        );
    }
}
