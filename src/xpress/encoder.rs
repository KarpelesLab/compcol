//! Streaming encoder for the Plain LZ77 codec.
//!
//! Strategy: accumulate raw input into a `Vec<u8>` during `encode`,
//! produce the compressed payload on the first `finish` call, then
//! drain the staged buffer to the caller across however many further
//! `finish` calls are needed.
//!
//! The matcher is a single-hashtable LZ77 (one hit per slot, no chain),
//! matched against the canonical 8 KiB sliding window. This keeps the
//! encoder small and predictable while still giving a useful ratio on
//! data with short-period repetition (the corpora we care about: WIM
//! file contents, configuration text, scripts). It is not byte-for-byte
//! compatible with Microsoft's encoders — those use richer match
//! searchers — but the output is a conformant Plain LZ77 stream.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawEncoder, RawProgress};

use super::{MAX_DISTANCE, MIN_MATCH};

/// Number of slots in the encoder hash table. Sized for a single 8 KiB
/// window so the table fits comfortably in L1 cache.
const HASH_BITS: u32 = 13;
const HASH_SIZE: usize = 1 << HASH_BITS;
const HASH_EMPTY: u32 = u32::MAX;

/// Streaming encoder phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    /// Accepting raw bytes; nothing has been encoded yet.
    Buffering,
    /// Staged compressed output is being drained.
    Draining,
    /// All bytes (including the 8-byte length header) have been emitted.
    Done,
}

/// Plain LZ77 encoder. Carries no tunables.
pub struct Encoder {
    raw: Vec<u8>,
    staged: Vec<u8>,
    staged_idx: usize,
    phase: EncPhase,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            raw: Vec::new(),
            staged: Vec::new(),
            staged_idx: 0,
            phase: EncPhase::Buffering,
        }
    }

    /// Drain as many bytes as will fit from `self.staged[self.staged_idx..]`
    /// into `output[*written..]`.
    fn drain_staged(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.staged.len() - self.staged_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.staged[self.staged_idx..self.staged_idx + n]);
            self.staged_idx += n;
            *written += n;
        }
        if self.staged_idx == self.staged.len() {
            self.staged.clear();
            self.staged_idx = 0;
            self.phase = EncPhase::Done;
        }
    }

    /// Run the LZ77 matcher over `self.raw` and produce a Plain LZ77
    /// payload in `self.staged`. Prepends the 8-byte length header.
    fn build_stream(&mut self) {
        self.staged.clear();
        self.staged
            .extend_from_slice(&(self.raw.len() as u64).to_le_bytes());

        if self.raw.is_empty() {
            return;
        }

        encode_payload(&self.raw, &mut self.staged);
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        // Encoder buffers everything until `finish`. No staged output
        // exists yet during `encode`; we just accept input.
        let _ = output;
        if self.phase != EncPhase::Buffering {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: false,
            });
        }
        // The match finder addresses positions with `u32`, so above 4 GiB the
        // hash table truncates positions and can emit wrong-distance matches.
        // Reject a stream at that limit with a clean error rather than risk
        // silently corrupt output.
        if self.raw.len() as u64 + input.len() as u64 > u32::MAX as u64 {
            return Err(Error::Unsupported);
        }
        self.raw.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        loop {
            match self.phase {
                EncPhase::Buffering => {
                    self.build_stream();
                    self.staged_idx = 0;
                    self.phase = EncPhase::Draining;
                }
                EncPhase::Draining => {
                    self.drain_staged(output, &mut written);
                    if self.phase == EncPhase::Draining {
                        // Output ran out before we emptied the staged buffer.
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        self.raw.clear();
        self.staged.clear();
        self.staged_idx = 0;
        self.phase = EncPhase::Buffering;
    }
}

/// LZ77 hash over the next 3 bytes. Plain LZ77's minimum match is 3 so
/// hashing on a 3-byte key catches every useful candidate.
#[inline]
fn hash3(b: [u8; 3]) -> usize {
    // Mix the three bytes via a multiplicative constant. The constant
    // is Knuth's golden-ratio approximation; any odd 32-bit multiplier
    // works.
    let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// Encode `input` into a Plain LZ77 payload appended to `out`.
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

fn encode_payload(input: &[u8], out: &mut Vec<u8>) {
    // The matcher emits an interleaved stream of:
    // - per-flag-DWORD groups: 32 symbols max, with the 32-bit flag
    //   word inserted into `out` at the right slot.
    // - within each group, every literal byte and every 16-bit metadata
    //   sym + variable-length extension is appended after the flag slot.
    //
    // Plain LZ77's half-byte slot adds a second bookkeeping channel:
    // when we emit a tier-2 length we either claim the low nibble of a
    // fresh byte (and remember its position so the next long-match can
    // claim the high nibble) or reuse a parked byte's high nibble.

    let mut table: [u32; HASH_SIZE] = [HASH_EMPTY; HASH_SIZE];

    // Cursor into `input`.
    let mut i: usize = 0;
    // Position (within `out`) of the byte currently providing a free
    // high nibble. `None` means the next tier-2 length needs a fresh
    // byte appended.
    let mut half_byte_owner: Option<usize> = None;

    while i < input.len() {
        // Start a new 32-flag group. Reserve 4 bytes in `out` for the
        // flag word, fill them once the group closes.
        let flag_pos = out.len();
        out.extend_from_slice(&[0u8; 4]);
        let mut flag_word: u32 = 0;
        let mut emitted: u32 = 0;

        while emitted < 32 && i < input.len() {
            // Need at least 3 bytes ahead to try a match.
            let match_found = if i + MIN_MATCH <= input.len() {
                let key = hash3([input[i], input[i + 1], input[i + 2]]);
                let prev = table[key];
                table[key] = i as u32;
                if prev != HASH_EMPTY {
                    let p = prev as usize;
                    if p < i && i - p <= MAX_DISTANCE && i - p >= 1 {
                        // Verify the 3-byte prefix.
                        if input[p] == input[i]
                            && input[p + 1] == input[i + 1]
                            && input[p + 2] == input[i + 2]
                        {
                            // Extend forward, 8 bytes at a time.
                            let len = 3 + match_forward(input, i + 3, p + 3, input.len());
                            Some((p, len))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                // Less than 3 bytes left; can't be a match. Still
                // insert into the table for completeness (not needed
                // since we're about to run out).
                None
            };

            match match_found {
                Some((p, len)) => {
                    // Match symbol: flag = 1.
                    flag_word |= 1u32 << (31 - emitted);
                    let distance = i - p;
                    write_match(out, distance as u32, len as u32, &mut half_byte_owner);
                    i += len;
                }
                None => {
                    // Literal: flag = 0.
                    out.push(input[i]);
                    i += 1;
                }
            }
            emitted += 1;
        }

        // The unused flag bits at the end of a group must be 1s — both
        // because the spec mandates it (the decoder's end-of-stream
        // sniff looks for a "1..10..0" pattern, i.e. trailing 1s) and
        // because legacy decoders read a fresh flag word at slot
        // boundaries and would treat trailing 0s as literal flags
        // trying to read past the end of input.
        if emitted < 32 {
            let trailing_ones = 32 - emitted;
            // Set the bottom `trailing_ones` bits.
            let mask: u32 = if trailing_ones == 32 {
                u32::MAX
            } else {
                (1u32 << trailing_ones) - 1
            };
            flag_word |= mask;
        }

        out[flag_pos..flag_pos + 4].copy_from_slice(&flag_word.to_le_bytes());
    }
}

/// Append the metadata + length extension for a single match.
///
/// `distance` is `1..=8192`; `length` is `>= 3`; `half_byte_owner` is
/// the index in `out` of the byte whose high nibble is parked for the
/// next tier-2 length read. The function mutates this on tier-2 reads.
fn write_match(out: &mut Vec<u8>, distance: u32, length: u32, half_byte_owner: &mut Option<usize>) {
    debug_assert!(distance >= 1 && distance <= MAX_DISTANCE as u32);
    debug_assert!(length >= MIN_MATCH as u32);

    // The 16-bit sym: high 13 bits = distance - 1; low 3 bits = base
    // length code (clamped to 7 for "tier 2+" length).
    let dist_field = distance - 1; // 0..=8191, fits in 13 bits
    let length_minus_3 = length - 3;
    let lc_field: u16 = if length_minus_3 < 7 {
        length_minus_3 as u16
    } else {
        7
    };
    let sym: u16 = ((dist_field as u16) << 3) | lc_field;
    out.extend_from_slice(&sym.to_le_bytes());

    if length_minus_3 < 7 {
        return;
    }

    // Length extension.
    let remainder = length - 10; // tier-2 base: 0..=14 fits in a nibble
    if remainder < 15 {
        write_half_byte(out, remainder as u8, half_byte_owner);
        return;
    }

    // Tier 2 half-byte is 15.
    write_half_byte(out, 15, half_byte_owner);

    let after_hb = length - (15 + 7 + 3); // i.e. length - 25
    if after_hb < 255 {
        out.push(after_hb as u8);
        return;
    }

    // Tier 3 byte is 255.
    out.push(255);

    // Tier 4 writes a value `w` (or `dw`) whose final decoded length
    // is `w - 22 + 15 + 7 + 3 = w + 3`. So `w = length - 3`.
    let biased = length - 3;
    if biased <= 0xFFFF {
        // 16-bit tier.
        out.extend_from_slice(&(biased as u16).to_le_bytes());
    } else {
        // 32-bit tier: write a sentinel `0` 16-bit, then the 32-bit
        // value.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&biased.to_le_bytes());
    }
}

/// Write a 4-bit value, either by claiming the parked high nibble of a
/// previous owner or by appending a fresh byte and parking its high
/// nibble for a future call.
fn write_half_byte(out: &mut Vec<u8>, nibble: u8, owner: &mut Option<usize>) {
    debug_assert!(nibble <= 0x0F);
    match *owner {
        Some(idx) => {
            // Pour `nibble` into the high half.
            out[idx] |= nibble << 4;
            *owner = None;
        }
        None => {
            // Append a fresh byte with `nibble` in the low half; park
            // its index so the next tier-2 length can claim the high
            // half.
            let idx = out.len();
            out.push(nibble);
            *owner = Some(idx);
        }
    }
}
