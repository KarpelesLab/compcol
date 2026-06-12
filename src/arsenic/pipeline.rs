//! Arsenic decode pipeline: header → per-block token loop → un-MTF →
//! inverse BWT → optional de-randomization → final RLE → CRC check.
//!
//! See FORMAT-SPEC §3–§6. Decodes a complete buffered stream in one shot.

use alloc::vec;
use alloc::vec::Vec;

use crate::arsenic::range::{Model, RangeDecoder};
use crate::arsenic::tables::{INITIAL_MODEL, MTF_MODELS, RAND_TABLE, SELECTOR_MODEL};
use crate::error::Error;

/// Hard cap on a single block (FORMAT-SPEC §3: blockbits ≤ 24 → 16 MiB).
const MAX_BLOCK_BITS: u32 = 24;

/// Hard cap on total one-shot decode output. The block loop (`while end_flag
/// == 0`) is unbounded and the final-RLE layer can expand ~51× per block, so a
/// small crafted stream could otherwise drive `out` to unbounded size. Matches
/// the sibling sit13 decoder's `DEFAULT_OUTPUT_CAP`.
const DEFAULT_OUTPUT_CAP: usize = 256 * 1024 * 1024;

/// Outcome of a full-stream decode attempt.
pub(crate) enum DecodeOutcome {
    /// The stream was decoded to completion (CRC verified).
    Complete(Vec<u8>),
    /// The bitstream ran out before the in-band terminator was reached; the
    /// caller should buffer more input and retry.
    NeedMore,
}

/// CRC-32 (poly 0xEDB88320, init 0xFFFFFFFF), table-free byte update.
#[inline]
fn crc32_update(crc: u32, byte: u8) -> u32 {
    let mut c = crc ^ byte as u32;
    for _ in 0..8 {
        let mask = (c & 1).wrapping_neg();
        c = (c >> 1) ^ (0xEDB8_8320 & mask);
    }
    c
}

/// Inverse move-to-front table over the 256 byte values.
struct UnMtf {
    table: [u8; 256],
}

impl UnMtf {
    fn new() -> Self {
        let mut table = [0u8; 256];
        for (i, t) in table.iter_mut().enumerate() {
            *t = i as u8;
        }
        Self { table }
    }

    #[inline]
    fn front(&self) -> u8 {
        self.table[0]
    }

    /// Remove the entry at `index` and reinsert it at the front; return it.
    #[inline]
    fn apply(&mut self, index: usize) -> u8 {
        let value = self.table[index];
        // Shift table[0..index] up by one, then place value at front.
        self.table.copy_within(0..index, 1);
        self.table[0] = value;
        value
    }
}

/// De-randomization state (FORMAT-SPEC §6.2/§6.4). XOR-corrects the
/// least-significant bit of bytes whose position equals a running cumulative
/// sum of [`RAND_TABLE`] entries (indexed cyclically). Inert unless the
/// block's randomized flag is set.
struct Derandomizer {
    enabled: bool,
    index: usize,
    /// Next byte position (0-based) at which a correction fires.
    next_count: u64,
}

impl Derandomizer {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            index: 0,
            next_count: RAND_TABLE[0] as u64,
        }
    }

    /// Given the inverse-BWT `byte` at output position `byte_count`, return
    /// the corrected byte. `byte_count` is the index of this byte (the value
    /// *before* it is incremented by the caller).
    #[inline]
    fn correct(&mut self, byte: u8, byte_count: u64) -> u8 {
        if self.enabled && byte_count == self.next_count {
            self.index = (self.index + 1) & 255;
            self.next_count += RAND_TABLE[self.index] as u64;
            byte ^ 1
        } else {
            byte
        }
    }
}

/// Decode a complete Arsenic stream. Returns `NeedMore` on input underflow
/// before the terminator; `Err(Corrupt)` on a malformed but complete stream.
pub(crate) fn decode_stream(data: &[u8]) -> Result<DecodeOutcome, Error> {
    if data.is_empty() {
        return Ok(DecodeOutcome::NeedMore);
    }

    let mut rc = RangeDecoder::new(data);

    // Persistent models. The initial model is *not* reset between blocks;
    // selector + mtf models are reset per block (FORMAT-SPEC §5.4).
    let mut initial = Model::new(&INITIAL_MODEL);
    let mut selector = Model::new(&SELECTOR_MODEL);
    let mut mtf_models: Vec<Model> = MTF_MODELS.iter().map(Model::new).collect();

    macro_rules! check_underflow {
        () => {
            if rc.underflowed() {
                return Ok(DecodeOutcome::NeedMore);
            }
        };
    }

    // ── Stream header (FORMAT-SPEC §3) ──────────────────────────────────
    let sig1 = rc.decode_bits(&mut initial, 8)?;
    let sig2 = rc.decode_bits(&mut initial, 8)?;
    check_underflow!();
    if sig1 != u32::from(b'A') || sig2 != u32::from(b's') {
        return Err(Error::Corrupt);
    }

    let field = rc.decode_bits(&mut initial, 4)?;
    let block_bits = field + 9;
    check_underflow!();
    if block_bits > MAX_BLOCK_BITS {
        return Err(Error::Corrupt);
    }
    let block_size = 1usize << block_bits;

    let mut out: Vec<u8> = Vec::new();
    let mut crc: u32 = 0xFFFF_FFFF;

    // First end-of-blocks flag: if 1, there are no blocks (empty stream).
    let mut end_flag = rc.decode_index(&mut initial)?;
    check_underflow!();

    // Reusable per-block scratch buffers.
    let mut block: Vec<u8> = Vec::new();

    while end_flag == 0 {
        // ── Block header (§5.1) ─────────────────────────────────────────
        let mut unmtf = UnMtf::new();
        let randomized = rc.decode_index(&mut initial)? == 1;
        let primary = rc.decode_bits(&mut initial, block_bits)? as usize;
        check_underflow!();

        // ── Token loop (§5.2): produce BWT last-column bytes ────────────
        block.clear();
        let mut sel = rc.decode_value(&mut selector)? as u32;
        check_underflow!();
        loop {
            if sel < 2 {
                // Zero-run: bijective base-2 accumulation of MTF-index-0 runs.
                let mut weight: u64 = 1;
                let mut count: u64 = 0;
                while sel < 2 {
                    if sel == 0 {
                        count += weight;
                    } else {
                        count += 2 * weight;
                    }
                    weight <<= 1;
                    // Guard against an unbounded run that would overflow the
                    // block well before producing it.
                    if count > block_size as u64 {
                        return Err(Error::Corrupt);
                    }
                    sel = rc.decode_value(&mut selector)? as u32;
                    check_underflow!();
                }
                let count = count as usize;
                if block.len() + count > block_size {
                    return Err(Error::Corrupt);
                }
                let zero_val = unmtf.front();
                for _ in 0..count {
                    block.push(zero_val);
                }
                // `sel` now holds the first value >= 2 that ended the run;
                // fall through to handle it below.
            }

            if sel == 10 {
                // End of block.
                break;
            }

            // Single literal MTF index (§5.2.4).
            let m: usize = if sel == 2 {
                1
            } else {
                // sel in 3..=9 → mtf model (sel - 3).
                let mi = (sel - 3) as usize;
                if mi >= mtf_models.len() {
                    return Err(Error::Corrupt);
                }
                let v = rc.decode_value(&mut mtf_models[mi])? as usize;
                check_underflow!();
                v
            };
            if block.len() >= block_size {
                return Err(Error::Corrupt);
            }
            let byte = unmtf.apply(m);
            block.push(byte);

            sel = rc.decode_value(&mut selector)? as u32;
            check_underflow!();
        }

        let numbytes = block.len();

        // Reset selector + mtf models for the next block (§5.4.1).
        selector.reset();
        for m in mtf_models.iter_mut() {
            m.reset();
        }

        // End-of-blocks flag for *this* block (§5.4.2).
        end_flag = rc.decode_index(&mut initial)?;
        check_underflow!();
        let last_block = end_flag == 1;
        // The 32-bit CRC trailer follows only the final block.
        let stored_crc = if last_block {
            let v = rc.decode_bits(&mut initial, 32)?;
            check_underflow!();
            Some(v)
        } else {
            None
        };

        // ── Inverse BWT (§5.5) ──────────────────────────────────────────
        // Primary index must be a valid row of the sorted-rotations matrix.
        if numbytes == 0 {
            // An empty block produces no output; only valid if primary == 0.
            if primary != 0 {
                return Err(Error::Corrupt);
            }
            if let Some(stored) = stored_crc
                && stored != !crc
            {
                return Err(Error::Corrupt);
            }
            continue;
        }
        if primary >= numbytes {
            return Err(Error::Corrupt);
        }

        let mut counts = [0u32; 256];
        for &b in &block {
            counts[b as usize] += 1;
        }
        let mut base = [0u32; 256];
        let mut acc = 0u32;
        for v in 0..256 {
            base[v] = acc;
            acc += counts[v];
        }
        let mut transform: Vec<u32> = vec![0u32; numbytes];
        let mut seen = [0u32; 256];
        for (i, &b) in block.iter().enumerate() {
            let v = b as usize;
            let pos = (base[v] + seen[v]) as usize;
            transform[pos] = i as u32;
            seen[v] += 1;
        }

        // ── Output stage (§6): de-randomization + final RLE ─────────────
        let mut idx = primary;
        let mut derand = Derandomizer::new(randomized);
        let mut byte_count: u64 = 0;

        // Final-RLE state.
        let mut rle_count: u32 = 0;
        let mut rle_last: u8 = 0;
        let mut rle_repeat: u32 = 0;

        // Pull one inverse-BWT byte (§6.2), applying de-randomization.
        macro_rules! pull_ibwt {
            () => {{
                idx = transform[idx] as usize;
                let b = derand.correct(block[idx], byte_count);
                byte_count += 1;
                b
            }};
        }

        // The final-RLE layer emits one logical output byte per loop turn,
        // consuming `numbytes` inverse-BWT bytes total.
        while byte_count < numbytes as u64 || rle_repeat > 0 {
            // Bound total output across all blocks. The final-RLE layer can
            // expand a 16 MiB block ~51×, so the check must live inside the
            // emit loop, not merely per-block.
            if out.len() >= DEFAULT_OUTPUT_CAP {
                return Err(Error::Corrupt);
            }
            if rle_repeat > 0 {
                out.push(rle_last);
                crc = crc32_update(crc, rle_last);
                rle_repeat -= 1;
                continue;
            }
            // Need another inverse-BWT byte.
            if byte_count >= numbytes as u64 {
                break;
            }
            let byte = pull_ibwt!();
            if rle_count == 4 {
                rle_count = 0;
                if byte == 0 {
                    // Run of exactly four; no extra copies. Loop to pull next.
                    continue;
                }
                rle_repeat = (byte - 1) as u32;
                out.push(rle_last);
                crc = crc32_update(crc, rle_last);
            } else {
                if byte == rle_last {
                    rle_count += 1;
                } else {
                    rle_count = 1;
                    rle_last = byte;
                }
                out.push(byte);
                crc = crc32_update(crc, byte);
            }
        }

        // CRC check after the final block (§6.6).
        if let Some(stored) = stored_crc
            && stored != !crc
        {
            return Err(Error::Corrupt);
        }
    }

    Ok(DecodeOutcome::Complete(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926 (after the standard final XOR,
        // i.e. the complement of the running register). We replicate the
        // pipeline's running CRC and complement it.
        let mut crc = 0xFFFF_FFFFu32;
        for &b in b"123456789" {
            crc = crc32_update(crc, b);
        }
        assert_eq!(!crc, 0xCBF4_3926);
    }

    #[test]
    fn unmtf_moves_to_front() {
        let mut t = UnMtf::new();
        // Identity table: front is 0.
        assert_eq!(t.front(), 0);
        // Pull index 5 → value 5, now front.
        assert_eq!(t.apply(5), 5);
        assert_eq!(t.front(), 5);
        // Pull index 0 → the value just moved to front (5), unchanged order.
        assert_eq!(t.apply(0), 5);
        // Pull index 1 → value 0 (was shifted to position 1), moves to front.
        assert_eq!(t.apply(1), 0);
        assert_eq!(t.front(), 0);
    }

    #[test]
    fn derandomizer_disabled_is_identity() {
        let mut d = Derandomizer::new(false);
        for i in 0..1000u64 {
            assert_eq!(d.correct(0xAA, i), 0xAA);
        }
    }

    #[test]
    fn derandomizer_xors_at_table_spaced_positions() {
        // The first correction fires at position RAND_TABLE[0] (=238), the
        // next at RAND_TABLE[0]+RAND_TABLE[1], etc. (FORMAT-SPEC §6.2/§6.4).
        let mut d = Derandomizer::new(true);
        let p0 = RAND_TABLE[0] as u64;
        let p1 = p0 + RAND_TABLE[1] as u64;
        let p2 = p1 + RAND_TABLE[2] as u64;

        let mut corrected = Vec::new();
        for i in 0..=p2 {
            // Feed a fixed 0x00 byte; corrections flip the low bit to 0x01.
            if d.correct(0x00, i) == 0x01 {
                corrected.push(i);
            }
        }
        assert_eq!(corrected, vec![p0, p1, p2]);
    }

    #[test]
    fn empty_input_is_need_more() {
        assert!(matches!(decode_stream(&[]), Ok(DecodeOutcome::NeedMore)));
    }

    #[test]
    fn random_table_has_256_entries() {
        assert_eq!(RAND_TABLE.len(), 256);
        // A spot-check on the embedded values (first/last) to guard against
        // an accidental transcription drift.
        assert_eq!(RAND_TABLE[0], 238);
        assert_eq!(RAND_TABLE[255], 23);
    }
}
