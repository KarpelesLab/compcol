#![allow(dead_code)] // rle2_inverse is unused but kept symmetric for tests

//! bzip2's two run-length passes.
//!
//! ## RLE-1 (pre-BWT)
//!
//! Run-length encode the **raw input** before BWT: any run of 4..=255
//! identical bytes is replaced with 4 copies of the byte followed by a
//! single "extra count" byte holding `(run_length - 4) in 0..=251`.
//! Runs of 1..=3 bytes are emitted as-is. The decoder must run the
//! inverse pass after BWT⁻¹/MTF⁻¹/RLE-2⁻¹.
//!
//! Why: bzip2's BWT is O(n log n) on the average sort cost; runs of
//! identical bytes blow that up to O(n²) on the comparison side
//! (suffixes starting inside a long run all share an arbitrarily long
//! prefix). Capping runs at 4-then-count keeps the suffix sort
//! manageable.
//!
//! ## RLE-2 (post-MTF, zero-only)
//!
//! After MTF, the symbol stream is dominated by zeros (because BWT
//! concentrates runs of the same byte and MTF turns each such run into
//! a long stretch of zeros). RLE-2 encodes runs of zeros as a pair of
//! synthetic symbols `RUNA = 0` and `RUNB = 1`:
//!
//! ```text
//! run_length = 1·(RUNA?1:2) + 2·(RUNA?1:2) + 4·(RUNA?1:2) + ... + 1
//! ```
//!
//! That is, each subsequent RUNA/RUNB in the run doubles the
//! contribution; RUNA contributes `1×2^k`, RUNB contributes `2×2^k`.
//! The final `+1` makes the encoding self-delimiting (no run of zero
//! length).
//!
//! All non-zero MTF indices `i` are emitted as the symbol `i + 1` (so
//! symbol 2 = MTF index 1, etc.); the post-RLE-2 alphabet is
//! `{ RUNA, RUNB, mtf+1 ... }` followed by an explicit end-of-block
//! marker `EOB = alphabet_size_after_rle2 - 1`.

extern crate alloc;
use alloc::vec::Vec;

// ─── RLE-1 (raw bytes, encoder side) ─────────────────────────────────────

/// Apply bzip2's RLE-1 pre-pass to `input`.
///
/// Replace any run of `R` (3 < R ≤ 255) identical bytes with 4 copies of
/// the byte followed by a single byte holding `R - 4` (0..=251). Runs of
/// 1, 2, 3, or 4 bytes are emitted verbatim — but a run of exactly 4
/// must still be followed by a zero "extra-count" byte, because the
/// decoder always reads the count byte after seeing the 4th identical
/// byte in a row.
pub(crate) fn rle1_forward(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        // Find run length, capped at 255 (the max we can encode in one
        // 4+count token).
        let mut run = 1usize;
        while i + run < input.len() && input[i + run] == b && run < 255 {
            run += 1;
        }
        if run < 4 {
            // Emit raw.
            for _ in 0..run {
                out.push(b);
            }
        } else {
            // 4 copies + 1 byte holding (run - 4).
            out.push(b);
            out.push(b);
            out.push(b);
            out.push(b);
            out.push((run - 4) as u8);
        }
        i += run;
    }
    out
}

/// Invert bzip2's RLE-1 pre-pass. Streaming-friendly: consumes the full
/// `input` and returns the reconstituted raw bytes.
pub(crate) fn rle1_inverse(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        out.push(b);
        i += 1;
        if i >= input.len() || input[i] != b {
            continue;
        }
        out.push(b);
        i += 1;
        if i >= input.len() || input[i] != b {
            continue;
        }
        out.push(b);
        i += 1;
        if i >= input.len() || input[i] != b {
            continue;
        }
        // Fourth copy.
        out.push(b);
        i += 1;
        // Next byte is the extra-count.
        if i < input.len() {
            let extra = input[i] as usize;
            i += 1;
            for _ in 0..extra {
                out.push(b);
            }
        }
        // If we ran off the end before seeing the count byte, the
        // stream is malformed; let the caller's framing layer notice.
    }
    out
}

// ─── RLE-2 (post-MTF, zero-only) ─────────────────────────────────────────

/// Symbols emitted by RLE-2. Layout (encoder-side view):
/// - 0: RUNA  (contribution 1 × 2^k)
/// - 1: RUNB  (contribution 2 × 2^k)
/// - 2..: original MTF index `i ≥ 1` becomes the symbol `i + 1`
///
/// The caller adds the end-of-block marker (alphabet size - 1) after
/// the last symbol — that's outside RLE-2's purview.
///
/// Returns the symbol stream and the alphabet size used so far,
/// **without** the EOB marker counted.
pub(crate) fn rle2_forward(mtf_indices: &[u8], alphabet_size: usize) -> Vec<u16> {
    // alphabet_size = N = number of distinct bytes in the block. MTF
    // indices live in 0..N. RLE-2 maps:
    //   MTF index 0..=0 → RUNA/RUNB run
    //   MTF index 1..N → symbol (i + 1), i.e. 2..=N
    // Total symbols (excluding EOB) = N + 1; the EOB sits at index N+1,
    // so the full alphabet size on the Huffman side is N + 2.
    let _ = alphabet_size; // used only for documentation; we trust the input.

    let mut out: Vec<u16> = Vec::with_capacity(mtf_indices.len());
    let mut run: u32 = 0;
    for &i in mtf_indices {
        if i == 0 {
            run += 1;
        } else {
            // Flush any pending zero run.
            emit_run(&mut out, run);
            run = 0;
            // Non-zero MTF index `i` (1..=alphabet_size-1) becomes
            // symbol `i + 1` (2..=alphabet_size).
            out.push((i as u16) + 1);
        }
    }
    emit_run(&mut out, run);
    out
}

fn emit_run(out: &mut Vec<u16>, mut run: u32) {
    // bzip2 encodes (run + 1) in a sort of bijective base-2 using
    // {RUNA, RUNB}: bit value 1 → RUNA, bit value 2 → RUNB, low order
    // first, with the implicit final +1 lost on encode (handled by
    // the encoder writing (run + 1) and stripping the high "1" bit).
    //
    // The classical recipe (see bzip2's encoder pseudo-code):
    //   while run > 0:
    //     if run odd:
    //       emit RUNA; run = (run - 1) / 2
    //     else:
    //       emit RUNB; run = (run - 2) / 2
    if run == 0 {
        return;
    }
    loop {
        if run % 2 == 1 {
            out.push(0); // RUNA
            run = (run - 1) / 2;
        } else {
            out.push(1); // RUNB
            run = (run - 2) / 2;
        }
        if run == 0 {
            break;
        }
    }
}

/// Inverse of `rle2_forward`. Given a stream of decoded symbols
/// (RUNA=0, RUNB=1, MTF+1=2..=alphabet_size, plus EOB at
/// alphabet_size+1), return the MTF index stream that produced it.
///
/// The EOB is **not** expected to be present in `symbols` — the decoder
/// strips it before handing us the rest.
pub(crate) fn rle2_inverse(symbols: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(symbols.len());
    let mut i = 0;
    while i < symbols.len() {
        let s = symbols[i];
        if s <= 1 {
            // Decode a run of zeros. Read consecutive RUNA/RUNB symbols
            // and accumulate the value. The run length is:
            //   sum over k of contribution(symbol_k) × 2^k
            // where contribution(RUNA) = 1, contribution(RUNB) = 2.
            let mut run: u32 = 0;
            let mut weight: u32 = 1;
            while i < symbols.len() && symbols[i] <= 1 {
                let contrib = if symbols[i] == 0 { 1 } else { 2 };
                run = run.saturating_add(contrib * weight);
                weight = weight.saturating_mul(2);
                i += 1;
            }
            out.extend(core::iter::repeat_n(0u8, run as usize));
        } else {
            // s >= 2 means MTF index (s - 1) >= 1.
            out.push((s - 1) as u8);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rle1_short_runs_passthrough() {
        let v = b"abcabc";
        assert_eq!(rle1_forward(v), v);
        assert_eq!(rle1_inverse(&rle1_forward(v)), v);
    }

    #[test]
    fn rle1_run_of_four_emits_extra() {
        // Run of 4 → 4 copies + 0.
        let v = b"aaaa";
        let r = rle1_forward(v);
        assert_eq!(r, vec![b'a', b'a', b'a', b'a', 0]);
        assert_eq!(rle1_inverse(&r), v);
    }

    #[test]
    fn rle1_run_of_seven() {
        let v = b"aaaaaaa";
        let r = rle1_forward(v);
        assert_eq!(r, vec![b'a', b'a', b'a', b'a', 3]);
        assert_eq!(rle1_inverse(&r), v);
    }

    #[test]
    fn rle1_long_run_capped() {
        // 256 'a's → 4 'a's + 251 (run-4) = 255, then a run of 1 'a'.
        // Wait: in our impl we cap at 255 so the output is one 4+251
        // token (covering 255 bytes) followed by a single 'a'.
        let v = vec![b'a'; 256];
        let r = rle1_forward(&v);
        // First five bytes are 'a','a','a','a',251 (covers 255 bytes),
        // then 'a' (the leftover one).
        assert_eq!(r.len(), 6);
        assert_eq!(r[..5], [b'a', b'a', b'a', b'a', 251]);
        assert_eq!(r[5], b'a');
        assert_eq!(rle1_inverse(&r), v);
    }

    #[test]
    fn rle2_round_trip() {
        // Use a synthetic MTF stream with zeros mixed in.
        let mtf = vec![0u8, 0, 0, 1, 2, 0, 0, 0, 0, 5, 0];
        let alphabet_size = 6;
        let sym = rle2_forward(&mtf, alphabet_size);
        let inv = rle2_inverse(&sym);
        assert_eq!(inv, mtf);
    }

    #[test]
    fn rle2_empty() {
        let sym = rle2_forward(&[], 4);
        assert!(sym.is_empty());
        assert!(rle2_inverse(&sym).is_empty());
    }
}
