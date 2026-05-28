//! Quantum probability model and arithmetic decoder.
//!
//! Ported from libmspack's `qtmd.c`:
//! - `Model::new` is `qtmd_init_model`.
//! - `Model::update` is `qtmd_update_model`.
//! - [`ArithDecoder::get_symbol`] is the `GET_SYMBOL(model, var)` macro.
//!
//! The model is a small per-alphabet table of (symbol, cumulative-frequency)
//! pairs. The arithmetic coder works on 16-bit `H`/`L`/`C` registers (named
//! after libmspack's locals) with a fixed total cumfreq budget of about 3800
//! before a normalisation pass kicks in.

use crate::error::Error;
use crate::quantum::bits::BitReader;

/// One (symbol, cumulative-frequency) entry in a [`Model`]. The model also
/// carries a sentinel entry at the end (with `cumfreq == 0`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ModelSym {
    pub sym: u16,
    pub cumfreq: u16,
}

/// Quantum probability model. `syms` has length `entries + 1` — the trailing
/// entry is a sentinel with `cumfreq == 0` and `sym` set to the "one past the
/// last" symbol value. The model owns its symbol array; sizes are small
/// (≤ 43 entries) so we use fixed-size storage.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    pub shiftsleft: i32,
    pub entries: usize,
    /// Pre-allocated symbol array. The largest model in Quantum has
    /// `entries == 64`, so 65 is a safe upper bound for the full table.
    pub syms: [ModelSym; 65],
}

impl Model {
    /// Build a model with symbols `start .. start + len` and initial
    /// cumulative frequencies `len, len-1, …, 1, 0` (the trailing 0 is the
    /// sentinel).
    pub(crate) fn new(start: u16, len: usize) -> Self {
        assert!(len <= 64, "Quantum model size out of range");
        let mut syms = [ModelSym::default(); 65];
        for (i, slot) in syms.iter_mut().take(len + 1).enumerate() {
            slot.sym = start + i as u16;
            slot.cumfreq = (len - i) as u16;
        }
        Self {
            shiftsleft: 4,
            entries: len,
            syms,
        }
    }

    /// Apply the model update step. Called after the cumulative frequency
    /// budget exceeds 3800. Mirrors `qtmd_update_model`.
    fn update(&mut self) {
        self.shiftsleft -= 1;
        if self.shiftsleft != 0 {
            // Normal pass: halve every cumfreq, keeping the table strictly
            // monotone (each entry must remain ≥ next entry + 1).
            for i in (0..self.entries).rev() {
                self.syms[i].cumfreq >>= 1;
                if self.syms[i].cumfreq <= self.syms[i + 1].cumfreq {
                    self.syms[i].cumfreq = self.syms[i + 1].cumfreq + 1;
                }
            }
        } else {
            // Major pass (every 50 minor steps): rebuild the table.
            self.shiftsleft = 50;

            // Cumfreqs → frequencies, increment by 1, then halve.
            for i in 0..self.entries {
                // Include the sentinel in this loop (i.e. no -1 from entries).
                self.syms[i].cumfreq -= self.syms[i + 1].cumfreq;
                self.syms[i].cumfreq += 1;
                self.syms[i].cumfreq >>= 1;
            }

            // Selection sort by frequency, descending. libmspack notes this
            // MUST be a (stable-or-equal-instability) selection sort because
            // adaptive-coder correctness depends on the exact tie ordering.
            for i in 0..self.entries.saturating_sub(1) {
                for j in (i + 1)..self.entries {
                    if self.syms[i].cumfreq < self.syms[j].cumfreq {
                        self.syms.swap(i, j);
                    }
                }
            }

            // Frequencies → cumfreqs.
            for i in (0..self.entries).rev() {
                self.syms[i].cumfreq += self.syms[i + 1].cumfreq;
            }
        }
    }
}

/// Arithmetic decoder state: the H/L/C 16-bit registers.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ArithDecoder {
    pub h: u16,
    pub l: u16,
    pub c: u16,
}

impl ArithDecoder {
    pub(crate) const fn new() -> Self {
        Self { h: 0, l: 0, c: 0 }
    }

    /// Initialise the decoder at the start of a new frame:
    /// `H = 0xFFFF; L = 0; C = read 16 bits from the stream`.
    pub(crate) fn init_frame(&mut self, br: &mut BitReader, buf: &[u8]) -> Result<(), Error> {
        self.h = 0xFFFF;
        self.l = 0;
        self.c = br.read_bits(16, buf)? as u16;
        Ok(())
    }

    /// Pull one symbol from `model`, performing the renormalisation /
    /// underflow-handling dance. Mirrors libmspack's `GET_SYMBOL` macro.
    pub(crate) fn get_symbol(
        &mut self,
        model: &mut Model,
        br: &mut BitReader,
        buf: &[u8],
    ) -> Result<u16, Error> {
        let h = self.h as u32;
        let l = self.l as u32;
        let c = self.c as u32;

        // range = ((H - L) & 0xFFFF) + 1
        let range = ((h.wrapping_sub(l)) & 0xFFFF) + 1;
        // symf = (((C - L + 1) * model.syms[0].cumfreq) - 1) / range, & 0xFFFF
        let cumfreq0 = model.syms[0].cumfreq as u32;
        if cumfreq0 == 0 {
            // Defensive: would imply an exhausted model. Treat as corrupt.
            return Err(Error::Corrupt);
        }
        let symf = ((c.wrapping_sub(l).wrapping_add(1).wrapping_mul(cumfreq0)).wrapping_sub(1)
            / range)
            & 0xFFFF;

        // Linear scan: find the bracket [syms[i-1].cumfreq, syms[i].cumfreq)
        // containing symf. `syms[0].cumfreq` is the total, so we always start
        // from i=1 and stop when syms[i].cumfreq <= symf.
        let mut i: usize = 1;
        while i < model.entries {
            if (model.syms[i].cumfreq as u32) <= symf {
                break;
            }
            i += 1;
        }
        let sym = model.syms[i - 1].sym;

        // Update H, L for the chosen sub-interval.
        let range2 = h.wrapping_sub(l) + 1;
        let total = model.syms[0].cumfreq as u32;
        let cf_lo = model.syms[i - 1].cumfreq as u32;
        let cf_hi = model.syms[i].cumfreq as u32;
        // H = L + (cf_lo * range / total) - 1
        // L = L + (cf_hi * range / total)
        let new_h = (l + (cf_lo.wrapping_mul(range2) / total)).wrapping_sub(1) & 0xFFFF;
        let new_l = (l + (cf_hi.wrapping_mul(range2) / total)) & 0xFFFF;
        let mut h = new_h;
        let mut l = new_l;

        // Update model: add 8 to cumfreq of chosen symbol and all preceding
        // (i.e. indices i-1, i-2, …, 0).
        let mut k = i;
        loop {
            k -= 1;
            model.syms[k].cumfreq = model.syms[k].cumfreq.wrapping_add(8);
            if k == 0 {
                break;
            }
        }
        if model.syms[0].cumfreq > 3800 {
            model.update();
        }

        // Renormalisation loop. We use u32 arithmetic but mask to 16 bits
        // at each step — this mirrors the C uint16 wrap semantics.
        let mut c = c & 0xFFFF;
        loop {
            // Compare top bits of L and H.
            if (l & 0x8000) != (h & 0x8000) {
                if (l & 0x4000) != 0 && (h & 0x4000) == 0 {
                    // Underflow case: C ^= 0x4000; L &= 0x3FFF; H |= 0x4000.
                    c ^= 0x4000;
                    l &= 0x3FFF;
                    h |= 0x4000;
                } else {
                    break;
                }
            }
            // L <<= 1 (16-bit); H = (H << 1) | 1 (16-bit).
            l = (l << 1) & 0xFFFF;
            h = ((h << 1) | 1) & 0xFFFF;
            // Pull one more bit into C.
            br.ensure_bits(1, buf)?;
            let bit = br.peek_bits(1);
            br.remove_bits(1);
            c = ((c << 1) | bit) & 0xFFFF;
        }

        self.h = h as u16;
        self.l = l as u16;
        self.c = c as u16;
        Ok(sym)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_initial_cumfreq_table() {
        let m = Model::new(0, 4);
        // syms: (0, 4), (1, 3), (2, 2), (3, 1), sentinel (4, 0).
        assert_eq!(m.syms[0].sym, 0);
        assert_eq!(m.syms[0].cumfreq, 4);
        assert_eq!(m.syms[1].sym, 1);
        assert_eq!(m.syms[1].cumfreq, 3);
        assert_eq!(m.syms[4].sym, 4);
        assert_eq!(m.syms[4].cumfreq, 0);
        assert_eq!(m.entries, 4);
        assert_eq!(m.shiftsleft, 4);
    }

    #[test]
    fn model_update_minor_pass_keeps_monotone() {
        let mut m = Model::new(10, 5);
        // Force cumfreqs into a state where halving would otherwise collide.
        m.syms[0].cumfreq = 100;
        m.syms[1].cumfreq = 80;
        m.syms[2].cumfreq = 60;
        m.syms[3].cumfreq = 40;
        m.syms[4].cumfreq = 20;
        m.syms[5].cumfreq = 0;
        m.shiftsleft = 4;
        m.update();
        // Must remain strictly decreasing.
        for i in 0..m.entries {
            assert!(
                m.syms[i].cumfreq > m.syms[i + 1].cumfreq,
                "non-monotone at {i}: {} {}",
                m.syms[i].cumfreq,
                m.syms[i + 1].cumfreq
            );
        }
    }

    #[test]
    fn model_update_major_pass_sorts_descending() {
        let mut m = Model::new(0, 4);
        // Drive shiftsleft to 1 so the next update is the major pass.
        m.shiftsleft = 1;
        // Build cumfreqs corresponding to per-symbol frequencies 1, 5, 2, 3.
        // cumfreq[i] = sum_{j>=i} freq[j]. So cumfreqs = 11, 10, 5, 3, 0.
        m.syms[0].cumfreq = 11;
        m.syms[1].cumfreq = 10;
        m.syms[2].cumfreq = 5;
        m.syms[3].cumfreq = 3;
        m.syms[4].cumfreq = 0;
        // Symbols 0,1,2,3 with frequencies 1,5,2,3.
        m.update();
        // After major pass shifts each frequency by >>=1 after a +1 increment:
        // (1+1)/2 = 1, (5+1)/2 = 3, (2+1)/2 = 1, (3+1)/2 = 2.
        // Sorted descending: freqs [3,2,1,1] correspond to symbols [1, 3, 0, 2]
        // (with the original [0,2] tie broken in selection-sort order).
        assert_eq!(m.syms[0].sym, 1);
        assert_eq!(m.syms[1].sym, 3);
        // Sentinel is still 0.
        assert_eq!(m.syms[4].cumfreq, 0);
        // shiftsleft reset.
        assert_eq!(m.shiftsleft, 50);
    }
}
