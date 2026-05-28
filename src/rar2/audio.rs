//! RAR 2.x "audio block" delta-prediction decoder.
//!
//! Audio blocks in RAR 2.x split the stream into 1..=4 channels. Each channel
//! has its own Huffman tree over `0..=256` (where 256 is a control symbol
//! that triggers re-reading of the per-block trees). Symbols 0..=255 are
//! deltas applied through a small adaptive linear predictor.
//!
//! The predictor keeps five learnable weights and a sliding window of recent
//! deltas, picks one of eleven candidate prediction-error variants every
//! 32 samples, and nudges the dominant weight up or down. Channels share a
//! single `channeldelta` (the most recent delta across *any* channel) which
//! folds in cross-channel correlation.
//!
//! Re-implementation patterns from XADMaster's `RARAudioDecoder.c` (LGPL);
//! the constants and the predictor shape are dictated by the wire format.

/// Per-channel adaptive predictor state.
#[derive(Debug, Clone, Default)]
pub struct AudioState {
    weight1: i32,
    weight2: i32,
    weight3: i32,
    weight4: i32,
    weight5: i32,
    delta1: i32,
    delta2: i32,
    delta3: i32,
    delta4: i32,
    last_delta: i32,
    error: [i32; 11],
    count: u32,
    last_byte: i32,
}

impl AudioState {
    pub const fn new() -> Self {
        Self {
            weight1: 0,
            weight2: 0,
            weight3: 0,
            weight4: 0,
            weight5: 0,
            delta1: 0,
            delta2: 0,
            delta3: 0,
            delta4: 0,
            last_delta: 0,
            error: [0; 11],
            count: 0,
            last_byte: 0,
        }
    }

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Decode one audio sample for the given channel. `channel_delta` is mutated
/// in place — it tracks the most recent delta across all channels and is read
/// by the predictor as `weight5 * channel_delta`. `delta` is the raw symbol
/// the Huffman tree just produced (0..=255).
///
/// Returns the decoded byte (0..=255).
pub fn decode_sample(state: &mut AudioState, channel_delta: &mut i32, delta: u8) -> u8 {
    state.count = state.count.wrapping_add(1);

    state.delta4 = state.delta3;
    state.delta3 = state.delta2;
    state.delta2 = state.last_delta - state.delta1;
    state.delta1 = state.last_delta;

    // Eight times last_byte + weighted sum of recent deltas, divided by 8.
    // All intermediates are i32; the final result is masked to 8 bits.
    let pred = 8 * state.last_byte
        + state.weight1 * state.delta1
        + state.weight2 * state.delta2
        + state.weight3 * state.delta3
        + state.weight4 * state.delta4
        + state.weight5 * *channel_delta;
    let pred_byte = (pred >> 3) & 0xff;

    let byte_i = (pred_byte - delta as i32) & 0xff;
    let byte = byte_i as u8;

    // Sign-extend delta into i8 then shift up by 3 — the reference uses
    // ((int8_t)delta) << 3.
    let pred_error: i32 = (delta as i8 as i32) << 3;

    state.error[0] = state.error[0].wrapping_add(pred_error.abs());
    state.error[1] = state.error[1].wrapping_add((pred_error - state.delta1).abs());
    state.error[2] = state.error[2].wrapping_add((pred_error + state.delta1).abs());
    state.error[3] = state.error[3].wrapping_add((pred_error - state.delta2).abs());
    state.error[4] = state.error[4].wrapping_add((pred_error + state.delta2).abs());
    state.error[5] = state.error[5].wrapping_add((pred_error - state.delta3).abs());
    state.error[6] = state.error[6].wrapping_add((pred_error + state.delta3).abs());
    state.error[7] = state.error[7].wrapping_add((pred_error - state.delta4).abs());
    state.error[8] = state.error[8].wrapping_add((pred_error + state.delta4).abs());
    state.error[9] = state.error[9].wrapping_add((pred_error - *channel_delta).abs());
    state.error[10] = state.error[10].wrapping_add((pred_error + *channel_delta).abs());

    let new_last = (byte_i - state.last_byte) as i8 as i32;
    *channel_delta = new_last;
    state.last_delta = new_last;
    state.last_byte = byte_i;

    if (state.count & 0x1f) == 0 {
        // Find the minimum-error candidate and nudge the matching weight.
        let mut min_err = state.error[0];
        let mut min_idx = 0usize;
        for (i, &e) in state.error.iter().enumerate().skip(1) {
            if e < min_err {
                min_err = e;
                min_idx = i;
            }
        }
        state.error = [0; 11];
        match min_idx {
            1 if state.weight1 >= -16 => state.weight1 -= 1,
            2 if state.weight1 < 16 => state.weight1 += 1,
            3 if state.weight2 >= -16 => state.weight2 -= 1,
            4 if state.weight2 < 16 => state.weight2 += 1,
            5 if state.weight3 >= -16 => state.weight3 -= 1,
            6 if state.weight3 < 16 => state.weight3 += 1,
            7 if state.weight4 >= -16 => state.weight4 -= 1,
            8 if state.weight4 < 16 => state.weight4 += 1,
            9 if state.weight5 >= -16 => state.weight5 -= 1,
            10 if state.weight5 < 16 => state.weight5 += 1,
            _ => {}
        }
    }

    byte
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_delta_repeats_byte() {
        // With a fresh state (all zeros) and delta = 0, the predicted byte
        // is `(0 >> 3) & 0xff` = 0, so the output is `(0 - 0) & 0xff` = 0.
        // After we feed 0 once, last_byte = 0, last_delta = 0; feeding
        // zero again should still emit 0.
        let mut s = AudioState::new();
        let mut cd = 0i32;
        for _ in 0..10 {
            assert_eq!(decode_sample(&mut s, &mut cd, 0), 0);
        }
    }

    #[test]
    fn first_sample_is_negation_of_delta() {
        // On the first call, last_byte = 0, all weights = 0, so the predicted
        // byte is 0 and the output is `(0 - delta) & 0xff`.
        let mut s = AudioState::new();
        let mut cd = 0i32;
        // delta = 1 → output = (-1) & 0xff = 0xff
        assert_eq!(decode_sample(&mut s, &mut cd, 1), 0xff);
    }

    #[test]
    fn weights_adapt_every_32_samples() {
        // Drive the count past 32 with non-zero deltas and confirm at least
        // one weight has moved off zero.
        let mut s = AudioState::new();
        let mut cd = 0i32;
        for _ in 0..32 {
            decode_sample(&mut s, &mut cd, 0x40);
        }
        let any_moved =
            s.weight1 != 0 || s.weight2 != 0 || s.weight3 != 0 || s.weight4 != 0 || s.weight5 != 0;
        assert!(any_moved, "expected at least one weight to be adjusted");
    }
}
