//! Move-To-Front (MTF) transform — a reversible, length-preserving filter.
//!
//! This is a *filter*, not a compressor: it makes data more compressible
//! for a downstream entropy coder (it does not shrink the data on its own —
//! output length always equals input length). MTF is the classic transform
//! that sits between the BWT and the entropy stage inside bzip2; here it is
//! exposed standalone.
//!
//! ## Transform
//!
//! A 256-entry table is initialised to the identity permutation
//! `0, 1, …, 255`. The encoder, for each input byte `b`:
//!
//! 1. finds the current index `i` of `b` in the table,
//! 2. emits `i`, then
//! 3. moves `b` to the front of the table (index 0), shifting the bytes
//!    that were ahead of it one slot back.
//!
//! ```text
//! out[k] = position of in[k] in table; then table.move_to_front(in[k])
//! ```
//!
//! The decoder is the exact inverse: for each input byte `i` it emits
//! `table[i]`, then moves that symbol to the front:
//!
//! ```text
//! out[k] = table[in[k]]; then table.move_to_front(out[k])
//! ```
//!
//! Because the encoder and decoder keep their tables in lock-step, the
//! decoder reconstructs the original byte before it needs to mutate the
//! table, so `decode ∘ encode` is the identity for *every* input.
//!
//! ## Why it helps
//!
//! Recently-seen bytes live near the front of the table, so a run of one
//! symbol encodes as a single high index followed by zeros, and locally
//! skewed data maps to a stream dominated by small values. That heavily
//! biased distribution is exactly what a Huffman / range coder exploits.
//!
//! ## State
//!
//! The only state is the 256-byte table, carried across calls. The filter
//! is therefore fully streaming: feeding one byte or a megabyte per call
//! produces identical output, since each output byte depends only on the
//! input bytes seen so far. No input buffering is required and there is no
//! header or trailer.
//!
//! References:
//! * J. L. Bentley, D. D. Sleator, R. E. Tarjan, V. K. Wei,
//!   "A Locally Adaptive Data Compression Scheme" (CACM, 1986).
//! * The MTF stage of the bzip2 pipeline. Implemented clean-room from the
//!   transform described above.

#![cfg_attr(docsrs, doc(cfg(feature = "mtf")))]

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for the MTF filter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mtf;

impl Algorithm for Mtf {
    const NAME: &'static str = "mtf";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_cfg: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(_cfg: ()) -> Decoder {
        Decoder::new()
    }
}

/// The 256-entry move-to-front table.
///
/// `table[k]` is the symbol currently at rank `k`; rank 0 is the front.
/// Starts as the identity permutation, which both directions share so they
/// stay in lock-step across the whole stream.
#[derive(Debug, Clone)]
struct Table {
    table: [u8; 256],
}

impl Table {
    const fn new() -> Self {
        // `0, 1, …, 255` — built in a const-friendly loop.
        let mut table = [0u8; 256];
        let mut i = 0usize;
        while i < 256 {
            table[i] = i as u8;
            i += 1;
        }
        Self { table }
    }

    fn reset(&mut self) {
        let mut i = 0usize;
        while i < 256 {
            self.table[i] = i as u8;
            i += 1;
        }
    }

    /// Encode one byte: return its current rank and move it to the front.
    fn encode_byte(&mut self, b: u8) -> u8 {
        // Linear scan of 256 entries — `b` is guaranteed present (the table
        // is always a permutation of all byte values), so the loop always
        // finds it.
        let mut rank = 0usize;
        while self.table[rank] != b {
            rank += 1;
        }
        self.move_to_front(rank);
        rank as u8
    }

    /// Decode one byte: return the symbol at `rank` and move it to the front.
    fn decode_byte(&mut self, rank: u8) -> u8 {
        let b = self.table[rank as usize];
        self.move_to_front(rank as usize);
        b
    }

    /// Move the entry at `rank` to the front, shifting `[0, rank)` back one.
    fn move_to_front(&mut self, rank: usize) {
        if rank == 0 {
            return;
        }
        let b = self.table[rank];
        self.table.copy_within(0..rank, 1);
        self.table[0] = b;
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming MTF-filter encoder.
#[derive(Debug, Clone)]
pub struct Encoder {
    table: Table,
}

impl Encoder {
    /// Construct an encoder with a fresh identity table.
    pub const fn new() -> Self {
        Self {
            table: Table::new(),
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let n = input.len().min(output.len());
        for i in 0..n {
            output[i] = self.table.encode_byte(input[i]);
        }
        Ok(RawProgress {
            consumed: n,
            written: n,
            done: false,
        })
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        // 1:1 transform with no trailer: once all input is consumed the
        // stream is complete and there is nothing buffered to flush.
        Ok(RawProgress {
            consumed: 0,
            written: 0,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.table.reset();
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming MTF-filter decoder (inverse of [`Encoder`]).
#[derive(Debug, Clone)]
pub struct Decoder {
    table: Table,
}

impl Decoder {
    /// Construct a decoder with a fresh identity table.
    pub const fn new() -> Self {
        Self {
            table: Table::new(),
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let n = input.len().min(output.len());
        for i in 0..n {
            output[i] = self.table.decode_byte(input[i]);
        }
        Ok(RawProgress {
            consumed: n,
            written: n,
            done: false,
        })
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        Ok(RawProgress {
            consumed: 0,
            written: 0,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.table.reset();
    }
}

// ─── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decoder as _, Encoder as _, Status};
    use alloc::vec;
    use alloc::vec::Vec;

    /// One-shot encode: assumes `output` is large enough (it always is for a
    /// length-preserving filter when sized to the input).
    fn encode_all(data: &[u8]) -> Vec<u8> {
        let mut enc = Mtf::encoder();
        let mut out = vec![0u8; data.len()];
        let (p, status) = enc.encode(data, &mut out).unwrap();
        assert_eq!(p.consumed, data.len());
        assert_eq!(p.written, data.len());
        assert_eq!(status, Status::InputEmpty);
        let (fp, fstatus) = enc.finish(&mut []).unwrap();
        assert_eq!(fp.written, 0);
        assert_eq!(fstatus, Status::StreamEnd);
        out
    }

    fn decode_all(data: &[u8]) -> Vec<u8> {
        let mut dec = Mtf::decoder();
        let mut out = vec![0u8; data.len()];
        let (p, _status) = dec.decode(data, &mut out).unwrap();
        assert_eq!(p.consumed, data.len());
        assert_eq!(p.written, data.len());
        out
    }

    fn assert_round_trip(data: &[u8]) {
        let encoded = encode_all(data);
        assert_eq!(
            encoded.len(),
            data.len(),
            "filter must be length-preserving"
        );
        let decoded = decode_all(&encoded);
        assert_eq!(decoded, data, "round-trip must be byte-identical");
    }

    #[test]
    fn round_trip_empty() {
        assert_round_trip(&[]);
    }

    #[test]
    fn round_trip_single_byte() {
        assert_round_trip(&[0x00]);
        assert_round_trip(&[0x7F]);
        assert_round_trip(&[0xFF]);
    }

    #[test]
    fn round_trip_repeated_bytes() {
        assert_round_trip(&[0x41; 1000]);
        assert_round_trip(&[0xFF; 257]);
    }

    #[test]
    fn round_trip_english_text() {
        let text = b"the quick brown fox jumps over the lazy dog. \
                     The QUICK Brown Fox Jumps Over The Lazy Dog!";
        assert_round_trip(text);
    }

    #[test]
    fn round_trip_all_byte_values() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_round_trip(&data);
        // And the reverse ordering.
        let rev: Vec<u8> = (0..=255u8).rev().collect();
        assert_round_trip(&rev);
    }

    #[test]
    fn round_trip_pseudo_random() {
        // Deterministic xorshift PRNG — no deps.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut data = Vec::with_capacity(4096);
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push((state & 0xFF) as u8);
        }
        assert_round_trip(&data);
    }

    /// Feeding the input one byte at a time (or in small chunks) must yield
    /// the same output as one shot — proves the table state persists across
    /// calls.
    #[test]
    fn streaming_matches_one_shot() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut data = Vec::with_capacity(3000);
        for _ in 0..3000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push((state & 0xFF) as u8);
        }

        let one_shot = encode_all(&data);

        // Encode in chunks of varying small sizes through a single encoder.
        for &chunk in &[1usize, 2, 3, 7, 64] {
            let mut enc = Mtf::encoder();
            let mut streamed = Vec::with_capacity(data.len());
            let mut scratch = vec![0u8; chunk];
            let mut off = 0;
            while off < data.len() {
                let end = (off + chunk).min(data.len());
                let (p, _) = enc.encode(&data[off..end], &mut scratch).unwrap();
                assert_eq!(p.consumed, end - off);
                streamed.extend_from_slice(&scratch[..p.written]);
                off += p.consumed;
            }
            assert_eq!(streamed, one_shot, "chunk size {chunk} diverged");

            // And decoding the streamed output (also chunked) recovers data.
            let mut dec = Mtf::decoder();
            let mut decoded = Vec::with_capacity(data.len());
            let mut doff = 0;
            while doff < streamed.len() {
                let end = (doff + chunk).min(streamed.len());
                let (p, _) = dec.decode(&streamed[doff..end], &mut scratch).unwrap();
                decoded.extend_from_slice(&scratch[..p.written]);
                doff += p.consumed;
            }
            assert_eq!(decoded, data, "chunked decode (chunk {chunk}) diverged");
        }
    }

    /// A long run of a single byte after a fresh table: the first occurrence
    /// emits that byte's rank, every subsequent one emits 0. This is the
    /// low/zero-byte property that makes MTF useful.
    #[test]
    fn repetitive_data_yields_low_bytes() {
        let data = [0x42u8; 500];
        let encoded = encode_all(&data);
        assert_eq!(encoded[0], 0x42, "first occurrence emits the symbol's rank");
        assert!(
            encoded[1..].iter().all(|&b| b == 0),
            "subsequent identical bytes must encode as 0"
        );

        // Mixed but locally-repetitive data should be dominated by zeros.
        let mixed: Vec<u8> = b"aaaabbbbccccddddaaaabbbb".to_vec();
        let enc_mixed = encode_all(&mixed);
        let zeros = enc_mixed.iter().filter(|&&b| b == 0).count();
        assert!(
            zeros >= mixed.len() / 2,
            "locally repetitive data should be majority zeros, got {zeros}/{}",
            mixed.len()
        );
    }

    /// Length is preserved and a spread of inputs round-trips cleanly.
    #[test]
    fn length_preserving_across_sizes() {
        for len in [0usize, 1, 2, 17, 256, 257, 1024] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let encoded = encode_all(&data);
            assert_eq!(encoded.len(), data.len());
            let decoded = decode_all(&encoded);
            assert_eq!(decoded, data);
        }
    }

    /// `reset` returns the encoder to the identity table so a second stream
    /// encodes independently of the first.
    #[test]
    fn reset_restores_initial_state() {
        let first = b"hello world";
        let second = b"different payload entirely";

        let mut enc = Mtf::encoder();
        let mut out = vec![0u8; 64];

        let (_p, _) = enc.encode(first, &mut out).unwrap();
        enc.reset();
        let (p, _) = enc.encode(second, &mut out).unwrap();
        let after_reset = out[..p.written].to_vec();

        // Encoding `second` on a fresh encoder must match the post-reset run.
        let fresh = encode_all(second);
        assert_eq!(after_reset, fresh);
    }
}
