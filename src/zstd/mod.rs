//! Zstandard (RFC 8478) — partial implementation.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8478>.
//!
//! # What works
//!
//! - **Decoder**: streams Zstd frames whose data blocks are `Raw_Block`
//!   (Block_Type=0), `RLE_Block` (Block_Type=1), or `Compressed_Block`
//!   (Block_Type=2). The Compressed_Block path implements:
//!     - All four literals encodings: Raw, RLE, Compressed (fresh Huffman
//!       tree), and Treeless (reuse previous tree). Both 1-stream and
//!       4-stream Huffman bitstream layouts.
//!     - Huffman tree decoding for both direct (nibble-packed) and
//!       FSE-compressed weight encodings.
//!     - FSE table decoding for the literal-length / offset / match-length
//!       sequences. Predefined_Mode, RLE_Mode, FSE_Compressed_Mode, and
//!       Repeat_Mode are all supported.
//!     - LZ77 reconstruction including the "previous offsets" repeat-code
//!       quirk (offset values 1..=3 alias the three most recent offsets,
//!       with special handling when `literal_length == 0`).
//!
//!   The frame header parser handles the full set of Frame_Header_Descriptor
//!   permutations (Single_Segment_Flag, optional Window_Descriptor, optional
//!   Dictionary_ID field of 0/1/2/4 bytes, optional Frame_Content_Size of
//!   0/1/2/4/8 bytes with the 2-byte FCS+256 quirk).
//!
//! - **Encoder**: emits a valid Zstd frame. Per-block, the encoder picks
//!   between:
//!     - `RLE_Block` (Block_Type=1) when every byte in the block is identical
//!       (single payload byte; biggest win on long zero/one-byte runs).
//!     - `Compressed_Block` (Block_Type=2) otherwise, with:
//!         - **LZ77** match finding via a 4-byte hash-chain matcher.
//!         - **Repeat offsets** (offset_value ∈ 1..=3) tracked in a ring
//!           buffer carried across blocks per RFC 8478 §3.1.1.5.
//!         - **Huffman literals** (RFC §4.2) — direct nibble-packed weight
//!           encoding, 1-stream for blocks ≤ 1023 literals and 4-stream
//!           otherwise. Emits `Compressed_Literals_Block` (fresh tree) when
//!           the previous block's tree is missing or worse;
//!           `Treeless_Literals_Block` when reusing the previous tree saves
//!           tree-description bytes.
//!         - **FSE_Compressed_Mode** for sequence tables when a custom
//!           distribution measurably beats the predefined LL/OF/ML tables;
//!           Predefined_Mode otherwise. The encoder does NOT currently emit
//!           Repeat_Mode (per-table) or RLE_Mode for sequences.
//!     - `Raw_Block` (Block_Type=0) as a fallback when neither RLE nor
//!       Compressed beats the raw size.
//!
//!   What we still don't do: FSE-compressed Huffman weight tables (we cap
//!   the alphabet at 128 weights for direct nibble encoding), Repeat_Mode /
//!   RLE_Mode for sequence FSE tables, multi-frame output, content checksum,
//!   or dictionaries.
//!
//! # What does NOT work
//!
//! - **Content_Checksum_Flag** in the Frame_Header. The 4-byte trailer is the
//!   low 32 bits of XXH64 over the decompressed data; we do not ship an
//!   XXH64 implementation, so any frame that advertises a content checksum
//!   is refused with [`crate::Error::Unsupported`].
//!
//! - **Skippable_Frame** magic numbers (`0x184D2A50..=0x184D2A5F`) are
//!   detected and rejected as unsupported rather than silently skipped.
//!
//! - **Dictionary_ID != 0** frames are unsupported (no dictionary registry).
//!
//! - **Concatenated frames** are not supported — the decoder stops after the
//!   last block of the first frame.
//!
//! Both halves are pure streaming: caller owns the input/output buffers and
//! the codec preserves state across `encode`/`decode` calls.

mod bitreader;
mod decoder;
mod encoder;
mod encoder_bitwriter;
mod encoder_fse;
mod encoder_huffman;
mod encoder_seq;
mod fse;
mod huffman;
mod literals;
mod matcher;
mod sequences;

pub use decoder::Decoder;
pub use encoder::Encoder;

/// Internal helpers exposed for integration tests only. Not part of the
/// public API; subject to change without notice.
#[doc(hidden)]
pub mod _internal_test_api {
    use crate::error::Error;

    /// Decode a single Compressed_Block body (the bytes after its 3-byte
    /// block header) into the decompressed output. Returns the decoded
    /// bytes. State carried across blocks is **not** preserved — for
    /// multi-block decoding use the [`super::Decoder`] type.
    pub fn decode_compressed_block_body(body: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
        use alloc::vec::Vec;
        let mut lit_state = super::literals::LiteralsState::default();
        let mut seq_state = super::sequences::SequencesState::new();
        let lit = super::literals::decode_literals(body, &mut lit_state)?;
        let seq_data = &body[lit.consumed..];
        let seqs = super::sequences::decode_sequences(seq_data, &mut seq_state)?;
        let mut out: Vec<u8> = Vec::new();
        super::sequences::execute_sequences(&seqs, &lit.literals, &mut out)?;
        Ok(out)
    }

    /// Just the literals section.
    pub fn decode_literals_for_test(body: &[u8]) -> Result<(alloc::vec::Vec<u8>, usize), Error> {
        let mut s = super::literals::LiteralsState::default();
        let r = super::literals::decode_literals(body, &mut s)?;
        Ok((r.literals, r.consumed))
    }

    /// Just the sequences section. Returns the number of sequences decoded.
    pub fn decode_sequences_for_test(seq_data: &[u8]) -> Result<usize, Error> {
        let mut s = super::sequences::SequencesState::new();
        let seqs = super::sequences::decode_sequences(seq_data, &mut s)?;
        Ok(seqs.len())
    }

    /// Dump the default LL table for inspection.
    pub fn default_ll_entries() -> alloc::vec::Vec<(u16, u8, u16)> {
        let t = super::fse::default_ll_table();
        t.entries
            .iter()
            .map(|e| (e.symbol, e.num_bits, e.base_state))
            .collect()
    }

    /// Dump the default ML table.
    pub fn default_ml_entries() -> alloc::vec::Vec<(u16, u8, u16)> {
        let t = super::fse::default_ml_table();
        t.entries
            .iter()
            .map(|e| (e.symbol, e.num_bits, e.base_state))
            .collect()
    }

    /// Dump the default OF table.
    pub fn default_of_entries() -> alloc::vec::Vec<(u16, u8, u16)> {
        let t = super::fse::default_of_table();
        t.entries
            .iter()
            .map(|e| (e.symbol, e.num_bits, e.base_state))
            .collect()
    }

    /// Decode the FSE weights from a Huffman tree description and return them.
    /// `data` should point to the literals payload (starting at the Huffman
    /// Header_Byte). Returns `(weights, header_bytes_consumed)`.
    pub fn huff_tree_weights_for_test(data: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
        super::huffman::decode_huffman_tree_weights_for_test(data)
    }
}

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for Zstd.
///
/// See the [module-level documentation](self) for the supported subset and
/// known limitations.
#[derive(Debug, Clone, Copy, Default)]
pub struct Zstd;

impl Algorithm for Zstd {
    const NAME: &'static str = "zstd";
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
