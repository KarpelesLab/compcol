//! Zstandard (RFC 8478) — partial implementation.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8478>.
//!
//! # What works
//!
//! - **Decoder**: streams Zstd frames whose data blocks are all `Raw_Block`
//!   (Block_Type=0) or `RLE_Block` (Block_Type=1). The frame header parser
//!   handles the full set of Frame_Header_Descriptor permutations
//!   (Single_Segment_Flag, optional Window_Descriptor, optional Dictionary_ID
//!   field of 0/1/2/4 bytes, optional Frame_Content_Size of 0/1/2/4/8 bytes
//!   with the 2-byte FCS+256 quirk).
//!
//! - **Encoder**: emits a valid Zstd frame whose body is one or more
//!   `Raw_Block`s. **No compression is actually performed** — every input byte
//!   is copied into the output verbatim, wrapped in Zstd block headers. This
//!   is the "fallback" encoder mode required by the task: it lets the decoder
//!   round-trip its own output without bringing in the FSE/Huffman/LZ77
//!   machinery that real Zstd compression demands.
//!
//! # What does NOT work
//!
//! - **`Compressed_Block` (Block_Type=2) decoding** is the bulk of the spec
//!   (FSE entropy coding, Huffman literals, LZ77 sequences). The decoder
//!   returns [`Error::Unsupported`] when it encounters such a block.
//!
//! - **Content_Checksum_Flag** in the Frame_Header. The 4-byte trailer is the
//!   low 32 bits of XXH64 over the decompressed data; we do not ship an
//!   XXH64 implementation, so any frame that advertises a content checksum is
//!   refused with [`Error::Unsupported`] (the task spec explicitly permits
//!   this).
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

mod decoder;
mod encoder;

pub use decoder::Decoder;
pub use encoder::Encoder;

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

    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}
