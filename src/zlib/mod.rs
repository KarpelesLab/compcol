//! RFC 1950 zlib container around RFC 1951 deflate.
//!
//! Wire format:
//! ```text
//! +---+---+--- ... ---+---+---+---+---+
//! |CMF|FLG|  deflate  |   ADLER-32    |
//! +---+---+--- ... ---+---+---+---+---+
//! ```
//! - `CMF`: bits 0-3 = CM (8 = deflate), bits 4-7 = CINFO (`log2(WINDOW)-8`).
//! - `FLG`: bits 0-4 = FCHECK (chosen so `CMF*256 + FLG` is a multiple of 31),
//!   bit 5 = FDICT, bits 6-7 = FLEVEL.
//! - With FDICT set, a 4-byte big-endian DICTID (the Adler-32 of a preset
//!   dictionary) follows the header. The decoder uses the dictionary from
//!   its config, or else stops with `Error::NeedDictionary` until
//!   `Decoder::set_dictionary` supplies it (zlib's `Z_NEED_DICT`).
//! - 4-byte big-endian Adler-32 of the **uncompressed** data.
//!
//! The encoder writes CINFO from the deflate window
//! (`Encoder::with_deflate_config`) and FDICT/DICTID when given a
//! dictionary (`Encoder::with_dictionary`).
//!
//! The decoder never counts bytes after the trailer as consumed, and
//! `Decoder::decode_block` stops at deflate block boundaries like zlib's
//! `inflate(Z_BLOCK)`.
//!
//! With the `embed` feature, `Encoder`, `Decoder` and their configs are the
//! allocation-free variants instead, alongside one-shot `decompress`,
//! `decompressed_len` and `compress` functions; see `compcol::embed`
//! for what differs (no preset dictionary, no sync flush).

#[cfg(not(feature = "embed"))]
mod full;
#[cfg(not(feature = "embed"))]
pub use full::{Decoder, DecoderConfig, Encoder, EncoderConfig};

#[cfg(feature = "embed")]
mod embed;
#[cfg(feature = "embed")]
pub use embed::{
    BlockEncoder, Decoder, DecoderConfig, Encoder, EncoderConfig, WindowedDecoder, compress,
    decompress, decompressed_len,
};

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for zlib.
#[derive(Debug, Clone, Copy, Default)]
pub struct Zlib;

impl Algorithm for Zlib {
    const NAME: &'static str = "zlib";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = DecoderConfig;

    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(c: Self::DecoderConfig) -> Decoder {
        Decoder::with_config(c)
    }
}
