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
//!   bit 5 = FDICT (must be 0 here), bits 6-7 = FLEVEL.
//! - 4-byte big-endian Adler-32 of the **uncompressed** data.
//!
//! With the `embed` feature, `Encoder`, `Decoder` and their configs are the
//! allocation-free variants over `minizlib` instead; see `compcol::embed`
//! for what differs (no preset dictionary, no sync flush).

#[cfg(not(feature = "embed"))]
mod full;
#[cfg(not(feature = "embed"))]
pub use full::{Decoder, DecoderConfig, Encoder, EncoderConfig};

#[cfg(feature = "embed")]
mod embed;
#[cfg(feature = "embed")]
pub use embed::{Decoder, DecoderConfig, Encoder, EncoderConfig};

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
