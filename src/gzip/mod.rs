//! RFC 1952 gzip container around RFC 1951 deflate.
//!
//! Wire format:
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---== ... ==---+---+---+---+---+---+---+---+---+
//! |1F |8B |CM |FLG|    MTIME      |XFL|OS |  optional |    deflate    |    CRC-32     |   ISIZE   |
//! +---+---+---+---+---+---+---+---+---+---+---== ... ==---+---+---+---+---+---+---+---+---+
//! ```
//! Fixed 10-byte header followed by optional fields gated by FLG bits:
//!   FEXTRA (bit 2)   — 2-byte XLEN + XLEN bytes
//!   FNAME  (bit 3)   — NUL-terminated filename
//!   FCOMMENT (bit 4) — NUL-terminated comment
//!   FHCRC  (bit 1)   — 2-byte header CRC16 (low 16 bits of CRC-32)
//! Then deflate, then 8-byte trailer (little-endian CRC-32 of original data +
//! ISIZE = uncompressed length mod 2^32).
//!
//! v1 limitations:
//! - Decoder ignores MTIME/XFL/OS and any optional metadata; it parses but
//!   doesn't expose the filename or comment.
//! - Encoder always emits a minimal 10-byte header (FLG = 0); the XFL byte
//!   is filled in from [`EncoderConfig::level`] per RFC 1952 §2.3.1.
//! - Concatenated gzip members are not supported — decoder stops at the
//!   first member's trailer. Multi-member streams (RFC 1952 §2.2,
//!   produced by `gzip --concatenate`, `tar zcf` on partial files,
//!   `logrotate`, etc.) are now decoded — the decoder restarts at the
//!   header phase whenever it sees another `1F 8B` magic after a
//!   trailer.
//!
//! With the `embed` feature, `Encoder` and `Decoder` are the allocation-free
//! variants instead, alongside one-shot `decompress`, `decompressed_len` and
//! `compress` functions; see `compcol::embed` for what differs (no sync
//! flush, a fixed ratio).

#[cfg(not(feature = "embed"))]
mod full;
#[cfg(not(feature = "embed"))]
pub use full::{Decoder, Encoder, EncoderConfig};

#[cfg(feature = "embed")]
mod embed;
#[cfg(feature = "embed")]
pub use embed::{
    BlockEncoder, Decoder, Encoder, EncoderConfig, WindowedDecoder, compress, decompress,
    decompressed_len,
};

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for gzip.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gzip;

impl Algorithm for Gzip {
    const NAME: &'static str = "gzip";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = ();

    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}
