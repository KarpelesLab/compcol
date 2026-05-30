//! PKWARE deflate64 (zip method 9).
//!
//! Streaming encoder + decoder behind a shared [`crate::Algorithm`] impl.
//! Bit-stream framing, block-type discrimination, code-length-code
//! prelude, and canonical Huffman are identical to RFC 1951 deflate; the
//! deltas are entirely in the symbol tables (`tables.rs`):
//!
//!   * 64 KiB sliding window (vs 32 KiB).
//!   * length code 285 = base 3 + 16 extra bits → matches up to 65538.
//!   * distance symbols 30, 31 are real (each carry 14 extra bits) and
//!     address distances 32769..=65536.
//!
//! Both directions are fully streaming and the decoder keeps the 64 KiB
//! sliding window on the heap.

#![cfg_attr(docsrs, doc(cfg(feature = "deflate64")))]

mod tables;

pub mod decoder;
pub mod encoder;
pub mod lz77;

pub use decoder::{Decoder, DecoderConfig};
pub use encoder::{Encoder, EncoderConfig};

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for deflate64.
#[derive(Debug, Clone, Copy, Default)]
pub struct Deflate64;

impl Algorithm for Deflate64 {
    const NAME: &'static str = "deflate64";
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
