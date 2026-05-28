//! RFC 1951 deflate.
//!
//! Streaming encoder + decoder behind a shared [`crate::Algorithm`]
//! implementation. The encoder uses LZ77 (hash-chain match finder, lazy
//! matching) followed by length-limited dynamic Huffman coding via the
//! Larmore–Hirschberg package-merge algorithm. The decoder handles all
//! three block types (stored, fixed-Huffman, dynamic-Huffman) defined by
//! RFC 1951.
//!
//! Both directions are fully streaming: the caller owns the input/output
//! buffers and the codec preserves its state across `encode`/`decode` calls.
//! The decoder keeps the 32 KiB sliding window on the heap.

mod tables;

pub mod decoder;
pub mod encoder;
pub mod lz77;

pub use decoder::Decoder;
pub use encoder::{Encoder, EncoderConfig};

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for raw deflate.
#[derive(Debug, Clone, Copy, Default)]
pub struct Deflate;

impl Algorithm for Deflate {
    const NAME: &'static str = "deflate";
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
