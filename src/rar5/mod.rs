//! RAR 5.x (2013-present) — LZ77/Huffman + new filters — decoder-only stub.
//!
//! Reference: <https://www.rarlab.com/technote.htm>.
//!
//! # Encoder is intentionally unsupported
//!
//! RARLAB's unRAR license explicitly forbids using its source code to
//! reconstruct the RAR compression algorithm. Even clean-room
//! implementations of RAR decoders (libarchive, The Unarchiver) ship
//! decoder-only for that reason. The encoder in this module will
//! permanently return [`Error::Unsupported`].
//!
//! The decoder is currently a stub returning [`Error::Unsupported`];
//! the real implementation lands in a follow-up.

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Zero-sized marker type implementing [`Algorithm`] for Rar5.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar5;

impl Algorithm for Rar5 {
    const NAME: &'static str = "rar5";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder { Encoder::new() }
    fn decoder() -> Decoder { Decoder::new() }
}

/// Permanently-unsupported encoder. See module docs for the licence reason.
#[derive(Debug, Default)]
pub struct Encoder;
impl Encoder { pub const fn new() -> Self { Self } }
impl EncoderTrait for Encoder {
    fn encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn finish(&mut self, _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn reset(&mut self) {}
}

#[derive(Debug, Default)]
pub struct Decoder;
impl Decoder { pub const fn new() -> Self { Self } }
impl DecoderTrait for Decoder {
    fn decode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn finish(&mut self, _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn reset(&mut self) {}
}
