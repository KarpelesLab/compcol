//! LZO (Lempel–Ziv–Oberhumer, LZO1X-1 variant) — stub.
//!
//! Reference: <https://www.oberhumer.com/opensource/lzo/>.
//!
//! The encoder and decoder here return [`Error::Unsupported`] until a real
//! implementation lands.

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Zero-sized marker type implementing [`Algorithm`] for Lzo.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzo;

impl Algorithm for Lzo {
    const NAME: &'static str = "lzo";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder { Encoder::new() }
    fn decoder() -> Decoder { Decoder::new() }
}

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
