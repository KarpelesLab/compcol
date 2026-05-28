//! RAR 3.x (2002-2013) — LZ77 + Huffman path — **decoder only**.
//!
//! ## Encoder is permanently unsupported
//!
//! RARLAB's unRAR license explicitly forbids using its source code to
//! reconstruct the RAR compression algorithm. Even clean-room
//! implementations of RAR decoders (libarchive, The Unarchiver, unarr)
//! ship decoder-only for that reason. The encoder in this module returns
//! [`Error::Unsupported`] from every method, permanently.
//!
//! ## What the decoder does
//!
//! RAR3 streams use one of two compression methods at the block level:
//!
//! 1. **LZ77 + Huffman** — five canonical Huffman codes drive a sliding-window
//!    LZ77 with a 4-deep repeat-offset buffer. This is the vast majority of
//!    real-world RAR3 archives.
//! 2. **PPMd-II** — an Order-N context-mixed arithmetic coder. Used by some
//!    text-heavy archives and `-m5` (best compression) runs.
//!
//! This build implements the **LZ77 + Huffman path** in full. PPMd-II blocks
//! are refused with `Error::Unsupported` — see the private `decoder` submodule for details and
//! limitations. The standalone E8/E9 (x86 near-call) post-pass filter can
//! be enabled via [`Decoder::with_e8_filter`]; the in-band RarVM filter
//! mechanism (main symbols 257..=261) is refused.
//!
//! ## Calling convention
//!
//! We deliberately do **not** parse the surrounding RAR archive container —
//! that's a separate (much larger) project. The decoder takes the raw
//! compressed-data block (the bytes that immediately follow the RAR file
//! header in a `.rar` file) plus the declared unpacked size:
//!
//! ```ignore
//! use compcol::rar3::Decoder;
//! use compcol::Decoder as _;
//!
//! let mut dec = Decoder::with_unpack_size(file_header.unpacked_size);
//! // feed bytes
//! let _ = dec.decode(&compressed_block, &mut [])?;
//! // collect output
//! let mut out = vec![0u8; file_header.unpacked_size as usize];
//! let mut total = 0;
//! loop {
//!     let p = dec.finish(&mut out[total..])?;
//!     total += p.written;
//!     if p.done { break }
//! }
//! ```
//!
//! ## References
//!
//! - libarchive `archive_read_support_format_rar.c` (BSD): structure and
//!   tables cross-checked, no code copied.
//! - The Unarchiver `XADRARHandle.m` (LGPL): algorithmic structure only,
//!   no code copied.
//! - unarr's `uncompress-rar.c` (LGPL): the cleanest non-RARLAB reference
//!   for the LZ77 + Huffman path.

use crate::error::Error;
use crate::traits::{Algorithm, Encoder as EncoderTrait, Progress};

mod bits;
mod decoder;
mod filters;
mod huffman;
mod tables;

pub use decoder::Decoder;
pub use filters::apply_e8_filter;

/// Zero-sized marker type implementing [`Algorithm`] for Rar3.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar3;

impl Algorithm for Rar3 {
    const NAME: &'static str = "rar3";
    type Encoder = Encoder;
    type Decoder = Decoder;
    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

/// Permanently-unsupported encoder. See module docs for the licence reason.
#[derive(Debug, Default)]
pub struct Encoder;
impl Encoder {
    pub const fn new() -> Self {
        Self
    }
}
impl EncoderTrait for Encoder {
    fn encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn finish(&mut self, _output: &mut [u8]) -> Result<Progress, Error> {
        Err(Error::Unsupported)
    }
    fn reset(&mut self) {}
}
