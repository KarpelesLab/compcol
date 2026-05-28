//! RAR 2.x (1997-2002) — reverse-engineered — decoder-only.
//!
//! Reference: The Unarchiver's `XADRAR20Handle` (LGPL — patterns copied,
//! not code), at <https://github.com/MacPaw/XADMaster>.
//!
//! # Format overview
//!
//! RAR 2.x is an LZ77 codec with Huffman-coded literal/length/offset
//! alphabets and an optional per-channel delta-prediction "audio" mode.
//! Each compressed block carries its Huffman trees via a 19-symbol pretree
//! plus delta-coded length values; the window is a fixed 1 MiB and offsets
//! are LRU-tracked across symbols.
//!
//! Unlike RAR3/RAR5, the window size and bit format are constants — the
//! container hands the decoder a raw byte stream and the unpacked length;
//! everything else is inferred from the bitstream.
//!
//! # Encoder is intentionally unsupported
//!
//! RARLAB's unRAR license explicitly forbids using its source code to
//! reconstruct the RAR compression algorithm. Even clean-room
//! implementations of RAR decoders (libarchive, The Unarchiver) ship
//! decoder-only for that reason. The encoder in this module will
//! permanently return [`Error::Unsupported`].
//!
//! # Decoder calling convention
//!
//! RAR2 streams do not carry an in-band decompressed length, so callers
//! must supply it out of band:
//!
//! ```ignore
//! use compcol::rar2::Decoder;
//! use compcol::Decoder as _;
//!
//! let mut dec = Decoder::with_unpack_size(unpacked_len as u64);
//! // feed compressed bytes via `decode(...)`, then drain via `finish(...)`.
//! ```
//!
//! `decode` buffers input but never emits output; once the caller switches
//! to `finish` the decoder runs the actual decompression in one shot and
//! drains the result across however many `finish` calls the caller makes.
//!
//! # Fixture famine and verification scope
//!
//! Genuine RAR2 archives are very rare today and no public test vector
//! suite exists. Each component (bit reader, Huffman decoder, audio
//! predictor) is exercised by unit tests against hand-built inputs;
//! end-to-end integration relies on assembled fixtures that exercise the
//! literal-only and short-match paths. The audio block, long-match, and
//! long-distance branches share infrastructure with the literal path but
//! have not been verified against a known-good real-world RAR2 archive.

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod audio;
mod bitreader;
mod decoder;
mod huffman;
mod tables;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for Rar2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar2;

impl Algorithm for Rar2 {
    const NAME: &'static str = "rar2";
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

/// Permanently-unsupported encoder. See module docs for the licence reason.
#[derive(Debug, Default)]
pub struct Encoder;
impl Encoder {
    pub const fn new() -> Self {
        Self
    }
}
impl RawEncoder for Encoder {
    fn raw_encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_reset(&mut self) {}
}
