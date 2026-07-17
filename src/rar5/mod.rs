//! RAR 5.x (2013-present) — LZ77/Huffman + new filters — **decoder only**.
//!
//! Reference: <https://www.rarlab.com/technote.htm> (partial — the wire-level
//! algorithm details are not in the public technote; the canonical format
//! description is the libarchive RAR5 reader, BSD-licensed). This decoder
//! was implemented from the libarchive reader's algorithm description, not
//! its code; no code is copied.
//!
//! # Encoder is intentionally unsupported
//!
//! RARLAB's unRAR license explicitly forbids using its source code to
//! reconstruct the RAR compression algorithm. Even clean-room
//! implementations of RAR decoders (libarchive, The Unarchiver) ship
//! decoder-only for that reason. The encoder in this module will
//! permanently return [`Error::Unsupported`].
//!
//! # What the decoder supports
//!
//! - Single-volume RAR5 LZ77+Huffman compressed-data runs.
//! - Cross-block table reuse (`table_present` bit set or clear).
//! - The four-deep distance LRU and the "repeat last match" command.
//! - The Delta (type 0), x86 E8 (type 1) and x86 E8/E9 (type 2)
//!   post-decompression filters. ARM (type 3) and the rare types 4–7 are
//!   recognised on the wire but return [`Error::Unsupported`]. The
//!   transforms live in the crate-internal `rar_filters` module, shared
//!   with the RAR3 decoder.
//! - **Solid groups**, when the caller drives them as one continuous
//!   stream: the LZ window carries across the group's members naturally,
//!   and [`Decoder::add_file_boundary`] lets the container register each
//!   member's starting offset so the x86 filters compute file-relative
//!   addresses (unrar semantics). See the decoder docs.
//!
//! # What the decoder does *not* do
//!
//! - **No archive container parsing.** RAR5's outer container (signature,
//!   main header, file headers, multi-volume continuations, encryption,
//!   recovery records, …) is not decoded here. Callers extract the inner
//!   compressed-data run from the container themselves and feed it to
//!   the decoder's `decode()` method. For solid groups that includes
//!   concatenating the members' runs and slicing the decoded output.
//! - **No CRC32/Blake2sp verification.** Those checksums live in the file
//!   header, not the compressed stream.
//!
//! # Calling convention
//!
//! Construct via [`Decoder::with_unpack_size`] when the caller knows the
//! expected uncompressed size (from the container header). The decoder
//! stops once that many bytes have been emitted, regardless of whether
//! more compressed input is available. For exploratory use, [`Decoder::new`]
//! constructs a decoder with no unpack-size cap; the decoder then stops
//! at the block carrying the `last_block` flag.
//!
//! The window size also comes from the container (file header bits 11..=15
//! encode `128 KiB << N`). [`Decoder::with_window_size`] applies an
//! explicit window; [`Decoder::with_unpack_size_and_window`] sets both.

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod bits;
mod decoder;
mod filters;
mod huffman;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for Rar5.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar5;

impl Algorithm for Rar5 {
    const NAME: &'static str = "rar5";
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
