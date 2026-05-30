//! StuffIt compression **method 13** ("LZ + Huffman") — building blocks +
//! payload `Unsupported`.
//!
//! Method 13 is the LZ-Huffman ("fast") compression mode of Aladdin /
//! Smith Micro's StuffIt engine. This module targets the **raw method
//! payload** — the bytes a StuffIt (SIT) container stores for a member
//! compressed with method 13 — *not* the SIT/SITX container itself. It
//! plugs in behind the streaming [`crate::traits::Algorithm`] trait like
//! the other per-method ZIP / RAR codecs in this crate.
//!
//! ## Why the payload decode returns [`Error::Unsupported`]
//!
//! StuffIt's compression methods are **proprietary and undocumented**.
//! There is no published specification for method 13. The only surviving
//! open-source description of the algorithm is in The Unarchiver /
//! XADMaster (`StuffItDecompressor` / the method-13 path), which is
//! licensed **LGPL** (copyright MacPaw Inc.). This crate is permissively
//! (MIT) licensed and clean-room: per the project's strict licensing
//! policy (see [`crate::rar1`]), we may study public format *descriptions*
//! but must **not** copy code or data tables from LGPL / GPL / unRAR
//! sources.
//!
//! No public *description* of method 13 exists in enough detail to
//! reconstruct the exact wire format (the precise Huffman alphabet
//! partitioning, the length/distance extra-bit schedules, the block
//! framing, and the window size are all only encoded in the LGPL source).
//! Crucially, we have:
//!
//! - **no clean-room format description** to implement from, and
//! - **no public method-13 test fixtures** and no permissively-licensed
//!   reference tool to generate them.
//!
//! That means a decoder written here could be neither derived correctly
//! nor *validated*. A round-trip through a same-crate encoder would only
//! prove the encoder and decoder agree with **each other** — it would say
//! nothing about whether either matches StuffIt's real method-13 stream.
//! Per the project's correctness bar, a "plausible but unverified" decoder
//! must not be shipped. So, exactly as [`crate::lzham`] does for its inner
//! bitstream and [`crate::rar1`] does for its static tables, this module
//! ships the **well-defined, unit-tested building blocks** a method-13
//! decoder needs and returns [`Error::Unsupported`] from the payload
//! decode path.
//!
//! ## What this module ships
//!
//! Internally the module provides the generic primitives any LZ+Huffman
//! decoder of this shape requires, each independently unit-tested:
//!
//! - `BitReader` — MSB-first streaming bit reader (the convention
//!   the StuffIt readers use), with a 32-bit accumulator fed one byte at a
//!   time so it works under arbitrary input chunking.
//! - `Huffman` — canonical, **Kraft-validated** Huffman decoder
//!   parameterised by alphabet size. Rejects over-full (Kraft-overflowing)
//!   and over-long code-length tables with [`Error::InvalidHuffmanTree`];
//!   never panics on crafted input.
//! - `Window` — bounds-checked LZSS sliding-window output buffer
//!   with literal / overlapping-match emission and a streaming drain
//!   cursor. Rejects distance 0, distance past the window, and
//!   back-references that point before the start of produced output with
//!   [`Error::InvalidDistance`].
//!
//! When (if ever) a clean-room format description or permissively-licensed
//! fixtures become available, the method-13 state machine can be built on
//! top of these primitives and wired into [`decoder::Decoder`] without
//! rebuilding the infrastructure.
//!
//! ## Calling convention (caller-supplied uncompressed length)
//!
//! Method 13 carries **no in-band uncompressed length** — like RAR2 (see
//! [`crate::rar2`]) the length lives in the surrounding SIT container's
//! member header, not in the method payload. A real decoder would
//! therefore need the length supplied out of band; this module documents
//! and accepts that convention via [`Decoder::with_unpack_size`] for
//! forward compatibility, even though the payload decode is currently
//! `Unsupported`. The default [`Decoder::new`] leaves the length
//! unspecified.
//!
//! ## Encoder
//!
//! Permanently [`Error::Unsupported`]: there is no clean-room encoder for
//! a format whose decoder we cannot even validate.
//!
//! ## References
//!
//! - StuffIt (overview / method list): <https://en.wikipedia.org/wiki/StuffIt>
//! - The Unarchiver / XADMaster (LGPL — *not* used as a code/table source,
//!   listed only to identify where the proprietary format is reversed):
//!   <https://github.com/MacPaw/XADMaster>
//! - Method 15 ("Arsenic") reverse-engineering write-up, for context on
//!   how thin public StuffIt documentation is:
//!   <http://www.russotto.net/arseniccomp.html>

#![cfg_attr(docsrs, doc(cfg(feature = "sit13")))]

extern crate alloc;

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

pub(crate) mod bits;
pub(crate) mod decoder;
pub(crate) mod huffman;
pub(crate) mod window;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for StuffIt method 13.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sit13;

impl Algorithm for Sit13 {
    const NAME: &'static str = "sit13";
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

// ─── encoder ─────────────────────────────────────────────────────────────

/// Encoder stub. StuffIt method 13 encoding is out of scope for this build
/// (the format is undocumented and the decoder is unvalidatable); every
/// method here returns [`Error::Unsupported`].
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
