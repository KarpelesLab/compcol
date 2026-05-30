//! PKZIP Implode (ZIP method 6) — **decoder only**.
//!
//! Implode was introduced with PKZIP 1.01 (July 1989) and remained the
//! flagship algorithm until PKZIP 2.04g (1993) shipped Deflate. It pairs
//! an LZ77 sliding-window matcher (4 KiB or 8 KiB, selected by a flag bit)
//! with Shannon–Fano coding of the match-length and back-reference
//! high-distance alphabets; a third Shannon–Fano tree may optionally cover
//! the literal alphabet (256 symbols). The four (window-size × tree-count)
//! combinations are all supported by this decoder.
//!
//! There is no widely-used Implode encoder outside of the now-defunct
//! PKZIP 1.x line — Info-ZIP, libarchive, miniz, and friends all dropped
//! encoder support decades ago and the format is read-only in every
//! modern toolchain. This crate matches that: the [`Encoder`] in this
//! module returns [`Error::Unsupported`] from every call. Hans Wennborg's
//! `hwzip` and PKWARE's APPNOTE provide good encoder references for
//! anyone who wants to bring an encoder to this build later.
//!
//! ## Wire framing
//!
//! ZIP itself does not embed the Implode flag bits or the uncompressed
//! length inside the compressed payload — the central-directory and
//! local-file-header carry them out-of-band. To make the codec usable as
//! a standalone streaming decoder we wrap the payload in a tiny header:
//!
//! ```text
//! +----+----+----+----+----+----+
//! | F  | U0 | U1 | U2 | U3 | …  |   payload bytes follow
//! +----+----+----+----+----+----+
//! ```
//!
//! - `F` (1 byte): low bit = `large_window` (1 → 8 KiB dictionary, 0 → 4
//!   KiB), next bit = `lit_tree` (1 → literal tree present, 0 → raw
//!   8-bit literals). Bits 2..7 are reserved and must be zero; non-zero
//!   reserved bits return [`Error::BadHeader`].
//! - `U0..U3` (4 bytes, little-endian): decompressed length.
//! - Payload: the raw PKZIP Implode codestream as it appears inside a
//!   ZIP local-file entry, LSB-first.
//!
//! The framing is exactly the two pieces of metadata the algorithm
//! needs from a ZIP entry's general-purpose flags and uncompressed-size
//! field — nothing else. Callers that already have a ZIP entry's GP-flag
//! word in hand can derive `F` directly: `((gp_flags >> 1) & 1) << 1 |
//! ((gp_flags >> 2) & 1)`. Most callers, though, will simply construct
//! the header from the two booleans.
//!
//! ## Bitstream conventions
//!
//! Implode packs bits LSB-first within each byte (same as Deflate, not
//! bzip2). The Shannon–Fano canonical-code assignment is *reversed*
//! compared to RFC 1951: the longest codes get all zeros at the bottom
//! of each length and the shortest codes get the higher numeric values.
//! We follow `hwzip`'s trick — build a standard canonical decoder and
//! complement the next-up-to-16 bits before each table lookup.
//!
//! ## Match length / distance encoding
//!
//! - Each token starts with a 1-bit selector: `1` = literal, `0` = match.
//! - Literals: 8 raw LSB-first bits when no literal tree, otherwise a
//!   literal-tree code.
//! - Matches: read `bdl` raw bits (6 for 4 KiB, 7 for 8 KiB) giving the
//!   low distance bits, then a distance-tree symbol giving the high 6
//!   bits, then a length-tree symbol. If the length symbol is 63 a raw
//!   8-bit extra byte is added. Final length is `(symbol [+ extra]) +
//!   min_len` where `min_len = 3` when the literal tree is present and
//!   `2` otherwise. Final distance is `(high << bdl) | low + 1`.
//!
//! ## References
//!
//! - PKWARE APPNOTE.TXT, §"Imploding (type 6)".
//! - Mark Adler's Info-ZIP `explode.c`:
//!   <https://github.com/madler/unzip/blob/master/explode.c>.
//! - Hans Wennborg, *Shrink, Reduce, and Implode*:
//!   <https://www.hanshq.net/zip2.html>.

#![cfg_attr(docsrs, doc(cfg(feature = "zip_implode")))]

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod decoder;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for PKZIP Implode.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZipImplode;

impl Algorithm for ZipImplode {
    const NAME: &'static str = "zip-implode";
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

/// Encoder stub. PKZIP Implode is decoder-only in this crate; every
/// method returns [`Error::Unsupported`].
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
