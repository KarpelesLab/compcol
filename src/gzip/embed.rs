//! The `embed` build of the gzip container: `minizlib`'s codecs behind the
//! same names as the standard build. See [`crate::embed`].
//!
//! The header written is the minimal ten bytes (no name, no flags,
//! `XFL = 0`, `OS = 255`); the trailer's CRC-32 and `ISIZE` are verified on
//! decode. Header fields of incoming streams (`FEXTRA`, `FNAME`, `FCOMMENT`,
//! `FHCRC`) are skipped. Only the first member of a concatenated stream is
//! decoded.

use crate::embed::WINDOW;
use crate::embed::codec::codec;

/// Tunables for the gzip encoder — accepted for compatibility with the
/// standard build, **without effect** in `embed` mode: the encoder has one
/// speed and one ratio, and the header always carries `XFL = 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`. Ignored.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// The gzip decoder takes no configuration; this mirrors the standard
/// build's `()`.
type DecoderConfig = ();

codec!(minizlib::Gzip, |_| WINDOW);
