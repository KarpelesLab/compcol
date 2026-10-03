//! The `embed` build of the zlib container: `minizlib`'s codecs behind the
//! same names as the standard build. See [`crate::embed`].
//!
//! The header written is `78 01` (deflate, 32 KiB window, "fastest"
//! compression level, no dictionary); the trailer is the Adler-32 of the
//! data, verified on decode. Streams with `FDICT` set are rejected with
//! `Error::Unsupported`.

use crate::embed::WINDOW;
use crate::embed::codec::codec;

/// Tunables for the zlib encoder — accepted for compatibility with the
/// standard build, **without effect** in `embed` mode: the encoder has one
/// speed and one ratio, and the header always advertises `FLEVEL = 0`.
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

/// Configuration for the zlib decoder. Nothing to configure in `embed`
/// mode: preset dictionaries are not supported (there is nowhere to put one
/// without allocating), so streams with `FDICT` set fail with
/// `Error::Unsupported`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecoderConfig {}

codec!(minizlib::Zlib, |_| WINDOW);
