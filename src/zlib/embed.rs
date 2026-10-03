//! The `embed` build of the zlib container: the small codecs behind the same
//! names as the standard build. See [`crate::embed`].
//!
//! The header written is `78 01` (deflate, 32 KiB window, "fastest"
//! compression level, no dictionary); the trailer is the Adler-32 of the
//! data, verified on decode. Streams with `FDICT` set are rejected with
//! `Error::Unsupported`.

use crate::embed::codec;
use crate::embed::format::Zlib;

/// Tunables for the zlib encoder — accepted for compatibility with the
/// standard build, **without effect** in `embed` mode: the encoder has one
/// speed, its ratio is set by the sizes of a [`BlockEncoder`], and
/// the header always advertises `FLEVEL = 0`.
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

// No window-size setting: the whole of the decoder's window is used.
codec!(Zlib, |_| usize::MAX);
