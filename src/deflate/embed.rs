//! The `embed` build of raw deflate: the small codecs behind the same
//! names as the standard build. See [`crate::embed`].

use crate::embed::WINDOW;
use crate::embed::codec;
use crate::embed::format::Raw;

/// Tunables for the deflate encoder — accepted for compatibility with the
/// standard build, **without effect** in `embed` mode: the encoder has one
/// speed, its ratio is set by the sizes of a
/// [`BlockEncoder`], and its matches reach no farther back than its block
/// size, or 32 KiB, whichever is less.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`. Ignored.
    pub level: u8,
    /// Maximum LZ77 match distance in bytes. Ignored: matches never reach
    /// farther than the block size; pick a `BlockEncoder` whose `BLOCK` is
    /// no larger to bound them.
    pub max_distance: usize,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            level: 6,
            max_distance: WINDOW,
        }
    }
}

impl EncoderConfig {
    /// Default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the compression level. Ignored in `embed` mode.
    #[must_use]
    pub fn with_level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    /// Cap the LZ77 match distance. Ignored in `embed` mode.
    #[must_use]
    pub fn with_max_distance(mut self, max_distance: usize) -> Self {
        self.max_distance = max_distance;
        self
    }
}

/// Configuration for the deflate decoder.
///
/// Unlike the standard build there is no preset `dictionary` (nowhere to
/// put one without allocating), and the window is inline in the decoder,
/// its size fixed by its type: [`WINDOW`] bytes for a [`Decoder`], or what
/// a [`WindowedDecoder`] is given. `window_size` only tightens the
/// back-reference check, so a stream that was produced for a smaller window
/// can be proven to stay within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecoderConfig {
    /// Farthest back-reference accepted, in bytes, clamped to 1 to the
    /// decoder's window size.
    /// Anything farther is rejected with `Error::InvalidDistance`.
    pub window_size: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            window_size: WINDOW,
        }
    }
}

impl DecoderConfig {
    /// Default configuration: the decoder's whole window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the farthest back-reference accepted (clamped to 1 to the
    /// decoder's window size).
    #[must_use]
    pub fn with_window_size(mut self, window_size: usize) -> Self {
        self.window_size = window_size;
        self
    }
}

codec!(Raw, |config| config.window_size);
