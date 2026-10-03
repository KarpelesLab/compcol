//! The `embed` build of raw deflate: the small codecs behind the same
//! names as the standard build. See [`crate::embed`].

use crate::embed::WINDOW;
use crate::embed::codec;
use crate::embed::format::Raw;

/// Tunables for the deflate encoder — accepted for compatibility with the
/// standard build, **without effect** in `embed` mode: the encoder has one
/// speed and one ratio, and always keeps its matches within
/// [`BLOCK`](crate::embed::BLOCK) bytes, well under any `max_distance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`. Ignored.
    pub level: u8,
    /// Maximum LZ77 match distance in bytes. Ignored: matches never reach
    /// farther than the block size.
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
/// put one without allocating), and the window is always the full
/// [`WINDOW`] bytes, inline in the decoder: `window_size` only tightens the
/// back-reference check, so a stream that was produced for a smaller window
/// can be proven to stay within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecoderConfig {
    /// Farthest back-reference accepted, in bytes, clamped to `1..=WINDOW`.
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
    /// Default configuration: the full 32 KiB window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the farthest back-reference accepted (clamped to `1..=WINDOW`).
    #[must_use]
    pub fn with_window_size(mut self, window_size: usize) -> Self {
        self.window_size = window_size;
        self
    }
}

codec!(Raw, |config| config.window_size);
