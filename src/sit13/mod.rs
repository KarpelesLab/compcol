//! StuffIt classic compression **method 13** ("LZ+Huffman").
//!
//! Method 13 is a sliding-window LZ77/LZSS scheme (64 KiB window) in which the
//! literal/length symbols and the offset bit-lengths are entropy-coded with
//! canonical Huffman codes. This module decodes the **raw method-13 payload** —
//! the bytes a classic StuffIt (`SIT!`) container stores for a member fork
//! compressed with method 13 — *not* the SIT container itself. It plugs into
//! the streaming [`crate::traits::Algorithm`] trait like the other per-method
//! codecs in this crate.
//!
//! ## Wire format (summary)
//!
//! The bitstream is read **least-significant-bit first** throughout (the
//! opposite order from method 5, "LZAH"). A leading control byte selects how
//! the three Huffman codes are obtained:
//!
//! - high nibble `0` — **dynamic**: the code-length lists for literal/length
//!   code A, code B, and the offset bit-length code are transmitted in the
//!   stream and decoded with a fixed 37-symbol meta-code via a run-length-of-
//!   lengths scheme. A control-byte flag may alias code B to code A; the low
//!   bits give the offset alphabet size.
//! - high nibble `1..=5` — **predefined**: one of five fixed code-length sets.
//! - high nibble `>= 6` — illegal.
//!
//! Tokens follow: a literal/length symbol is decoded from code A (after a
//! literal, or at the start) or code B (after a match). Symbols `0x000..=0x0FF`
//! are literals; `0x100..=0x13F` are matches (with extended-length escapes at
//! `0x13E`/`0x13F`); `0x140` is the explicit end-of-stream. Each match decodes
//! an offset from the offset bit-length code. See [`Decoder`] for the details
//! and the DoS-hardening notes.
//!
//! ## Embedded tables
//!
//! The fixed meta-code and the five predefined code-length sets are embedded
//! as constants in `tables`; they are the project's maintainer-sanctioned
//! interoperability data (per the project's licensing posture — see the
//! security/legal notes in the repository history). The decoding *mechanics*
//! follow the clean-room functional specification.
//!
//! ## Calling convention (caller-supplied uncompressed length)
//!
//! Method 13 carries no in-band uncompressed length — like [`crate::lha`] the
//! length lives in the surrounding container's member header. The method-13
//! stream *does* carry an explicit end-of-stream symbol (`0x140`), so it can
//! self-terminate; supplying the length via [`DecoderConfig::with_len`] also
//! stops decoding at exactly `n` bytes and bounds output. See
//! [`DecoderConfig`].
//!
//! ## Encoder
//!
//! [`Error::Unsupported`]: no StuffIt encoder exists, so there is nothing to
//! clean-room.

#![cfg_attr(docsrs, doc(cfg(feature = "sit13")))]

extern crate alloc;

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

pub(crate) mod bits;
pub(crate) mod decoder;
pub(crate) mod huffman;
pub(crate) mod tables;
pub(crate) mod window;

pub use decoder::Decoder;

/// Optional out-of-band uncompressed length for the decoder.
///
/// The decoder consumes the **raw** method-13 fork payload (exactly the bytes
/// stored in the `SIT!` container — no invented framing):
///
/// - **Default (`expected_len: None`)** — decode until the in-band end-of-
///   stream symbol `0x140`.
/// - **`with_len(n)`** — when the uncompressed size is known out of band (the
///   common container-reader case), the decoder stops at exactly `n` bytes,
///   bounds output, and treats a length mismatch as a corrupt stream.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecoderConfig {
    /// Uncompressed size from the container header, if known out of band.
    pub expected_len: Option<usize>,
}

impl DecoderConfig {
    /// Config for decoding a raw method-13 fork whose uncompressed size is
    /// known out of band (the common container-reader case).
    pub fn with_len(expected_len: usize) -> Self {
        Self {
            expected_len: Some(expected_len),
        }
    }
}

/// Zero-sized marker type implementing [`Algorithm`] for StuffIt method 13.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sit13;

impl Algorithm for Sit13 {
    const NAME: &'static str = "sit13";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = DecoderConfig;
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(config: DecoderConfig) -> Decoder {
        match config.expected_len {
            Some(n) => Decoder::with_len(n),
            None => Decoder::new(),
        }
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Encoder stub. There is no StuffIt encoder to clean-room, so every method
/// here returns [`Error::Unsupported`].
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
