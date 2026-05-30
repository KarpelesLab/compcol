//! StuffIt 5 **Arsenic** (compression method 15) — **decoder only**.
//!
//! Arsenic is the Burrows–Wheeler-based codec used by StuffIt 5 archives
//! (compression-method id 15). This module decodes the **raw method-15 fork
//! payload** — the bytes a StuffIt 5 container stores for a member
//! compressed with Arsenic — not the SIT container itself. It plugs in
//! behind the streaming [`crate::traits::Algorithm`] trait like the other
//! per-method codecs in this crate.
//!
//! ## Decode pipeline
//!
//! 1. A carry-less binary range/arithmetic decoder (`NUMBITS = 26`,
//!    `ONE = 2^25`, `HALF = 2^24`, MSB-first bit feed) driving nine adaptive
//!    frequency models recovers a stream of selector/symbol tokens.
//! 2. The tokens drive a combined un-RLE / un-MTF stage (a bijective base-2
//!    zero-run scheme for runs of MTF index 0) producing one block of
//!    BWT-permuted bytes.
//! 3. An inverse Burrows–Wheeler transform un-permutes the block using a
//!    stored primary index.
//! 4. If the block is flagged randomized, selected byte positions are
//!    XOR-corrected at spacings drawn cyclically from a fixed 256-entry
//!    randomization table.
//! 5. A final "four equal bytes then count" RLE layer is expanded.
//!
//! The stream self-terminates: each block carries an end-of-blocks flag and
//! the final block is followed by a 32-bit CRC-32 trailer (poly
//! `0xEDB88320`, init `0xFFFFFFFF`, compared to the bitwise complement of
//! the running CRC over the decoded output). No out-of-band length is
//! required.
//!
//! ## Encoder
//!
//! Permanently [`Error::Unsupported`]: StuffIt 5 is a decode-only target in
//! this crate (matching LZFSE, Quantum, RAR\*, …).
//!
//! ## Tables
//!
//! The nine model parameters and the 256-entry randomization table are
//! wire-format constants required for bit-exact decoding; they are embedded
//! verbatim in [`tables`](self) from the project's maintainer-sanctioned
//! interoperability data.

#![cfg_attr(docsrs, doc(cfg(feature = "arsenic")))]

extern crate alloc;

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

pub(crate) mod decoder;
pub(crate) mod pipeline;
pub(crate) mod range;
pub(crate) mod tables;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for StuffIt 5 Arsenic.
#[derive(Debug, Clone, Copy, Default)]
pub struct Arsenic;

impl Algorithm for Arsenic {
    const NAME: &'static str = "arsenic";
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

/// Encoder stub. StuffIt 5 Arsenic encoding is out of scope for this build;
/// every method here returns [`Error::Unsupported`].
#[derive(Debug, Default)]
pub struct Encoder;

impl Encoder {
    /// Construct the (no-op) encoder stub.
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
