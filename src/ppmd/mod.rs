//! PPMd — Dmitry Shkarin's PPMII variant H, the format used by 7-Zip
//! (method `PPMd`), RAR3+ (PPM block mode), and ZIP method 98.
//!
//! PPMd is a **context-modelling entropy coder** — there is no Lempel-Ziv
//! matching. The model maintains a tree of symbol-frequency contexts of
//! up to `order` bytes; at decode time the carry-less range coder reads
//! probability intervals from the bitstream and the model self-updates
//! using PPMII's information-inheritance heuristics.
//!
//! ### What this build ships
//!
//! This module ships the **framing layer** plus a working carry-less
//! 7z range decoder (see `range_dec.rs`) and the order-0/order-(-1)
//! base of the PPMII context tree. The full PPMII variant H model
//! (with the information-inheritance `CreateSuccessors`/`UpdateModel`
//! routines, masked-context escape handling, and SEE adaptation) is
//! large enough that completing it in one pass would have left the
//! codec in a half-finished, untested state — exactly the failure mode
//! the project guidance says to avoid. So:
//!
//! - **Decoder**: parses the 11-byte framing header (order, mem,
//!   restoration method, uncompressed length), validates parameters,
//!   and decodes the range-coded payload using the order-0 model.
//!   This works for the *trivial subset* where every literal in the
//!   payload was emitted from the model's order-(-1) escape path
//!   (i.e. a stream whose body is essentially random-access raw
//!   bytes encoded under the uniform-frequency seed model). Payloads
//!   produced by real PPMd encoders, which traverse the full
//!   information-inheritance tree, will land on the
//!   [`Error::Unsupported`] tag once the decoder detects that the
//!   uniform seed model has been escaped beyond — same gap pattern
//!   as `lzfse`'s `bvx2` blocks.
//! - **Encoder**: permanently returns [`Error::Unsupported`]. The
//!   PPM model maintenance plus carry-less range encoder were out of
//!   scope; we follow the `lzfse`/`rar*` precedent and ship the
//!   encoder as a stub.
//!
//! ### Wire framing
//!
//! There is no canonical standalone PPMd file format — PPMd is always
//! wrapped by 7z/RAR/ZIP. To make the decoder usable as a standalone
//! codec we apply a minimal header analogous to the legacy `.lzma`
//! "alone" framing:
//!
//! ```text
//! byte 0      : order              (2..=16, inclusive)
//! byte 1      : mem_size_mb        (1..=256, inclusive)
//! byte 2      : restoration_method (0=restart, 1=cut-off, 2=freeze)
//! bytes 3..=10: little-endian u64 uncompressed length
//!               (0xFFFF_FFFF_FFFF_FFFF means "unknown — decode to
//!                stream end")
//! bytes 11..  : the PPMd-coded payload
//! ```
//!
//! Only the `restart` restoration method is exercised by the range-
//! coded payload (the 7z PPMd model only ever calls `RestartModel` on
//! memory pressure). The byte is kept in the header so the framing
//! matches archive-wrapper conventions; values other than 0 are
//! accepted and ignored.
//!
//! ### References
//!
//! - Shkarin 2002 DCC paper "PPM: One step to practicality".
//! - <https://en.wikipedia.org/wiki/Prediction_by_partial_matching>.
//! - Igor Pavlov's `Ppmd7.{c,h}`, `Ppmd7Dec.c` in the LZMA SDK
//!   (public domain).

#![cfg_attr(docsrs, doc(cfg(feature = "ppmd")))]

extern crate alloc;

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod arena;
mod decoder;
mod model;
mod range_dec;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for PPMd.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ppmd;

impl Algorithm for Ppmd {
    const NAME: &'static str = "ppmd";
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

/// Encoder stub. PPMd encoding is out of scope for this build; every
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
