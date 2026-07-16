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
//! - **Decoder**: the **full PPMII variant H model** (`ppmd7`) — the
//!   information-inheritance context tree (`CreateSuccessors` /
//!   `UpdateModel`), the binary-context fast path, the masked-escape
//!   suffix walk, SEE (secondary escape estimation), tree-wide `Rescale`,
//!   and the sub-allocator with block coalescing — driven by a carry-less
//!   range decoder in both its 7z and RAR flavours (`range_dec`). The
//!   standalone framing below uses the 7z flavour; the RAR3/4 decoder
//!   feeds the same model core through the RAR flavour. Decodes streams
//!   produced by real PPMd encoders (7-Zip, `pyppmd`, WinRAR/`rar`).
//! - **Encoder**: permanently returns [`Error::Unsupported`]. The PPM
//!   model maintenance plus carry-less range encoder are out of scope; we
//!   follow the `lzfse`/`rar*` precedent and ship the encoder as a stub.
//!
//! ### Wire framing
//!
//! There is no canonical standalone PPMd file format — PPMd is always
//! wrapped by 7z/RAR/ZIP. To make the decoder usable as a standalone
//! codec we apply a minimal header analogous to the legacy `.lzma`
//! "alone" framing:
//!
//! ```text
//! byte 0      : order              (2..=64, inclusive)
//! byte 1      : mem_size_mb        (1..=255, inclusive)
//! byte 2      : restoration_method (0=restart, 1=cut-off, 2=freeze)
//! bytes 3..=10: little-endian u64 uncompressed length
//!               (0xFFFF_FFFF_FFFF_FFFF means "unknown — decode to
//!                stream end")
//! bytes 11..  : the PPMd-coded payload (a raw 7z Ppmd7 stream, i.e.
//!               a leading 0x00 byte then the range-coded body)
//! ```
//!
//! The order and memory size must match what the encoder used (they are
//! not otherwise recoverable from the stream). The restoration-method
//! byte is retained for archive-wrapper parity; the model restarts on
//! memory pressure regardless.
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

mod decoder;
mod ppmd7;
mod range_dec;

pub use decoder::Decoder;

// Re-exported for the RAR3/4 PPMd path; unused when `ppmd` is built alone.
#[cfg(feature = "rar3")]
pub(crate) use ppmd7::Ppmd7;
#[cfg(feature = "rar3")]
pub(crate) use range_dec::{Mode as RangeMode, RangeDec};

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
