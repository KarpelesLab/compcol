//! Quantum (Stac, used in older Microsoft CAB files) — **decoder only**.
//!
//! Quantum was created by David Stafford at Stac Electronics and adapted by
//! Microsoft for the legacy Cabinet (`.cab`) format. The relevant patents
//! expired around 2007 but the algorithm remained obscure and is no longer
//! used by any actively-developed tool. There is **no publicly-implemented
//! Quantum encoder** that we are aware of — even libmspack, the de facto
//! reference, ships decoder-only support. This crate matches that scope:
//! the [`Encoder`] in this module returns [`Error::Unsupported`] from every
//! call.
//!
//! Reference: libmspack `qtmd.c` and `qtm.h`
//! (<https://github.com/kyz/libmspack/blob/master/libmspack/mspack/qtmd.c>).
//! See also Matthew Russotto's notes at
//! <http://www.speakeasy.org/~russotto/quantumcomp.html>.
//!
//! ## Window size
//!
//! Quantum streams do **not** carry window size in-band — it is supplied by
//! the container (a CAB folder header byte). Callers that have parsed the
//! CAB folder should construct the decoder with
//! [`Decoder::with_window_bits`]. [`Decoder::new`] picks 15 (32 KiB) as a
//! reasonable default for inputs whose window size is unknown.
//!
//! Valid `window_bits` are `10..=21` (1 KiB to 2 MiB).
//!
//! ## Wire format summary
//!
//! - Bits are read MSB-first, two bytes at a time.
//! - Each 32 KiB frame starts with a 16-bit `C` value initialising the
//!   arithmetic decoder.
//! - The decoder picks a 3-bit *selector* from `model7`:
//!   - `0..=3` → literal byte from `model0..=model3` (each covering 64 of
//!     the 256 possible bytes).
//!   - `4` → 3-byte match, offset from `model4`.
//!   - `5` → 4-byte match, offset from `model5`.
//!   - `6` → variable length (from `model6len`) + offset from `model6`.
//! - After 32 KiB of output the decoder realigns to a byte boundary and
//!   consumes 0..=4 `0x00` trailer bytes followed by a `0xFF` sentinel.
//!
//! ## Streaming model
//!
//! Standard [`Decoder`](crate::Decoder) shape: input is buffered internally
//! and may be supplied in arbitrary chunks; output goes through a sliding
//! window and is emitted into the caller's slice. The decoder snapshots
//! all nine probability models before each packet attempt so that an
//! input underrun rewinds cleanly to a packet boundary.

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod bits;
mod decoder;
mod model;
mod tables;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for Quantum.
#[derive(Debug, Clone, Copy, Default)]
pub struct Quantum;

impl Algorithm for Quantum {
    const NAME: &'static str = "quantum";
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

/// Encoder stub. Quantum has no publicly-documented or publicly-implemented
/// encoder; every method here returns [`Error::Unsupported`].
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
