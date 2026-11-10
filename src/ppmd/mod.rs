//! PPMd — Dmitry Shkarin's PPMII: variant H, the format used by 7-Zip
//! (method `PPMd`) and RAR3+ (PPM block mode), and variant I rev. 1, the
//! format of ZIP method 98.
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
//!   produced by real PPMd encoders (7-Zip, `pyppmd`, WinRAR/`rar`). One
//!   known limitation: a stream that *exhausts the suballocator* (a
//!   high-order model over a large, high-entropy payload in a small arena)
//!   can desync at the memory-restart point and return [`Error::Corrupt`]
//!   rather than decoding — it fails closed (never wrong bytes); see the
//!   `glue_free_blocks` note in `ppmd7`.
//! - **ZIP method 98 decoder**: [`ZipDecoder`] decodes PPMd variant I
//!   rev. 1 (`ppmd8`, a port of the LZMA SDK's `Ppmd8.c`) as stored in a
//!   ZIP entry: a 2-byte header with the order, memory size and restore
//!   method, then the range-coded data. It streams, and handles both the
//!   restart and cut-off restore methods, matching 7-Zip when the model
//!   runs out of memory. The ZIP header supplies the output size.
//! - **Encoder**: permanently returns [`Error::Unsupported`]. The PPM
//!   model maintenance plus carry-less range encoder are out of scope; we
//!   follow the `rar*` precedent and ship the encoder as a stub.
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
//! bytes 3..=10: little-endian u64 uncompressed length. PPMd has no
//!               in-band end-of-stream marker, so the length is
//!               mandatory: the sentinel 0xFFFF_FFFF_FFFF_FFFF
//!               ("unknown") is refused, since decoding to physical
//!               input exhaustion would append range-coder finalisation
//!               garbage past the true end.
//! bytes 11..  : the PPMd-coded payload (a raw 7z Ppmd7 stream, i.e.
//!               a leading 0x00 byte then the range-coded body)
//! ```
//!
//! The order and memory size must match what the encoder used (they are
//! not otherwise recoverable from the stream). The restoration-method
//! byte is retained for archive-wrapper parity; the model restarts on
//! memory pressure regardless.
//!
//! ### Memory
//!
//! A PPMd model lives in an arena whose size the *stream header* picks:
//! 1..=255 MiB in the standalone framing (header byte 1), 1..=256 MiB in a
//! ZIP method 98 entry (8 bits of its 2-byte header). The decoder allocates
//! and zero-fills the whole arena as soon as the header has been read,
//! whatever the size of the data behind it, so by default **two header
//! bytes are enough to make it commit 256 MiB**.
//!
//! When the input is not trusted, cap it: [`DecoderConfig::with_max_memory`]
//! for the standalone decoder (or [`Decoder::with_config`]), and
//! [`ZipDecoder::with_max_memory`] for ZIP entries. A header asking for a
//! larger arena is then rejected with [`Error::Unsupported`] before anything
//! is allocated. The default is [`MAX_MEMORY`] (256 MiB), which accepts
//! every valid header. A stream can only be decoded with the arena size it
//! was encoded for, so the cap decides which streams are accepted, not how
//! well they decode.
//!
//! The cap is on the model arena only. The standalone decoder also buffers
//! its input and its decoded output (at most 64 MiB); bound the latter with
//! [`LimitedDecoder`](crate::limit::LimitedDecoder), which this decoder
//! honours before decoding.
//!
//! ### References
//!
//! - Shkarin 2002 DCC paper "PPM: One step to practicality".
//! - <https://en.wikipedia.org/wiki/Prediction_by_partial_matching>.
//! - Igor Pavlov's `Ppmd7.{c,h}`, `Ppmd7Dec.c`, `Ppmd8.{c,h}`,
//!   `Ppmd8Dec.c` in the LZMA SDK (public domain).
//! - PKWARE APPNOTE.TXT §5.10 (ZIP method 98).

#![cfg_attr(docsrs, doc(cfg(feature = "ppmd")))]

extern crate alloc;

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod decoder;
mod ppmd7;
mod ppmd8;
mod range_dec;
mod zip;

pub use decoder::Decoder;
pub use zip::ZipDecoder;

// Re-exported for the RAR3/4 PPMd path; unused when `ppmd` is built alone.
#[cfg(feature = "rar3")]
pub(crate) use ppmd7::Ppmd7;
#[cfg(feature = "rar3")]
pub(crate) use range_dec::{Mode as RangeMode, RangeDec, RangeDecState};

/// Largest model arena a PPMd header can ask for, in bytes (256 MiB, the
/// top of the ZIP method 98 range), and the default
/// [`DecoderConfig::max_memory`].
pub const MAX_MEMORY: usize = 256 * 1024 * 1024;

/// Decoder options for the standalone PPMd framing.
///
/// `#[non_exhaustive]`: construct via [`DecoderConfig::default`] and the
/// `with_*` builders rather than a struct literal, so new options can be
/// added in future without breaking downstream code.
///
/// ```
/// use compcol::Algorithm;
/// use compcol::ppmd::{DecoderConfig, Ppmd};
///
/// // Refuse streams whose header asks for a model over 16 MiB.
/// let config = DecoderConfig::default().with_max_memory(16 << 20);
/// let _decoder = Ppmd::decoder_with(config);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecoderConfig {
    /// Largest model arena, in bytes, a stream header may ask for. A
    /// header asking for more is rejected with [`Error::Unsupported`]
    /// before the arena is allocated. Default [`MAX_MEMORY`] (256 MiB),
    /// which accepts every valid header; see the
    /// [module docs](self#memory).
    pub max_memory: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            max_memory: MAX_MEMORY,
        }
    }
}

impl DecoderConfig {
    /// Set [`max_memory`](Self::max_memory), the largest model arena in
    /// bytes a stream header may ask for.
    pub fn with_max_memory(mut self, max_memory: usize) -> Self {
        self.max_memory = max_memory;
        self
    }
}

/// Zero-sized marker type implementing [`Algorithm`] for PPMd.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ppmd;

impl Algorithm for Ppmd {
    const NAME: &'static str = "ppmd";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = DecoderConfig;
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(config: DecoderConfig) -> Decoder {
        Decoder::with_config(config)
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
