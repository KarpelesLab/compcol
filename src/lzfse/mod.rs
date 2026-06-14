//! LZFSE (Apple's LZ77 + Finite State Entropy) — **decoder only**.
//!
//! LZFSE was introduced in iOS 9 / macOS 10.11 as a lower-CPU alternative
//! to zlib while still beating it on compression ratio for many real-world
//! payloads. The encoder is published as BSD code by Apple at
//! <https://github.com/lzfse/lzfse>, but in the interest of keeping this
//! crate's footprint focused on decoding (matching how we ship LZX,
//! Quantum, RAR\*, etc.) the encoder here always returns
//! [`Error::Unsupported`].
//!
//! ## Stream format
//!
//! An LZFSE stream is a sequence of blocks. Each block begins with a 4-byte
//! magic:
//!
//! | Magic   | Block kind                                                    |
//! |---------|---------------------------------------------------------------|
//! | `bvx-`  | Uncompressed payload (`u32` LE length, then raw bytes).       |
//! | `bvxn`  | LZVN-compressed payload (header + LZVN-encoded bytes).        |
//! | `bvx1`  | Uncompressed LZFSE v1 header. Rare; treated as `bvx-`-like.   |
//! | `bvx2`  | LZFSE v2 compressed block — FSE + LZ77.                       |
//! | `bvx$`  | End-of-stream marker; no payload.                             |
//!
//! ## What this build supports
//!
//! - `bvx-` (uncompressed) blocks: **fully supported**.
//! - `bvxn` (LZVN) blocks: **decoder implemented**.
//! - `bvx$` end-of-stream marker: **honoured** — decoder transitions to
//!   StreamEnd.
//! - `bvx1` blocks: not commonly emitted by modern encoders; this build
//!   returns [`Error::Unsupported`].
//! - `bvx2` (LZFSE v2 compressed) blocks: **decoder implemented** — the core
//!   LZFSE block type (LZ77 commands entropy-coded with Finite State
//!   Entropy). The FSE table construction matches Apple's general
//!   `fse_init_decoder_table` (k/k-1 split), so arbitrary per-symbol
//!   frequencies decode, not only power-of-two normalizations. Validated by
//!   round-trip against this crate's own spec-conformant general-frequency v2
//!   encoder, including deliberately non-dyadic distributions and a
//!   hand-frozen non-dyadic block (no Apple reference fixtures are available
//!   in this environment, so Apple-interop is best-effort but follows the
//!   documented wire format and real table-construction algorithm). See the
//!   internal `lzfse_v2` module for the layout reference and
//!   validation/interop notes.
//!
//! Real LZFSE files produced by Apple's encoders mix these block types
//! freely: small payloads land in `bvxn`, large ones in `bvx2`, and short
//! incompressible runs in `bvx-`.
//!
//! ## References
//!
//! - Apple's open-source reference: <https://github.com/lzfse/lzfse>
//!   (in particular `lzfse_internal.h`, `lzfse_decode_base.c`, and
//!   `lzvn_decode_base.c`).

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

pub(crate) mod bits;
pub(crate) mod decoder;
pub(crate) mod fse;
pub(crate) mod lzfse_v2;
pub(crate) mod lzvn;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for LZFSE.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzfse;

impl Algorithm for Lzfse {
    const NAME: &'static str = "lzfse";
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

/// Encoder stub. LZFSE encoding is out of scope for this build; every
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
