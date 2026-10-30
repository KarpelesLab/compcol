//! LZFSE (Apple's LZ77 + Finite State Entropy) — encoder and decoder.
//!
//! LZFSE was introduced in iOS 9 / macOS 10.11 as a lower-CPU alternative
//! to zlib while still beating it on compression ratio for many real-world
//! payloads. It is what `COMPRESSION_LZFSE` means in Apple's
//! `libcompression`, and the chunk codec of `ULFO` disk images.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use compcol::lzfse::Lzfse;
//! use compcol::vec::{compress_to_vec, decompress_to_vec};
//!
//! let data = b"an example, an example, an example".repeat(200);
//! let packed = compress_to_vec::<Lzfse>(&data).unwrap();
//! assert!(packed.len() < data.len());
//! assert_eq!(decompress_to_vec::<Lzfse>(&packed).unwrap(), data);
//! # }
//! ```
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
//! ## Encoder
//!
//! [`Encoder`] writes the stream shape of Apple's reference
//! `lzfse_encode`: an input under 4 KiB becomes one `bvxn` block (or `bvx-`
//! when LZVN doesn't shrink it); longer input is parsed (hash-chain match
//! finder, lazy matching, repeat distances, matches reaching up to 256 KiB
//! back across blocks) into `bvx2` blocks, each stored as `bvx-` instead if
//! FSE would grow it; `bvx$` ends the stream. The output decodes with
//! Apple's `libcompression` (`COMPRESSION_LZFSE`) and the reference `lzfse`
//! tool. [`Encoder::flush`](crate::Encoder::flush) closes the current block
//! so everything so far is decodable ([`Flush::Full`](crate::Flush::Full)
//! also stops later matches reaching back past it).
//!
//! ## What the decoder supports
//!
//! - `bvx-` (uncompressed) blocks: **fully supported**.
//! - `bvxn` (LZVN) blocks: **decoder implemented**.
//! - `bvx$` end-of-stream marker: **honoured** — decoder transitions to
//!   StreamEnd.
//! - `bvx1` blocks: not commonly emitted by modern encoders; this build
//!   returns [`Error::Unsupported`](crate::Error::Unsupported).
//! - `bvx2` (LZFSE v2 compressed) blocks: **decoder implemented** — the core
//!   LZFSE block type (LZ77 commands entropy-coded with Finite State
//!   Entropy), following Apple's reference decoder. Validated against
//!   streams from Apple's `libcompression` and from an independent encoder
//!   (`lzfse_rust`). See the internal `lzfse_v2` module for the layout
//!   reference.
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

use crate::traits::Algorithm;

pub(crate) mod bits;
pub(crate) mod decoder;
pub(crate) mod encoder;
pub(crate) mod fse;
pub(crate) mod lzfse_v2;
pub(crate) mod lzvn;

pub use decoder::Decoder;
pub use encoder::Encoder;

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
