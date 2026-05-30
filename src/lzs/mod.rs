//! Stac LZS (Lempel–Ziv–Stac) — the LZ77 variant specified by
//! [RFC 1974](https://datatracker.ietf.org/doc/html/rfc1974) (PPP Stac
//! LZS Compression Protocol).
//!
//! Used historically by MPPE (RFC 2118), IPComp, Cisco WAN compression
//! and various Stac Electronics hardware accelerators.
//!
//! ## Wire format (RFC 1974 §2)
//!
//! Tokens are packed MSB-first into the output byte stream. Each token
//! is one of:
//!
//! - **Literal**: `0` + 8 bits of literal byte.
//! - **Match**: `1` + offset + length. The offset uses one of two
//!   prefixes — `11` + 7-bit value → short offset (1..=127), or
//!   `10` + 11-bit value → long offset (1..=2047) — and the length is
//!   a variable-length integer (see below).
//! - **End of stream**: an offset of zero, encoded as `110000000` (the
//!   `11` short-offset prefix followed by seven zero bits). The compressor
//!   then pads to the next byte boundary with `1` bits.
//!
//! ### Length encoding
//!
//! After the offset bits, the match length is encoded as:
//!
//! | wire bits     | length |
//! |---------------|-------:|
//! | `00`          |     2  |
//! | `01`          |     3  |
//! | `10`          |     4  |
//! | `1100`        |     5  |
//! | `1101`        |     6  |
//! | `1110`        |     7  |
//! | `1111` + 4    |  8..22 |
//!
//! Lengths ≥ 8 use a chain of one or more `1111` markers (each adds 15)
//! followed by a final non-`1111` nibble that contributes its raw value.
//! So `1111 1111 0000` is length `8 + 15 + 0 = 23`, etc.
//!
//! ### Sliding window
//!
//! The decompression history covers the last 2048 bytes (matching the
//! 11-bit long-offset field). Minimum match length is 2; maximum is
//! unbounded thanks to the chained-`1111` length code.
//!
//! ## Framing
//!
//! RFC 1974 §2 is a pure bit-stream — there is no container, decompressed
//! length, or trailer beyond the end-of-stream marker. The PPP-layer
//! framing in §3 onwards is a transport detail, not part of the codec.
//! To round-trip arbitrary streams through compcol's
//! [`Encoder`](crate::Encoder)/[`Decoder`](crate::Decoder) traits we layer
//! a minimal compcol framing on top:
//!
//! ```text
//! stream  := u64_le(uncompressed_size) || rfc1974_payload
//! ```
//!
//! `uncompressed_size = 0` is a valid stream (empty input); the payload
//! is then a single end-of-stream marker plus padding.

#![cfg_attr(docsrs, doc(cfg(feature = "lzs")))]

extern crate alloc;

use crate::traits::Algorithm;

mod bits;
mod decoder;
mod encoder;

pub use decoder::Decoder;
pub use encoder::Encoder;

/// Maximum back-reference distance, in bytes. The 11-bit long-offset
/// field caps it at 2 KiB.
pub const MAX_DISTANCE: usize = 2048;

/// Minimum match length the encoder will emit.
pub const MIN_MATCH: usize = 2;

/// Zero-sized marker type implementing [`Algorithm`] for LZS.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzs;

impl Algorithm for Lzs {
    const NAME: &'static str = "lzs";
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
