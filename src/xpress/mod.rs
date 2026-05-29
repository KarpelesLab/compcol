//! Microsoft Xpress — Plain LZ77 byte-aligned codec.
//!
//! Reference: [MS-XCA] section 2.4 "Plain LZ77 Decompression Algorithm
//! Details" (and the symmetric 2.3 for compression). Plain LZ77 is the
//! lowest-CPU member of the Xpress family — no Huffman, no entropy
//! coding, just LZ77 length/distance pairs packed into a small byte-
//! oriented stream gated by 32-bit flag DWORDs.
//!
//! ## Wire format (per MS-XCA §2.3/2.4)
//!
//! Each output region begins with a 32-bit little-endian "flag DWORD".
//! The 32 bits, read **MSB-first**, are the literal/match flags for the
//! following 32 symbols:
//!
//! - `0` → the next byte in the input is a raw literal.
//! - `1` → the next two input bytes are a 16-bit little-endian "metadata"
//!   word `sym`. The 13 high bits encode the back-reference distance
//!   (`(sym >> 3) + 1`, in range `1..=8192`); the 3 low bits encode the
//!   base length code.
//!
//! After consuming 32 symbols, a fresh flag DWORD is read, and so on,
//! until the decompressed size announced by the framing header has been
//! produced.
//!
//! ### Match-length expansion
//!
//! The base length code `lc = sym & 7` is the first stage of a four-
//! tier variable-length integer that encodes match length minus 3:
//!
//! 1. If `lc < 7`: actual length is `lc + 3`. Range: 3..=9.
//! 2. If `lc == 7`: read a 4-bit "half-byte" (`hb`).
//!    - Half-bytes are packed: the **low** nibble of a byte is read
//!      first, then the high nibble of the same byte is consumed by the
//!      next long-match. A persistent pointer to the current "owner"
//!      byte tracks which half is available.
//!    - If `hb < 15`: actual length is `hb + 7 + 3 = hb + 10`. Range: 10..=24.
//! 3. If `hb == 15`: read a full 8-bit byte `b`.
//!    - If `b < 255`: actual length is `b + 15 + 7 + 3 = b + 25`.
//!      Range: 25..=279.
//! 4. If `b == 255`: read a 16-bit little-endian word `w`.
//!    - If `w != 0`: actual length is `w - (15 + 7) = w - 22`.
//!      (The `+3` is **not** added in this branch — the spec's encoder
//!      writes the final length, biased only by `15+7`, here.)
//!    - If `w == 0`: read a 32-bit little-endian word `dw`. Actual
//!      length is `dw - 22`.
//!
//! `w` (or `dw`) is rejected as corrupt if it is less than `22` because
//! that would represent a length below the threshold of the previous
//! tier — a clear sign the stream is malformed.
//!
//! ### End of stream
//!
//! MS-XCA's plain format has no in-band end marker — the producer knows
//! the decompressed size. Conventionally, when the last flag DWORD's
//! "current" bit position is reached mid-DWORD, the remaining bits are
//! all `1`s (so the truncated DWORD is `1xxx…1`). Our framing carries
//! an explicit 8-byte decompressed-size header so the decoder knows
//! exactly when to stop emitting bytes.
//!
//! ## Framing (this crate)
//!
//! MS-XCA plain LZ77 has no on-disk header; callers are expected to
//! know the decompressed size out of band. To round-trip arbitrary
//! streams through our [`Encoder`]/[`Decoder`] traits we layer a minimal
//! framing on top:
//!
//! ```text
//! stream  := u64_le(uncompressed_size) || plain_lz77_payload
//! ```
//!
//! `uncompressed_size = 0` is a valid stream meaning "empty input" —
//! the payload is then zero bytes, with no flag DWORD.
//!
//! This is intentionally smaller than the WIM / Win10-compressed-folder
//! containers that wrap raw MS-XCA blocks in the wild; their containers
//! have their own framing layers that callers can implement on top.
//!
//! ## Sliding window
//!
//! Maximum back-reference distance is 8192 bytes (13-bit field +1).
//! Minimum match length is 3 bytes.

#![cfg_attr(docsrs, doc(cfg(feature = "xpress")))]

extern crate alloc;

use crate::traits::Algorithm;

mod decoder;
mod encoder;

pub use decoder::Decoder;
pub use encoder::Encoder;

/// Maximum back-reference distance, in bytes. The 13-bit distance field
/// plus the implicit `+1` bias caps it at 8 KiB.
pub const MAX_DISTANCE: usize = 8192;

/// Minimum match length. Encoder will not emit a match shorter than this.
pub const MIN_MATCH: usize = 3;

/// Zero-sized marker type implementing [`Algorithm`] for Xpress (Plain LZ77).
#[derive(Debug, Clone, Copy, Default)]
pub struct Xpress;

impl Algorithm for Xpress {
    const NAME: &'static str = "xpress";
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
