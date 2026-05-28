//! LZX (Microsoft CAB / WIM compression).
//!
//! References:
//!   - [MS-PATCH] §2 (LZX DELTA Compression and Decompression):
//!     <https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf>
//!   - libmspack's `lzxd.c` reference implementation (LGPL 2.1, used for
//!     cross-checking constants and edge cases — no code is copied).
//!
//! ## What this build supports
//!
//! ### Decoder
//!
//! All three block types are accepted:
//!   - **Verbatim** (BLOCKTYPE=1): MAIN_TREE + LENGTH_TREE driven LZ77.
//!   - **Aligned-offset** (BLOCKTYPE=2): adds an ALIGNED_TREE for the low
//!     3 bits of large offsets.
//!   - **Uncompressed** (BLOCKTYPE=3): raw byte payload with R0/R1/R2 dump.
//!
//! The full pretree machinery (delta-encoded code lengths with the 4-bit
//! pretree and the 17/18/19 run-length specials) is implemented. The intel
//! E8 call-translation filter is applied when the stream's leading flag bit
//! is set.
//!
//! Supported windows are the CAB profile (window_bits ∈ 15..=21). LZX DELTA
//! windows (22..=25) and the DELTA-specific extended match lengths are not
//! implemented.
//!
//! ### Encoder
//!
//! The encoder emits **uncompressed blocks only** (BLOCKTYPE=3). The output
//! is a valid LZX stream that the decoder accepts; it just doesn't actually
//! compress. A real verbatim/aligned encoder is out of scope for this build.
//!
//! ## Stream framing
//!
//! Standard LZX is framed externally (the CAB CFFOLDER header, the WIM
//! resource header, etc.). Because this crate is a stand-alone codec, we
//! add the minimal framing needed to let the decoder know when to stop:
//!
//! ```text
//! byte 0      : window_bits        (15..=21)
//! bytes 1..=4 : little-endian u32 of the total uncompressed length
//! bytes 5..   : the LZX bitstream
//! ```
//!
//! When the decoder has emitted `total uncompressed length` bytes it
//! transitions to a Done state and ignores any trailing bits.

mod bitreader;
pub mod decoder;
pub mod encoder;
mod huffman;
mod tables;

pub use decoder::Decoder;
pub use encoder::Encoder;

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for LZX.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzx;

impl Algorithm for Lzx {
    const NAME: &'static str = "lzx";
    type Encoder = Encoder;
    type Decoder = Decoder;

    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}
