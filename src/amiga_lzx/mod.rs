//! Amiga LZX — the original 1995 Jonathan Forbes LZX codec used by the
//! Amiga `.lzx` archive format.
//!
//! This is distinct from the MS-CAB LZX variant shipped at [`crate::lzx`].
//! Block-level decoding is identical (verbatim / aligned-offset /
//! uncompressed, pretree-coded code lengths, R0/R1/R2 LRU offsets,
//! `EXTRA_BITS` / `POSITION_BASE` tables); the surrounding framing differs:
//!
//! | Aspect                       | MS-CAB LZX                                  | Amiga LZX (this module)        |
//! |------------------------------|---------------------------------------------|--------------------------------|
//! | Window size                  | 32 KiB..2 MiB (window_bits ∈ 15..=21)        | Fixed **64 KiB** (window_bits = 16) |
//! | 32 KiB chunk/frame structure | Yes — forces flush + reset boundary for E8  | None — continuous bitstream    |
//! | E8 jump-translation filter   | Yes — leading flag bit + per-frame post-fix | None — Motorola 68000, no x86 fixups |
//!
//! See <https://en.wikipedia.org/wiki/LZX> for an overview. The MS-CAB
//! profile is documented in [MS-PATCH] §2; the Amiga profile is essentially
//! "the same block format minus the chunking and the x86 filter".
//!
//! ## What this build supports
//!
//! ### Decoder
//!
//! All three block types are accepted:
//!   - **Verbatim** (`BLOCKTYPE=1`): MAIN_TREE + LENGTH_TREE driven LZ77.
//!   - **Aligned-offset** (`BLOCKTYPE=2`): adds an ALIGNED_TREE for the
//!     low 3 bits of large offsets.
//!   - **Uncompressed** (`BLOCKTYPE=3`): raw byte payload with R0/R1/R2 dump.
//!
//! The pretree machinery (delta-encoded code lengths with the 4-bit pretree
//! and the 17/18/19 run-length specials) is implemented in full.
//!
//! ### Encoder
//!
//! The encoder emits **uncompressed blocks only** (`BLOCKTYPE=3`). The
//! output is a valid Amiga-LZX stream that the decoder accepts; it just
//! doesn't actually compress. This mirrors the [`crate::lzx`] encoder
//! precedent. A real verbatim/aligned encoder is out of scope for this
//! build.
//!
//! ## Wire framing
//!
//! Amiga `.lzx` archives wrap their LZX payload in a per-entry header
//! (filename, length, CRC, …) that this codec does not implement — that
//! belongs to a separate archive module. Since this crate is a stand-alone
//! codec we add the minimal framing needed to let the decoder know when to
//! stop:
//!
//! ```text
//! bytes 0..=3 : little-endian u32 of the total uncompressed length
//! bytes 4..   : continuous LZX bitstream of blocks
//! ```
//!
//! Each block on the wire is, MSB-first within each 16-bit-LE word:
//!
//! ```text
//! 3 bits  : BLOCKTYPE (1 = verbatim, 2 = aligned, 3 = uncompressed)
//! 24 bits : BLOCK_SIZE (uncompressed bytes encoded by this block)
//! ... block payload per BLOCKTYPE ...
//! ```
//!
//! Note that there is **no** leading "intel translation" flag bit and **no**
//! 32 KiB chunk reset between blocks; the bitstream is a self-delimited
//! sequence of blocks back-to-back. The decoder stops once
//! `output_so_far == total uncompressed length`; trailing bits / partial
//! trailing bytes are tolerated.
//!
//! ## Extension conflict
//!
//! Both the MS-CAB LZX and Amiga LZX formats use the `.lzx` extension. The
//! [`crate::factory`] extension table maps `"lzx"` to the CAB codec
//! (`crate::lzx`). The two stream formats are **not** interoperable; a
//! CAB-LZX stream will not decode through this decoder and vice versa. To
//! select the Amiga variant, look it up by name through
//! [`crate::factory::encoder_by_name`] / [`crate::factory::decoder_by_name`]
//! with `"amiga_lzx"`.

pub mod decoder;
pub mod encoder;

pub use decoder::Decoder;
pub use encoder::Encoder;

use crate::traits::Algorithm;

/// Fixed LZX window size for the Amiga profile.
pub(crate) const WINDOW_BITS: u8 = 16;

/// Window size in bytes: 64 KiB.
pub(crate) const WINDOW_SIZE: usize = 1usize << WINDOW_BITS;

/// Zero-sized marker type implementing [`Algorithm`] for Amiga LZX.
#[derive(Debug, Clone, Copy, Default)]
pub struct AmigaLzx;

impl Algorithm for AmigaLzx {
    const NAME: &'static str = "amiga_lzx";
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
