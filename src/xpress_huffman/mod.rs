//! XPress Huffman ([MS-XCA] §2.1) — Microsoft's LZ77 + canonical Huffman.
//!
//! Used by WIM (LZX containers also reference XPress for small files),
//! CompactOS NTFS file compression, and several Windows-internal cache
//! surfaces. The transport itself is very thin: a sequence of 65,536-
//! byte output blocks, each prefixed by a 256-byte Huffman code-length
//! table over a 512-symbol alphabet (literals 0..=255 + match-class
//! symbols 256..=511).
//!
//! Reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b>
//!
//! ## Wire layout (per block)
//!
//! ```text
//!   byte  0..256   : packed code lengths (4 bits/symbol, low nibble = even
//!                    symbol, high nibble = odd; max length 15)
//!   byte 256..     : MSB-first bit stream of 16-bit little-endian words.
//!                    Each match symbol may be followed by 1 or 3 "extra"
//!                    raw bytes for the long-length escape, then 0..15
//!                    extra MSB-first bits for the low bits of the
//!                    distance.
//! ```
//!
//! A match symbol decomposes as:
//! - `match_sym = HuffmanSymbol - 256`
//! - `length_class = match_sym & 15`        (the short length in 0..=14, or 15 = escape)
//! - `dist_hi      = match_sym >> 4`        (the bit-index of the distance's MSB)
//! - If `length_class == 15`, read one byte; if that's 255, read a u16
//!   (LE) instead; assemble per spec to produce `length` (≥ 18).
//! - Final length = (computed) + 3.
//! - Final offset = (`NextBits >> (32 - dist_hi)`) + (1 << dist_hi);
//!   `dist_hi` extra MSB-first bits consumed.
//!
//! The end-of-stream sentinel is symbol `256` (a "match" with
//! length_class=0, dist_hi=0); decoders honour it only after the
//! caller's expected uncompressed length has been emitted.
//!
//! ## Framing
//!
//! The MS-XCA stream proper carries no length information — Windows
//! callers know the expected decompressed size externally (NTFS file
//! header, WIM resource record, etc.). Because this crate is a
//! stand-alone codec, we prepend a 4-byte little-endian header:
//!
//! ```text
//!   bytes 0..=3 : u32 LE total uncompressed length
//!   bytes 4..   : the MS-XCA bitstream (one or more 64 KiB blocks)
//! ```
//!
//! Once `total_uncompressed` output bytes have been emitted the decoder
//! transitions to Done and ignores any trailing bytes. Mirrors the
//! framing used by the [`lzx`](crate::lzx) module.

#![cfg_attr(docsrs, doc(cfg(feature = "xpress_huffman")))]

mod decoder;
mod encoder;
mod huffman;

pub use decoder::Decoder;
pub use encoder::{Encoder, EncoderConfig};

use crate::traits::Algorithm;

/// Zero-sized marker type implementing [`Algorithm`] for XPress Huffman.
#[derive(Debug, Clone, Copy, Default)]
pub struct XpressHuffman;

impl Algorithm for XpressHuffman {
    const NAME: &'static str = "xpress-huffman";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = ();

    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}
