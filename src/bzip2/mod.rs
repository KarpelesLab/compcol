//! bzip2 (`.bz2`).
//!
//! Block-sorted compression: each block runs raw input through a
//! pipeline of RLE-1 → Burrows–Wheeler transform → move-to-front →
//! RLE-2 → multi-table canonical-Huffman → MSB-first bit packing. The
//! result is wrapped in a `"BZh<level>"` stream header, one or more
//! block payloads keyed off the `0x31_4159_2653_59` ("1AY&SY") magic,
//! and a `0x17_7245_3850_90` ("sqrt(pi)") end-of-stream magic followed
//! by a combined CRC over all per-block CRC-32/MPEG-2 values
//! (rotate-left-then-XOR accumulation).
//!
//! ## Module split
//!
//! - [`bits`](self#bit-readerwriter) — MSB-first bit reader/writer
//!   (separate from `crate::bits`, which is LSB-first for deflate).
//! - [`crc`](self#crc-32mpeg-2) — CRC-32/MPEG-2 implementation
//!   (non-reflected, no final XOR).
//! - [`huffman`](self#canonical-huffman) — canonical Huffman code
//!   construction (encoder) and prefix-code decode tables (decoder),
//!   limited to 20 bits.
//! - [`bwt`](self#burrowswheeler) — forward (naive O(n² log n) suffix
//!   sort) and inverse (classic O(n) permutation walk) BWT.
//! - [`mtf`](self#move-to-front) — MTF over a reduced byte alphabet.
//! - [`rle`](self#rle) — RLE-1 (raw-byte pre-pass, runs of 4+
//!   compressed into 4 copies + count) and RLE-2 (post-MTF zero-run
//!   coding via RUNA/RUNB).
//! - `encoder` / `decoder` — the streaming state machines.
//!
//! ## Round-trip status
//!
//! Both directions work on arbitrary input. The encoder is correctness
//! first, not byte-for-byte compatible with reference `bzip2 -c`: it
//! picks slightly different (still valid) selectors and table
//! frequencies. Streams produced here decompress cleanly with system
//! `bunzip2`, and our decoder accepts arbitrary system-`bzip2`-produced
//! streams.
//!
//! ## Concatenated streams
//!
//! Single-stream only in this build. Concatenated bzip2 streams
//! (`cat a.bz2 b.bz2`) are not yet supported on the decode side; the
//! decoder treats the second stream's header magic as garbage and
//! stops at the first stream's end-of-stream trailer.

#![cfg_attr(docsrs, doc(cfg(feature = "bzip2")))]

use crate::error::Error as _Error;
use crate::traits::Algorithm;

mod bits;
mod bwt;
mod crc;
mod decoder;
mod encoder;
mod huffman;
mod mtf;
mod rle;

// Silence "unused" if a downstream branch ever decouples; the public
// surface is re-exported below.
#[allow(unused_imports)]
use _Error as _;

pub use decoder::Decoder;
pub use encoder::{Encoder, EncoderConfig};

/// Zero-sized marker type implementing [`Algorithm`] for bzip2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bzip2;

impl Algorithm for Bzip2 {
    const NAME: &'static str = "bzip2";
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
