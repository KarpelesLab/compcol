//! RAR 3.x (2002-2013) — LZ77 + Huffman path — **decoder only**.
//!
//! ## Encoder is permanently unsupported
//!
//! RARLAB's unRAR license explicitly forbids using its source code to
//! reconstruct the RAR compression algorithm. Even clean-room
//! implementations of RAR decoders (libarchive, The Unarchiver, unarr)
//! ship decoder-only for that reason. The encoder in this module returns
//! [`Error::Unsupported`] from every method, permanently.
//!
//! ## What the decoder does
//!
//! RAR3 streams use one of two compression methods at the block level:
//!
//! 1. **LZ77 + Huffman** — five canonical Huffman codes drive a sliding-window
//!    LZ77 with a 4-deep repeat-offset buffer. This is the vast majority of
//!    real-world RAR3 archives.
//! 2. **PPMd-II** — an Order-N context-mixed arithmetic coder. Used by some
//!    text-heavy archives and `-m5` (best compression) runs.
//!
//! This build implements the **LZ77 + Huffman path** in full, including the
//! in-band standard filters WinRAR declares via main symbol 257 or PPMd
//! escape code 3 (Delta and x86 E8/E8E9, recognized by bytecode fingerprint
//! and run natively — no RarVM interpreter; unknown programs are refused),
//! **PPMd-II variant H** blocks (the full PPMII model in [`crate::ppmd`],
//! driven by the RAR range decoder with the RAR literal/match/end-of-data
//! escape layer), mid-stream switches between the two, and **solid
//! multi-member groups** (shared LZ window, code tables, filter programs
//! and PPMd model across members — see [`Decoder::with_solid`] /
//! [`Decoder::begin_solid_member`]). The standalone E8/E9 (x86 near-call)
//! post-pass filter can also be enabled via [`Decoder::with_e8_filter`].
//!
//! ## Calling convention
//!
//! We deliberately do **not** parse the surrounding RAR archive container —
//! that's a separate (much larger) project. The decoder takes the raw
//! compressed-data block (the bytes that immediately follow the RAR file
//! header in a `.rar` file) plus the declared unpacked size:
//!
//! ```ignore
//! use compcol::rar3::Decoder;
//! use compcol::Decoder as _;
//!
//! let mut dec = Decoder::with_unpack_size(file_header.unpacked_size);
//! // feed bytes
//! let _ = dec.decode(&compressed_block, &mut [])?;
//! // collect output
//! let mut out = vec![0u8; file_header.unpacked_size as usize];
//! let mut total = 0;
//! loop {
//!     let p = dec.finish(&mut out[total..])?;
//!     total += p.written;
//!     if p.done { break }
//! }
//! ```
//!
//! ## Streaming and memory
//!
//! `decode` buffers the compressed stream; decoding starts on the first
//! `finish` call and then proceeds as the caller drains: each `finish`
//! returns as soon as it has bytes to hand out. Output is released one
//! dictionary (4 MiB) behind the decoding position and never past the
//! start of an in-band filter window that is still incomplete, so for LZ
//! blocks the decoder holds about 4.3 MiB of output at most, whatever the
//! unpacked size — plus the compressed input and the 4 MiB dictionary.
//!
//! A **PPMd block** is the exception: it is decoded in one go, and its
//! whole output is held until it has been drained. When the input is
//! untrusted, set an output limit —
//! [`set_output_limit`](crate::Decoder::set_output_limit), or wrap the
//! decoder in a [`LimitedDecoder`](crate::limit::LimitedDecoder), which
//! sets it for you: the decoder then fails with
//! [`Error::OutputLimitExceeded`] at the symbol that would cross the limit
//! instead of building the excess, in LZ and PPMd blocks alike.
//!
//! For a **solid group**, construct the decoder with
//! [`Decoder::with_solid`], decode the first member as above, then call
//! [`Decoder::begin_solid_member`] with the next member's unpacked size
//! before feeding its payload — each member's payload is its own
//! byte-aligned stream, but the compression history carries over.
//!
//! ## References
//!
//! - libarchive `archive_read_support_format_rar.c` (BSD): structure and
//!   tables cross-checked, no code copied.
//! - The Unarchiver `XADRARHandle.m` (LGPL): algorithmic structure only,
//!   no code copied.
//! - unarr's `uncompress-rar.c` (LGPL): the cleanest non-RARLAB reference
//!   for the LZ77 + Huffman path.

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod bits;
mod decoder;
mod filters;
mod huffman;
mod tables;

pub use decoder::Decoder;
pub use filters::apply_e8_filter;

/// Zero-sized marker type implementing [`Algorithm`] for Rar3.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar3;

impl Algorithm for Rar3 {
    const NAME: &'static str = "rar3";
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

/// Permanently-unsupported encoder. See module docs for the licence reason.
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
