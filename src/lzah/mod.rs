//! StuffIt classic compression **method 5** ("LZAH"): LZSS sliding window
//! over a pre-seeded 4 KiB dictionary, with a single adaptive (sibling-
//! property) Huffman tree for literal/length tokens and a static canonical
//! prefix code for the high bits of each match offset.
//!
//! This is the *raw method-5 fork payload* — there is no StuffIt container
//! header here, exactly like the other archive-method codecs in this crate
//! (rar*, sit13, lha). A caller that walks a `SIT!` archive reads the per-
//! fork compressed bytes and the out-of-band uncompressed length from the
//! 112-byte entry header, then hands the payload to this decoder.
//!
//! ## Method 5 vs method 13
//!
//! The display name "LZAH" is used by some tools for *two* incompatible
//! classic StuffIt methods. This module implements **method low-nibble 5**
//! only (4 KiB window, MSB-first bits, one adaptive Huffman tree, fixed
//! window pre-seed). Method 13 is a different codec (64 KiB window, LSB-
//! first, transmitted prefix codes, in-band end-of-stream) handled by the
//! separate `sit13` module. Always disambiguate on the numeric method byte.
//!
//! ## Framing — length is out of band
//!
//! Method 5 has no in-band end-of-stream symbol; decoding stops exactly when
//! the declared uncompressed length has been produced. That length lives in
//! the archive entry header, not in the bitstream, so it is supplied through
//! [`DecoderConfig::with_len`]. A non-empty stream decoded with no length
//! (`expected_len == None`) cannot be terminated and is rejected with
//! [`Error::Unsupported`].
//!
//! ## No encoder
//!
//! No StuffIt method-5 encoder exists (the historical tooling is decode-only
//! and there is no modern need to write the format), so the [`Encoder`]
//! permanently returns [`Error::Unsupported`].
//!
//! ## Licensing
//!
//! Clean-room from a functional format description: the adaptive-Huffman
//! mechanics, the window pre-seed pattern, the offset prefix-code length
//! rule, and the container field offsets were implemented from a behavioural
//! specification, not from any reference source code or lookup tables.

#![cfg_attr(docsrs, doc(cfg(feature = "lzah")))]

extern crate alloc;
use alloc::vec::Vec;

mod adaptive;
mod bits;
mod offset;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

use adaptive::Tree;
use bits::BitReader;
use offset::OffsetCode;

/// Window (history) size in bytes.
const WINDOW: usize = 4096;
/// Window index mask.
const WMASK: usize = WINDOW - 1;
/// Minimum match length (length code 256 maps to 3).
const MIN_MATCH: usize = 3;
/// First length-code symbol value.
const LEN_BASE: u16 = 256;

// ─── marker type ─────────────────────────────────────────────────────────

/// StuffIt classic method 5 ("LZAH"): LZSS + adaptive Huffman, decode-only.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzah;

/// Decoder configuration: the out-of-band uncompressed length.
///
/// Method 5 streams carry no in-band end marker, so the decoder must be told
/// how many bytes to produce. Build one with [`DecoderConfig::with_len`]. The
/// [`Default`] is `expected_len = None`, which only decodes the empty stream;
/// a non-empty stream with no length returns [`Error::Unsupported`].
#[derive(Debug, Clone, Copy, Default)]
pub struct DecoderConfig {
    /// Exact number of decompressed bytes the fork expands to.
    pub expected_len: Option<usize>,
}

impl DecoderConfig {
    /// Configure the decoder with the fork's declared uncompressed length.
    pub fn with_len(n: usize) -> Self {
        Self {
            expected_len: Some(n),
        }
    }
}

impl Algorithm for Lzah {
    const NAME: &'static str = "lzah";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = DecoderConfig;
    fn encoder_with(_: ()) -> Encoder {
        Encoder
    }
    fn decoder_with(cfg: DecoderConfig) -> Decoder {
        Decoder::new(cfg.expected_len)
    }
}

// ─── encoder stub ─────────────────────────────────────────────────────────

/// Method-5 encoder stub: permanently returns [`Error::Unsupported`].
///
/// No StuffIt method-5 encoder exists; this type lets the crate auto-derive
/// the public [`Encoder`](crate::Encoder) trait while making encode attempts
/// fail cleanly.
#[derive(Debug, Clone, Copy, Default)]
pub struct Encoder;

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_reset(&mut self) {}
}

// ─── window pre-seed ────────────────────────────────────────────────────────

/// Build the fixed 4 KiB window pre-seed (spec section 9).
///
/// The first 18 bytes are left zero; then, in buffer order:
/// 13 copies of each byte value 0..255 (indices 18..3345), an ascending ramp
/// 0..255 (3346..3601), a descending ramp 255..0 (3602..3857), 128 zero bytes
/// (3858..3985), and 110 space bytes (3986..4095).
fn preseed_window() -> [u8; WINDOW] {
    let mut w = [0u8; WINDOW];
    let mut p = 18usize;
    // 13 copies of each value 0..=255.
    for v in 0u16..=255 {
        for _ in 0..13 {
            w[p] = v as u8;
            p += 1;
        }
    }
    // Ascending ramp 0..=255.
    for v in 0u16..=255 {
        w[p] = v as u8;
        p += 1;
    }
    // Descending ramp 255..=0.
    for v in (0u16..=255).rev() {
        w[p] = v as u8;
        p += 1;
    }
    // 128 zero bytes.
    for _ in 0..128 {
        w[p] = 0;
        p += 1;
    }
    // 110 space bytes, filling to the end.
    for _ in 0..110 {
        w[p] = 0x20;
        p += 1;
    }
    debug_assert_eq!(p, WINDOW);
    w
}

// ─── core decode ─────────────────────────────────────────────────────────

/// Decode a raw method-5 payload of exactly `expected_len` bytes.
fn decode_payload(payload: &[u8], expected_len: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(expected_len);
    if expected_len == 0 {
        return Ok(out);
    }

    let mut window = preseed_window();
    // The pre-seed reaches the final index, so the write cursor begins at 0.
    let mut cursor = 0usize;

    let mut br = BitReader::new(payload);
    let mut tree = Tree::new();
    let offset_code = OffsetCode::new();

    while out.len() < expected_len {
        let sym = tree.decode_symbol(|| br.get_bit())?;
        if br.exhausted() {
            return Err(Error::UnexpectedEnd);
        }
        tree.update(sym);

        if sym < LEN_BASE {
            // Literal byte.
            let b = sym as u8;
            window[cursor & WMASK] = b;
            cursor = cursor.wrapping_add(1);
            out.push(b);
        } else {
            // Match: length then offset.
            let length = (sym - LEN_BASE) as usize + MIN_MATCH;
            let h = offset_code.decode(&mut br)?;
            let low6 = br.get_bits(6);
            if br.exhausted() {
                return Err(Error::UnexpectedEnd);
            }
            let distance = ((h << 6) + low6) as usize + 1; // 1..=4096
            let mut src = cursor.wrapping_sub(distance) & WMASK;
            for _ in 0..length {
                if out.len() >= expected_len {
                    break;
                }
                let b = window[src & WMASK];
                window[cursor & WMASK] = b;
                src = src.wrapping_add(1);
                cursor = cursor.wrapping_add(1);
                out.push(b);
            }
        }
    }

    Ok(out)
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming method-5 decoder.
///
/// Buffers the full raw fork payload (a single MSB-first bitstream that
/// cannot be decoded incrementally without a resumable bit/Huffman state
/// machine), decodes it once the stream ends, then drains the decoded bytes
/// into the caller's output across calls. Output is bounded by the declared
/// uncompressed length, so a crafted small input cannot expand without limit.
#[derive(Debug)]
pub struct Decoder {
    expected_len: Option<usize>,
    input: Vec<u8>,
    output: Vec<u8>,
    out_cursor: usize,
    decoded: bool,
}

impl Decoder {
    fn new(expected_len: Option<usize>) -> Self {
        Self {
            expected_len,
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            decoded: false,
        }
    }

    /// Decode the buffered input into `self.output`. Idempotent.
    fn decode_all(&mut self) -> Result<(), Error> {
        if self.decoded {
            return Ok(());
        }
        match self.expected_len {
            None => {
                // No length and a non-empty stream cannot be terminated.
                if self.input.is_empty() {
                    self.decoded = true;
                    return Ok(());
                }
                return Err(Error::Unsupported);
            }
            Some(0) => {
                self.decoded = true;
                return Ok(());
            }
            Some(n) => {
                self.output = decode_payload(&self.input, n)?;
            }
        }
        self.decoded = true;
        Ok(())
    }

    fn drain(&mut self, output: &mut [u8]) -> RawProgress {
        let remaining = self.output.len() - self.out_cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + take]);
        self.out_cursor += take;
        RawProgress {
            consumed: 0,
            written: take,
            done: self.out_cursor >= self.output.len(),
        }
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.decoded {
            // Still accumulating the compressed stream; buffer and report it
            // consumed with no output until `raw_finish`.
            self.input.extend_from_slice(input);
            return Ok(RawProgress {
                consumed: input.len(),
                written: 0,
                done: false,
            });
        }
        let p = self.drain(output);
        Ok(RawProgress {
            consumed: 0,
            written: p.written,
            done: p.done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        self.decode_all()?;
        Ok(self.drain(output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.decoded = false;
    }
}
