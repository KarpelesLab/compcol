//! Raw LZMA2 decoder (7-Zip coder id `21`).
//!
//! 7-Zip's LZMA2 coder is a **raw LZMA2 chunk stream** — a sequence of
//! control-byte-framed chunks ending in a `0x00` end-control byte — *not*
//! the `.xz` container (that lives in [`crate::xz`]). This module exposes a
//! [`Decoder`](crate::Decoder)-shaped entry point over that raw stream so a
//! 7z reader can feed the coder's payload directly and stream the result
//! through a [`crate::io::DecoderReader`] / filter chain.
//!
//! ## Stream layout
//!
//! ```text
//!   ( chunk )* 0x00
//!
//!   control byte:
//!     0x00            end of stream
//!     0x01            uncompressed chunk, dictionary reset
//!     0x02            uncompressed chunk, no reset
//!     0x80..=0xFF     LZMA-compressed chunk
//!
//!   uncompressed chunk: control, size-1 (u16 BE), <size raw bytes>
//!   compressed chunk:   control (top bit set; bits 5-6 = reset mode,
//!                       bits 0-4 = top 5 bits of uncomp_size-1),
//!                       uncomp_size-1 low (u16 BE),
//!                       comp_size-1 (u16 BE),
//!                       [props byte if reset mode >= 2],
//!                       <comp_size LZMA range-coded bytes>
//!
//!   reset mode (bits 5-6 of the control byte):
//!     0  continuation (no resets)
//!     1  state reset
//!     2  state reset + new properties
//!     3  state reset + new properties + dictionary reset
//! ```
//!
//! Because the stream self-terminates on the `0x00` control byte, no
//! out-of-band uncompressed length is required. A [`DecoderConfig`] still
//! offers [`DecoderConfig::with_len`] for callers that know the exact
//! decompressed size up front (purely advisory — it is not needed to find
//! the end of the stream).
//!
//! ## Coder property
//!
//! The 7z LZMA2 coder property is a single **dictionary-size code** byte
//! (the same encoding the xz Block Header uses for the LZMA2 filter). Pass
//! it via [`DecoderConfig::with_dict_prop`]; the dictionary size is derived
//! exactly as in [`crate::xz`]. With no property the decoder uses a 4 MiB
//! dictionary, which is sufficient for any stream whose dictionary code
//! resolves to ≤ 4 MiB (the common case).
//!
//! ## Reuse
//!
//! The LZMA range coder, probability tables, and LZ window are the exact
//! machinery used by [`crate::xz`] (the shared `LzmaCore`); this module only
//! adds the raw chunk framing and self-termination handling. There is no
//! re-implementation of LZMA here.

#![cfg_attr(docsrs, doc(cfg(feature = "lzma2")))]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;
use crate::lzma2_internal::lzma2_decoder::{Lzma2Props, LzmaCore, lzma2_dict_size};
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Hard cap on the LZMA2 dictionary we will allocate, regardless of the
/// dictionary-size code. Bounds memory against a crafted property byte;
/// legitimate 7z LZMA2 streams essentially never exceed 64 MiB.
const MAX_DICT: usize = 128 * 1024 * 1024;

/// Default dictionary size when no property byte is supplied (4 MiB — the
/// LZMA2 default and the size [`crate::xz`] uses).
const DEFAULT_DICT: usize = 4 * 1024 * 1024;

/// Raw LZMA2 stream codec (7-Zip coder id 21). Decode-only.
///
/// The encoder is a permanent [`Error::Unsupported`] stub: 7z LZMA2 framing
/// is produced by the [`crate::xz`] encoder path, and there is no need for a
/// standalone raw LZMA2 encoder. See the [module docs](self) for the stream
/// shape.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzma2;

/// Decoder configuration for raw LZMA2.
///
/// Both fields are optional. The dictionary-size code (the 7z coder
/// property byte) sizes the LZ window; with no code a 4 MiB dictionary is
/// used. `expected_len` is advisory only — the stream self-terminates on
/// its `0x00` control byte.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecoderConfig {
    /// The 7z LZMA2 coder property: a 1-byte dictionary-size code, decoded
    /// the same way the xz LZMA2 filter property is. `None` → 4 MiB
    /// (unless `dict_size` is set).
    pub dict_prop: Option<u8>,
    /// Explicit dictionary size in bytes, overriding `dict_prop` when set.
    /// Clamped to `[4096, 128 MiB]` at decoder construction.
    pub dict_size: Option<usize>,
    /// Advisory uncompressed length, if known. Not required for decoding.
    pub expected_len: Option<usize>,
}

impl DecoderConfig {
    /// Configure the decoder with the 7z coder property (dictionary-size
    /// code byte).
    pub fn with_dict_prop(byte: u8) -> Self {
        Self {
            dict_prop: Some(byte),
            dict_size: None,
            expected_len: None,
        }
    }

    /// Configure the decoder with an explicit dictionary size in bytes
    /// (clamped to `[4096, 128 MiB]`). Use this when the dictionary size is
    /// known directly rather than as a code byte.
    pub fn with_dict_size(bytes: usize) -> Self {
        Self {
            dict_prop: None,
            dict_size: Some(bytes),
            expected_len: None,
        }
    }

    /// Add an advisory expected uncompressed length (not required to decode).
    pub fn with_len(mut self, n: usize) -> Self {
        self.expected_len = Some(n);
        self
    }
}

impl Algorithm for Lzma2 {
    const NAME: &'static str = "lzma2";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = DecoderConfig;
    fn encoder_with(_: ()) -> Encoder {
        Encoder
    }
    fn decoder_with(cfg: DecoderConfig) -> Decoder {
        Decoder::new(cfg)
    }
}

/// Resolve a configured dictionary size (in bytes), clamped to a sane
/// allocation range. An explicit `dict_size` wins; otherwise the property
/// byte is decoded; otherwise the 4 MiB default is used.
fn resolve_dict_size(cfg: &DecoderConfig) -> Result<usize, Error> {
    let raw = match (cfg.dict_size, cfg.dict_prop) {
        (Some(n), _) => n,
        (None, Some(b)) => lzma2_dict_size(b)? as usize,
        (None, None) => DEFAULT_DICT,
    };
    Ok(raw.clamp(4096, MAX_DICT))
}

// ─── encoder stub ─────────────────────────────────────────────────────────

/// Raw LZMA2 encoder stub: permanently returns [`Error::Unsupported`].
///
/// Lets the crate auto-derive the public [`Encoder`](crate::Encoder) trait
/// while making encode attempts fail cleanly. LZMA2 output is produced via
/// the [`crate::xz`] encoder.
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

// ─── decoder ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading the 1-byte control.
    Control,
    /// Reading the rest of an uncompressed chunk header (2 bytes).
    UncompHeader,
    /// Copying `chunk_remaining` raw bytes straight through.
    UncompData,
    /// Reading the rest of a compressed chunk header (4 or 5 bytes).
    CompHeader,
    /// Buffering `comp_size` compressed bytes.
    CompBuffer,
    /// Draining the decoded chunk to the caller.
    CompDrain,
    /// Saw the `0x00` end control; stream complete.
    Done,
}

/// Streaming raw LZMA2 decoder.
///
/// Drive through the [`Decoder`](crate::Decoder) trait (or
/// [`crate::io::DecoderReader`]). Self-terminates on the `0x00` control byte.
pub struct Decoder {
    dict_size: usize,
    lzma_core: Option<Box<LzmaCore>>,
    phase: Phase,
    poisoned: bool,

    /// First chunk in the stream must perform a dictionary reset.
    expecting_first: bool,

    // Scratch for partial header bytes spanning input chunks.
    scratch: Vec<u8>,
    scratch_want: usize,

    // Current compressed-chunk parameters.
    comp_ctrl: u8,
    comp_uncomp_size: usize,
    comp_size: usize,

    // Compressed-chunk working buffers.
    comp_buf: Vec<u8>,
    comp_decoded: Vec<u8>,
    comp_decoded_pos: usize,

    // Uncompressed (stored) chunk byte counter.
    chunk_remaining: usize,
}

impl Decoder {
    /// Build a decoder from a [`DecoderConfig`].
    pub fn new(cfg: DecoderConfig) -> Self {
        // Resolve dictionary size eagerly; an invalid property byte poisons
        // the decoder so the first `decode` call surfaces `Corrupt`.
        let (dict_size, poisoned) = match resolve_dict_size(&cfg) {
            Ok(n) => (n, false),
            Err(_) => (DEFAULT_DICT, true),
        };
        let _ = cfg.expected_len; // advisory only
        Self {
            dict_size,
            lzma_core: None,
            phase: Phase::Control,
            poisoned,
            expecting_first: true,
            scratch: Vec::new(),
            scratch_want: 0,
            comp_ctrl: 0,
            comp_uncomp_size: 0,
            comp_size: 0,
            comp_buf: Vec::new(),
            comp_decoded: Vec::new(),
            comp_decoded_pos: 0,
            chunk_remaining: 0,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Pull bytes from `input` (advancing `consumed`) into `scratch` until it
    /// holds `scratch_want` bytes. Returns true once full.
    fn fill_scratch(&mut self, input: &[u8], consumed: &mut usize) -> bool {
        while self.scratch.len() < self.scratch_want && *consumed < input.len() {
            self.scratch.push(input[*consumed]);
            *consumed += 1;
        }
        self.scratch.len() >= self.scratch_want
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                Phase::Done => {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
                Phase::Control => {
                    self.scratch_want = 1;
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let control = self.scratch[0];
                    self.scratch.clear();
                    if control == 0x00 {
                        self.phase = Phase::Done;
                    } else if control == 0x01 || control == 0x02 {
                        // First chunk must reset the dictionary; for an
                        // uncompressed chunk that means 0x01.
                        if self.expecting_first && control != 0x01 {
                            return Err(self.poison(Error::Corrupt));
                        }
                        if control == 0x01 {
                            // Dictionary reset clears any straddling LZ state.
                            self.lzma_core = None;
                        }
                        self.expecting_first = false;
                        self.scratch_want = 2;
                        self.phase = Phase::UncompHeader;
                    } else if control >= 0x80 {
                        // First chunk must full-reset (dict + props + state),
                        // i.e. control byte in 0xE0..=0xFF.
                        if self.expecting_first && control < 0xE0 {
                            return Err(self.poison(Error::Corrupt));
                        }
                        self.comp_ctrl = control;
                        // Need uncomp-low(2) + comp(2) + optional props(1).
                        let needs_props = (control & 0x40) != 0;
                        self.scratch_want = if needs_props { 5 } else { 4 };
                        self.phase = Phase::CompHeader;
                    } else {
                        return Err(self.poison(Error::Corrupt));
                    }
                }
                Phase::UncompHeader => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let len = (((self.scratch[0] as usize) << 8) | self.scratch[1] as usize) + 1;
                    self.scratch.clear();
                    self.chunk_remaining = len;
                    self.phase = Phase::UncompData;
                }
                Phase::UncompData => {
                    while self.chunk_remaining > 0
                        && consumed < input.len()
                        && written < output.len()
                    {
                        let take = self
                            .chunk_remaining
                            .min(input.len() - consumed)
                            .min(output.len() - written);
                        let src = &input[consumed..consumed + take];
                        output[written..written + take].copy_from_slice(src);
                        // Feed the bytes into the LZ window so a later
                        // compressed chunk (without a dict reset) can
                        // back-reference them.
                        if let Some(core) = self.lzma_core.as_mut() {
                            core.append_literals(src);
                        }
                        self.chunk_remaining -= take;
                        consumed += take;
                        written += take;
                    }
                    if self.chunk_remaining == 0 {
                        self.phase = Phase::Control;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                Phase::CompHeader => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let control = self.comp_ctrl;
                    let needs_props = (control & 0x40) != 0;
                    let uncomp_top = (control & 0x1F) as usize;
                    let uncomp_lo = ((self.scratch[0] as usize) << 8) | self.scratch[1] as usize;
                    self.comp_uncomp_size = ((uncomp_top << 16) | uncomp_lo) + 1;
                    self.comp_size =
                        (((self.scratch[2] as usize) << 8) | self.scratch[3] as usize) + 1;

                    // Reset semantics (bits 5-6 of control).
                    let reset_bits = (control >> 5) & 0x03;
                    if reset_bits == 0b11 {
                        let props = match Lzma2Props::parse(self.scratch[4]) {
                            Ok(p) => p,
                            Err(e) => return Err(self.poison(e)),
                        };
                        match self.lzma_core.as_mut() {
                            Some(core) if core.dict_capacity() == self.dict_size.max(1) => {
                                core.reset_full(props);
                            }
                            _ => {
                                self.lzma_core =
                                    Some(Box::new(LzmaCore::new(props, self.dict_size)));
                            }
                        }
                    } else if reset_bits == 0b10 {
                        let props = match Lzma2Props::parse(self.scratch[4]) {
                            Ok(p) => p,
                            Err(e) => return Err(self.poison(e)),
                        };
                        let core = match self.lzma_core.as_mut() {
                            Some(c) => c,
                            None => return Err(self.poison(Error::Corrupt)),
                        };
                        core.replace_props(props);
                        core.reset_state();
                    } else if reset_bits == 0b01 {
                        let _ = needs_props;
                        match self.lzma_core.as_mut() {
                            Some(c) => c.reset_state(),
                            None => return Err(self.poison(Error::Corrupt)),
                        }
                    } else {
                        // 00 continuation: core must already exist.
                        if self.lzma_core.is_none() {
                            return Err(self.poison(Error::Corrupt));
                        }
                    }

                    self.expecting_first = false;
                    self.scratch.clear();
                    self.comp_buf.clear();
                    self.phase = Phase::CompBuffer;
                }
                Phase::CompBuffer => {
                    let need = self.comp_size - self.comp_buf.len();
                    let take = need.min(input.len() - consumed);
                    if take > 0 {
                        self.comp_buf
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.comp_buf.len() < self.comp_size {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Decode the whole chunk into comp_decoded.
                    self.comp_decoded.clear();
                    self.comp_decoded.resize(self.comp_uncomp_size, 0u8);
                    let core = match self.lzma_core.as_mut() {
                        Some(c) => c,
                        None => return Err(self.poison(Error::Corrupt)),
                    };
                    if let Err(e) = core.init_range(&self.comp_buf) {
                        return Err(self.poison(e));
                    }
                    if let Err(e) = core.decode_chunk(&self.comp_buf, &mut self.comp_decoded) {
                        return Err(self.poison(e));
                    }
                    self.comp_decoded_pos = 0;
                    self.phase = Phase::CompDrain;
                }
                Phase::CompDrain => {
                    let total = self.comp_decoded.len();
                    while self.comp_decoded_pos < total && written < output.len() {
                        let take = (total - self.comp_decoded_pos).min(output.len() - written);
                        let src =
                            &self.comp_decoded[self.comp_decoded_pos..self.comp_decoded_pos + take];
                        output[written..written + take].copy_from_slice(src);
                        self.comp_decoded_pos += take;
                        written += take;
                    }
                    if self.comp_decoded_pos >= total {
                        self.phase = Phase::Control;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
            }
        }
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // Self-terminating: finishing before the 0x00 control is truncation.
        if self.phase == Phase::Done {
            Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            })
        } else {
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn raw_reset(&mut self) {
        self.lzma_core = None;
        self.phase = Phase::Control;
        self.poisoned = false;
        self.expecting_first = true;
        self.scratch.clear();
        self.scratch_want = 0;
        self.comp_ctrl = 0;
        self.comp_uncomp_size = 0;
        self.comp_size = 0;
        self.comp_buf.clear();
        self.comp_decoded.clear();
        self.comp_decoded_pos = 0;
        self.chunk_remaining = 0;
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(DecoderConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzma2_internal::lzma2_encoder::{
        EncoderParams, LZMA2_PROPS_BYTE, encode_lzma_chunk,
    };
    use crate::traits::{Decoder as _, Status};
    use alloc::vec;

    const TEST_DICT: u32 = 1 << 20; // 1 MiB

    /// Frame one full-reset compressed LZMA2 chunk (control 0xE0..0xFF).
    fn frame_compressed_chunk(data: &[u8], out: &mut Vec<u8>) {
        assert!(!data.is_empty() && data.len() <= 1 << 21);
        let comp = encode_lzma_chunk(data, TEST_DICT, EncoderParams::from_level(6));
        let uncomp_m1 = (data.len() - 1) as u32;
        let comp_m1 = (comp.len() - 1) as u32;
        assert!(comp_m1 < (1 << 16), "test chunk compressed size too large");
        let control = 0xE0 | ((uncomp_m1 >> 16) & 0x1F) as u8; // full reset
        out.push(control);
        out.push(((uncomp_m1 >> 8) & 0xFF) as u8);
        out.push((uncomp_m1 & 0xFF) as u8);
        out.push(((comp_m1 >> 8) & 0xFF) as u8);
        out.push((comp_m1 & 0xFF) as u8);
        out.push(LZMA2_PROPS_BYTE);
        out.extend_from_slice(&comp);
    }

    /// Frame one uncompressed LZMA2 chunk (control 0x01 dict-reset).
    fn frame_uncompressed_chunk(data: &[u8], out: &mut Vec<u8>) {
        assert!(!data.is_empty() && data.len() <= 1 << 16);
        let m1 = (data.len() - 1) as u16;
        out.push(0x01);
        out.push((m1 >> 8) as u8);
        out.push((m1 & 0xFF) as u8);
        out.extend_from_slice(data);
    }

    /// Build a complete raw LZMA2 stream from per-chunk (data, compressed?)
    /// segments, terminated by the 0x00 control byte.
    fn build_stream(chunks: &[(&[u8], bool)]) -> Vec<u8> {
        let mut s = Vec::new();
        for (data, compressed) in chunks {
            if *compressed {
                frame_compressed_chunk(data, &mut s);
            } else {
                frame_uncompressed_chunk(data, &mut s);
            }
        }
        s.push(0x00);
        s
    }

    /// Decode a full raw LZMA2 stream all at once.
    fn decode_all(stream: &[u8], out_cap: usize) -> Result<Vec<u8>, Error> {
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut out = vec![0u8; out_cap + 16];
        let mut consumed = 0;
        let mut written = 0;
        loop {
            let (p, st) = dec.decode(&stream[consumed..], &mut out[written..])?;
            consumed += p.consumed;
            written += p.written;
            match st {
                Status::StreamEnd => break,
                Status::InputEmpty => {
                    if consumed >= stream.len() {
                        // No 0x00 seen — let finish report truncation.
                        dec.finish(&mut out[written..])?;
                        break;
                    }
                }
                Status::OutputFull => {
                    assert!(written < out.len(), "output buffer exhausted");
                }
            }
        }
        out.truncate(written);
        Ok(out)
    }

    /// Decode feeding exactly one input byte at a time into a 1-byte output
    /// buffer — stresses every phase boundary.
    fn decode_byte_streaming(stream: &[u8], expected: &[u8]) {
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut produced = Vec::new();
        let mut in_pos = 0;
        let mut obuf = [0u8; 1];
        loop {
            let inb = if in_pos < stream.len() {
                &stream[in_pos..in_pos + 1]
            } else {
                &[][..]
            };
            let (p, st) = dec.decode(inb, &mut obuf).expect("decode");
            in_pos += p.consumed;
            if p.written == 1 {
                produced.push(obuf[0]);
            }
            match st {
                Status::StreamEnd => break,
                _ => {
                    if p.consumed == 0 && p.written == 0 && in_pos >= stream.len() {
                        panic!("stalled before stream end");
                    }
                }
            }
        }
        assert_eq!(produced, expected);
    }

    fn roundtrip(data: &[u8], chunks: &[(&[u8], bool)]) {
        let stream = build_stream(chunks);
        let got = decode_all(&stream, data.len()).expect("decode_all");
        assert_eq!(got, data, "bulk decode mismatch");
        decode_byte_streaming(&stream, data);
    }

    #[test]
    fn empty_stream() {
        // Just the end marker.
        let stream = vec![0x00u8];
        let got = decode_all(&stream, 0).unwrap();
        assert!(got.is_empty());
        decode_byte_streaming(&stream, &[]);
    }

    #[test]
    fn single_compressed_chunk() {
        let data = b"hello hello hello world, the quick brown fox jumps over hello";
        roundtrip(data, &[(data, true)]);
    }

    #[test]
    fn single_uncompressed_chunk() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        roundtrip(&data, &[(&data, false)]);
    }

    #[test]
    fn multi_chunk_with_dict_resets() {
        // Each compressed chunk is a full-reset chunk (its own dictionary).
        let a = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA repeated".to_vec();
        let b: Vec<u8> = (0u8..200).flat_map(|i| [i, i.wrapping_mul(3)]).collect();
        let c = b"trailing tail chunk with some words words words words".to_vec();
        let mut full = Vec::new();
        full.extend_from_slice(&a);
        full.extend_from_slice(&b);
        full.extend_from_slice(&c);
        roundtrip(&full, &[(&a, true), (&b, false), (&c, true)]);
    }

    #[test]
    fn large_compressible_chunk() {
        // 60 KiB highly compressible.
        let data = vec![0x5Au8; 60 * 1024];
        roundtrip(&data, &[(&data, true)]);
    }

    #[test]
    fn varied_inputs() {
        let cases: &[&[u8]] = &[
            b"a",
            b"ab",
            b"abcabcabcabcabcabc",
            &[0u8; 300],
            b"The quick brown fox jumps over the lazy dog. ",
        ];
        for case in cases {
            roundtrip(case, &[(case, true)]);
        }
    }

    #[test]
    fn truncated_stream_is_unexpected_end() {
        // A compressed chunk with no 0x00 terminator and clipped payload.
        let data = b"some payload bytes to compress here and there".to_vec();
        let mut stream = Vec::new();
        frame_compressed_chunk(&data, &mut stream);
        // Drop the trailing 0x00 and clip the last 3 compressed bytes.
        stream.truncate(stream.len() - 3);
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut out = vec![0u8; data.len() + 16];
        let mut consumed = 0;
        let mut written = 0;
        loop {
            let (p, st) = match dec.decode(&stream[consumed..], &mut out[written..]) {
                Ok(v) => v,
                Err(_) => return, // error on truncated payload is acceptable
            };
            consumed += p.consumed;
            written += p.written;
            if let Status::StreamEnd = st {
                panic!("truncated stream should not reach StreamEnd");
            }
            if consumed >= stream.len() {
                // Out of input without an end marker — finish must complain.
                assert_eq!(dec.finish(&mut out[written..]), Err(Error::UnexpectedEnd));
                return;
            }
        }
    }

    #[test]
    fn corrupt_control_byte() {
        // 0x7F is neither end (0x00), uncompressed (0x01/0x02), nor
        // compressed (>=0x80) — must be rejected.
        let stream = vec![0x7Fu8, 0, 0];
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut out = [0u8; 16];
        assert_eq!(dec.decode(&stream, &mut out), Err(Error::Corrupt));
    }

    #[test]
    fn first_chunk_must_reset_dict() {
        // A continuation compressed chunk (0x80) as the first chunk is illegal.
        let data = b"xyzzy".to_vec();
        let comp = encode_lzma_chunk(&data, TEST_DICT, EncoderParams::from_level(6));
        let mut stream = Vec::new();
        let uncomp_m1 = (data.len() - 1) as u32;
        let comp_m1 = (comp.len() - 1) as u32;
        stream.push(0x80 | ((uncomp_m1 >> 16) & 0x1F) as u8); // continuation
        stream.push(((uncomp_m1 >> 8) & 0xFF) as u8);
        stream.push((uncomp_m1 & 0xFF) as u8);
        stream.push(((comp_m1 >> 8) & 0xFF) as u8);
        stream.push((comp_m1 & 0xFF) as u8);
        stream.extend_from_slice(&comp);
        stream.push(0x00);
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut out = [0u8; 64];
        assert_eq!(dec.decode(&stream, &mut out), Err(Error::Corrupt));
    }

    #[test]
    fn dict_prop_config() {
        // A valid dict-size code byte should size the window; round-trips.
        let data = b"property byte sizing test data here repeated repeated".to_vec();
        let stream = build_stream(&[(&data, true)]);
        let mut dec = Lzma2::decoder_with(DecoderConfig::with_dict_prop(18)); // ~ default-ish
        let mut out = vec![0u8; data.len() + 16];
        let (p, st) = dec.decode(&stream, &mut out).unwrap();
        assert_eq!(st, Status::StreamEnd);
        assert_eq!(&out[..p.written], &data[..]);
    }

    #[test]
    fn invalid_dict_prop_poisons() {
        // dict-size code > 40 is invalid → decoder poisoned → Corrupt.
        let mut dec = Lzma2::decoder_with(DecoderConfig::with_dict_prop(99));
        let mut out = [0u8; 16];
        assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Corrupt));
    }

    #[test]
    fn reset_reuses_decoder() {
        let data = b"reusable stream content content content".to_vec();
        let stream = build_stream(&[(&data, true)]);
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut out = vec![0u8; data.len() + 16];
        let (p1, st1) = dec.decode(&stream, &mut out).unwrap();
        assert_eq!(st1, Status::StreamEnd);
        assert_eq!(&out[..p1.written], &data[..]);
        dec.reset();
        let (p2, st2) = dec.decode(&stream, &mut out).unwrap();
        assert_eq!(st2, Status::StreamEnd);
        assert_eq!(&out[..p2.written], &data[..]);
    }
}
