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
//!
//! ## Encoder
//!
//! The [`Encoder`] produces the same raw LZMA2 chunk stream the decoder
//! consumes, reusing the shared `encode_lzma_chunk` range coder from
//! [`crate::xz`]'s internals — no LZMA re-implementation. Every chunk is a
//! full-reset chunk (control byte `0xE0` for compressed, `0x01` for
//! uncompressed) so each chunk is independently decodable; an uncompressed
//! chunk is emitted as a fallback whenever compression would expand the data.
//! The stream is terminated by a single `0x00` end-marker byte.
//!
//! ### Dictionary-size contract
//!
//! A raw LZMA2 stream carries **no** dictionary size in band — that value is
//! the 7z coder property the decoder receives out of band (via
//! [`DecoderConfig::with_dict_prop`] / [`DecoderConfig::with_dict_size`]).
//! The encoder bounds its match distances by a fixed 4 MiB dictionary (the
//! [`crate::xz`] default), so a decoder built with the default config — which
//! also uses a 4 MiB window — round-trips the output exactly. If you transport
//! this stream inside a 7z container, advertise a dictionary size of at least
//! 4 MiB in the coder property.

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

/// Raw LZMA2 stream codec (7-Zip coder id 21).
///
/// Both directions are implemented: the [`Encoder`] emits a raw LZMA2 chunk
/// stream (full-reset chunks + `0x00` end marker) bounded by a 4 MiB
/// dictionary, and the [`Decoder`] consumes that stream. The dictionary size
/// is out of band (see the [module docs](self#dictionary-size-contract)); a
/// default-config decoder round-trips the default-config encoder's output.
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
        Encoder::new()
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

// ─── encoder ──────────────────────────────────────────────────────────────

use crate::lzma2_internal::lzma2_encoder::{
    EncoderParams, LZMA2_PROPS_BYTE, Lzma2Chunk, Lzma2StreamEncoder,
};

/// Dictionary size (in bytes) the encoder advertises to the LZMA chunk
/// coder as the match-distance ceiling. Fixed at 4 MiB — the [`crate::xz`]
/// default — so a default-config [`Decoder`] (also 4 MiB) round-trips.
const ENC_DICT_SIZE: u32 = DEFAULT_DICT as u32;

/// Default compression level (mirrors xz-utils' and [`crate::xz`]'s default).
const ENC_DEFAULT_LEVEL: u8 = 6;

/// Maximum uncompressed bytes buffered per LZMA2 chunk. Capped at 65_536 so
/// both the uncompressed-chunk 16-bit size field and the compressed-chunk
/// size fields stay in range, matching the [`crate::xz`] encoder's cap and
/// bounding peak working-buffer memory.
const ENC_CHUNK_MAX: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    /// Buffering input; flushing a chunk when the buffer fills.
    Body,
    /// Draining a staged chunk from `pending`, then back to `Body`.
    DrainPending,
    /// (`finish` only) Flush any partial buffered chunk, then stage the
    /// `0x00` end marker.
    Finishing,
    /// (`finish` only) Draining the `0x00` end marker from `pending`.
    DrainEnd,
    /// All chunks plus the `0x00` end marker have been drained.
    Done,
}

/// Raw LZMA2 encoder.
///
/// Emits the raw LZMA2 chunk stream consumed by [`Decoder`] — a sequence of
/// full-reset chunks terminated by a single `0x00` end marker. There is **no**
/// `.xz` container (no stream magic, block header, index, or CRC); for that,
/// use [`crate::xz`]. Match distances are bounded by a fixed 4 MiB dictionary
/// that the decoder must be told about out of band (see the
/// [module docs](self#dictionary-size-contract)).
///
/// Each chunk is independently decodable: the encoder always full-resets
/// (dict + props + state) at the chunk boundary, emitting a compressed chunk
/// (control `0xE0`) when that shrinks the data and an uncompressed chunk
/// (control `0x01`) otherwise.
///
/// Note: unlike the former permanently-`Unsupported` stub (a unit struct),
/// the working encoder buffers state, so it is a normal struct and is no
/// longer `Copy` — construct it via [`Lzma2::encoder()`](crate::Algorithm).
pub struct Encoder {
    phase: EncPhase,
    /// Staged bytes for the current chunk (or end marker), drained to the
    /// caller from `pending[pending_idx..]`.
    pending: Vec<u8>,
    pending_idx: usize,
    /// Bounded-memory continuous-dictionary LZMA2 chunk encoder; emits framed
    /// chunks incrementally so the whole input is never accumulated. `None`
    /// until the first input byte arrives.
    stream: Option<Lzma2StreamEncoder>,
    /// Raw input pushed into `stream` but not yet consumed by an emitted chunk.
    /// Bounded by one chunk's worth, used to frame uncompressed-fallback chunks.
    staged_input: Vec<u8>,
    /// Set once `stream.finish()` has run, so a multi-call `finish` doesn't
    /// re-finish.
    stream_finished: bool,
    /// Level-derived match-finder tuning; preserved across `reset`.
    params: EncoderParams,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// Build an encoder at the default compression level (6).
    pub fn new() -> Self {
        Self {
            phase: EncPhase::Body,
            pending: Vec::new(),
            pending_idx: 0,
            stream: None,
            staged_input: Vec::new(),
            stream_finished: false,
            params: EncoderParams::from_level(ENC_DEFAULT_LEVEL),
        }
    }

    /// Lazily create the bounded-memory LZMA2 stream encoder on first use.
    fn stream(&mut self) -> &mut Lzma2StreamEncoder {
        self.stream
            .get_or_insert_with(|| Lzma2StreamEncoder::new(ENC_DICT_SIZE, self.params))
    }

    /// Push staged bytes from `pending[pending_idx..]` into `output`. Returns
    /// true once the buffer is fully drained.
    fn drain_pending(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.pending_idx < self.pending.len() && *written < output.len() {
            output[*written] = self.pending[self.pending_idx];
            *written += 1;
            self.pending_idx += 1;
        }
        if self.pending_idx >= self.pending.len() {
            self.pending.clear();
            self.pending_idx = 0;
            true
        } else {
            false
        }
    }

    /// Frame each produced LZMA2 chunk into `pending`, consuming the matching
    /// raw bytes from `staged_input` (needed for the uncompressed fallback).
    ///
    /// The chunks come from a single continuous, **bounded-memory** match-finder
    /// ([`Lzma2StreamEncoder`]): the first chunk resets the dictionary (`0xE0`
    /// compressed / `0x01` uncompressed) and every later chunk continues it
    /// (`0xC0` compressed / `0x02` uncompressed), so cross-chunk matches (up to
    /// the 4 MiB dictionary) are found, while peak memory stays `O(dict_size)`.
    /// The caller appends the `0x00` end marker afterwards.
    fn stage_chunks(&mut self, chunks: Vec<Lzma2Chunk>) {
        for chunk in chunks {
            let n = chunk.uncomp_len;
            debug_assert!(self.staged_input.len() >= n);
            let data: Vec<u8> = self.staged_input.drain(..n).collect();
            match chunk.body {
                Some(ref body) => {
                    self.stage_compressed_chunk(&data, body, chunk.reset_dict, chunk.reset_state)
                }
                None => self.stage_uncompressed_chunk(&data, chunk.reset_dict),
            }
        }
    }

    /// Stage a compressed chunk. The control byte selects the reset mode:
    ///
    /// * `0xE0` — first chunk: reset dictionary + props + state (props byte
    ///   follows).
    /// * `0xC0` — `reset_state` set, dictionary continues: reset props + state
    ///   (props byte follows). Used after an uncompressed chunk.
    /// * `0x80` — continuation: no reset, the model carries over from the
    ///   previous chunk. **No props byte.** This is the common case on
    ///   compressible data and is what keeps the adaptive model warm across
    ///   64 KiB chunk boundaries (native `xz` does the same).
    ///
    /// All three carry the top 5 bits of `uncomp_size-1` in the low bits, then
    /// a 2-byte `uncomp_size-1` BE remainder, a 2-byte `comp_size-1` BE, the
    /// 1-byte LZMA props (only when the control byte sets bit 6), then the
    /// range-coded body.
    fn stage_compressed_chunk(
        &mut self,
        data: &[u8],
        compressed: &[u8],
        reset_dict: bool,
        reset_state: bool,
    ) {
        // A compressed chunk's uncompressed span uses the 21-bit size field
        // (≤ 2 MiB); the compressed body must fit the 16-bit comp field.
        debug_assert!(!data.is_empty() && data.len() <= 1 << 21);
        debug_assert!(!compressed.is_empty() && compressed.len() <= 65_536);

        let uncomp_m1 = (data.len() - 1) as u32; // 0..=2^21-1
        // The top 5 bits of (uncomp_size - 1) live in the low bits of the
        // control byte (nonzero once a chunk exceeds 64 KiB); the reset mode is
        // the high 3 bits: 0xE0 / 0xC0 / 0x80.
        let base: u8 = if reset_dict {
            0xE0
        } else if reset_state {
            0xC0
        } else {
            0x80
        };
        let control: u8 = base | ((uncomp_m1 >> 16) & 0x1F) as u8;
        // Bit 6 (0x40) set ⇒ new props follow (0xE0/0xC0); a `0x80`
        // continuation reuses the props established by an earlier chunk.
        let has_props = control & 0x40 != 0;
        let comp_m1 = (compressed.len() - 1) as u16;

        self.pending
            .reserve(5 + has_props as usize + compressed.len());
        self.pending.push(control);
        self.pending.push(((uncomp_m1 >> 8) & 0xFF) as u8);
        self.pending.push((uncomp_m1 & 0xFF) as u8);
        self.pending.push((comp_m1 >> 8) as u8);
        self.pending.push((comp_m1 & 0xFF) as u8);
        if has_props {
            self.pending.push(LZMA2_PROPS_BYTE);
        }
        self.pending.extend_from_slice(compressed);
        self.pending_idx = 0;
    }

    /// Stage an uncompressed chunk: control `0x01` (dict reset) for the first
    /// chunk or `0x02` (dictionary continues) otherwise, a 2-byte `size-1` BE,
    /// then the raw bytes.
    fn stage_uncompressed_chunk(&mut self, data: &[u8], reset_dict: bool) {
        debug_assert!(!data.is_empty() && data.len() <= ENC_CHUNK_MAX);
        let control: u8 = if reset_dict { 0x01 } else { 0x02 };
        let size_m1 = (data.len() - 1) as u16;
        self.pending.reserve(3 + data.len());
        self.pending.push(control);
        self.pending.push((size_m1 >> 8) as u8);
        self.pending.push((size_m1 & 0xFF) as u8);
        self.pending.extend_from_slice(data);
        self.pending_idx = 0;
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Body => {
                    // Feed input into the bounded-memory streaming LZMA2 encoder
                    // and frame any chunks it emits, draining them to the caller
                    // as we go. The whole input is never accumulated — the
                    // dictionary is a sliding `~dict_size` window inside the
                    // stream encoder.
                    if self.pending_idx < self.pending.len() {
                        self.phase = EncPhase::DrainPending;
                    } else if consumed < input.len() {
                        let take = (input.len() - consumed).min(ENC_CHUNK_MAX);
                        let slice = &input[consumed..consumed + take];
                        self.staged_input.extend_from_slice(slice);
                        let chunks = self.stream().push(slice);
                        consumed += take;
                        if !chunks.is_empty() {
                            self.stage_chunks(chunks);
                        }
                        if self.pending_idx < self.pending.len() {
                            self.phase = EncPhase::DrainPending;
                        }
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::DrainPending => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Body;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                // `encode` never advances into the finish-only phases.
                EncPhase::Finishing | EncPhase::DrainEnd | EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        // `encode` leaves the encoder in `Body`/`DrainPending`; the first
        // `finish` call drives it through `Finishing` → `DrainEnd` → `Done`.
        if self.phase == EncPhase::Body || self.phase == EncPhase::DrainPending {
            // A `DrainPending` left over from `encode` still has chunk bytes
            // staged; drain those before flushing the tail.
            self.phase = EncPhase::Finishing;
        }

        loop {
            match self.phase {
                EncPhase::Finishing => {
                    if self.pending_idx < self.pending.len() {
                        // Drain a chunk staged during `encode` first.
                        if !self.drain_pending(output, &mut written) {
                            return Ok(RawProgress {
                                consumed: 0,
                                written,
                                done: false,
                            });
                        }
                    }
                    if self.stream.is_some() && !self.stream_finished {
                        // Flush the remaining buffered bytes as the final
                        // chunk(s) from the bounded-memory stream encoder, then
                        // frame them. Memory stays `O(dict_size)`.
                        let chunks = self.stream().finish();
                        self.stream_finished = true;
                        self.stage_chunks(chunks);
                        // Stay in `Finishing`; the loop drains the staged chunks
                        // then emits the end marker.
                    } else {
                        // All chunks drained: emit the single 0x00 end marker.
                        self.pending.push(0x00);
                        self.pending_idx = 0;
                        self.phase = EncPhase::DrainEnd;
                    }
                }
                EncPhase::DrainEnd => {
                    if self.drain_pending(output, &mut written) {
                        self.phase = EncPhase::Done;
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
                EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
                // Unreachable: normalized to `Finishing` above.
                EncPhase::Body | EncPhase::DrainPending => {
                    self.phase = EncPhase::Finishing;
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        let params = self.params;
        self.phase = EncPhase::Body;
        self.pending.clear();
        self.pending_idx = 0;
        self.stream = None;
        self.staged_input.clear();
        self.stream_finished = false;
        self.params = params;
    }
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

    /// Feed raw uncompressed-chunk bytes into the LZMA2 dictionary so a later
    /// dictionary-continuing compressed chunk (`0xC0`) can reference them.
    /// Lazily creates `lzma_core` (canonical default props, sized to the
    /// configured dictionary) when the stream opens with an uncompressed chunk.
    fn feed_uncompressed_dict(&mut self, src: &[u8]) {
        if self.lzma_core.is_none() {
            let props = Lzma2Props::parse(LZMA2_PROPS_BYTE).unwrap_or(Lzma2Props {
                lc: 3,
                lp: 0,
                pb: 2,
            });
            self.lzma_core = Some(Box::new(LzmaCore::new(props, self.dict_size)));
        }
        if let Some(core) = self.lzma_core.as_mut() {
            core.append_literals(src);
        }
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
                        // dictionary-continuing compressed chunk (`0xC0`) can
                        // back-reference them. Lazily create the core (canonical
                        // default props — irrelevant for plain dict population,
                        // and replaced by the next compressed chunk's reset
                        // bits) when none exists yet, e.g. when the stream opens
                        // with an uncompressed chunk.
                        self.feed_uncompressed_dict(src);
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

    // ── encoder tests ─────────────────────────────────────────────────────

    use crate::traits::Encoder as _;

    /// Encode `data` with the raw LZMA2 [`Encoder`], driving the streaming
    /// API with the given output-buffer size to stress phase boundaries.
    fn encode_all(data: &[u8], out_chunk: usize) -> Vec<u8> {
        let mut enc = Lzma2::encoder_with(());
        let mut stream = Vec::new();
        let mut obuf = vec![0u8; out_chunk];
        let mut consumed = 0;
        loop {
            let (p, st) = enc.encode(&data[consumed..], &mut obuf).unwrap();
            stream.extend_from_slice(&obuf[..p.written]);
            consumed += p.consumed;
            match st {
                Status::InputEmpty => break,
                Status::OutputFull => {}
                Status::StreamEnd => unreachable!("encode never ends the stream"),
            }
        }
        loop {
            let (p, st) = enc.finish(&mut obuf).unwrap();
            stream.extend_from_slice(&obuf[..p.written]);
            if st == Status::StreamEnd {
                break;
            }
        }
        stream
    }

    /// Encode then decode `data`, asserting a byte-identical round-trip both
    /// in bulk and one byte at a time.
    fn enc_roundtrip(data: &[u8]) {
        for out_chunk in [4usize, 64, 4096, 1 << 17] {
            let stream = encode_all(data, out_chunk);
            // Last byte of a valid stream is always the 0x00 end marker.
            assert_eq!(stream.last().copied(), Some(0u8), "missing end marker");
            let got = decode_all(&stream, data.len()).expect("decode_all");
            assert_eq!(got, data, "bulk decode mismatch (out_chunk={out_chunk})");
        }
        // Stable framing → byte-streaming decode through every phase boundary.
        let stream = encode_all(data, 1 << 17);
        decode_byte_streaming(&stream, data);
    }

    #[test]
    fn enc_empty() {
        let stream = encode_all(&[], 16);
        assert_eq!(stream, vec![0x00]);
        assert!(decode_all(&stream, 0).unwrap().is_empty());
    }

    #[test]
    fn enc_one_byte() {
        enc_roundtrip(b"Z");
    }

    #[test]
    fn enc_small_text() {
        enc_roundtrip(b"hello hello hello world the quick brown fox hello hello");
    }

    #[test]
    fn enc_highly_compressible() {
        // Zeros: forces the compressed-chunk path; ratio must be large.
        let data = vec![0u8; 200 * 1024];
        let stream = encode_all(&data, 1 << 17);
        assert!(
            stream.len() < data.len() / 4,
            "zeros should compress hard, got {} from {}",
            stream.len(),
            data.len()
        );
        enc_roundtrip(&data);
    }

    #[test]
    fn enc_multi_chunk() {
        // > one 64 KiB chunk: several chunks plus the end marker.
        let data: Vec<u8> = (0u32..200_000)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        enc_roundtrip(&data);
    }

    #[test]
    fn enc_incompressible_falls_back() {
        // A pseudo-random, incompressible buffer forces uncompressed-chunk
        // fallback (control 0x01). Verify at least one such chunk appears.
        let mut data = vec![0u8; 4096];
        let mut x = 0x1234_5678u32;
        for b in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
        let stream = encode_all(&data, 1 << 17);
        assert_eq!(stream[0], 0x01, "expected uncompressed fallback chunk");
        enc_roundtrip(&data);
    }

    #[test]
    fn enc_reset_reuses_encoder() {
        let data = b"reusable encoder content content content".to_vec();
        let s1 = encode_all(&data, 1 << 17);
        let mut enc = Lzma2::encoder_with(());
        let mut obuf = vec![0u8; 1 << 17];
        let mut produce = |enc: &mut Encoder| {
            let mut out = Vec::new();
            let (p, _) = enc.encode(&data, &mut obuf).unwrap();
            out.extend_from_slice(&obuf[..p.written]);
            loop {
                let (p, st) = enc.finish(&mut obuf).unwrap();
                out.extend_from_slice(&obuf[..p.written]);
                if st == Status::StreamEnd {
                    break;
                }
            }
            out
        };
        let a = produce(&mut enc);
        enc.reset();
        let b = produce(&mut enc);
        assert_eq!(a, b);
        assert_eq!(a, s1, "reset output diverged from a fresh encoder");
        assert_eq!(decode_all(&a, data.len()).unwrap(), data);
    }
}
