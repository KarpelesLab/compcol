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
//! ## Memory
//!
//! The streaming decoder's one large allocation is its window, of the
//! configured dictionary size at most (it is grown as output is produced,
//! so a stream costs the smaller of the dictionary size and its decoded
//! length). [`DecoderConfig::max_dict_size`] bounds it: with a dictionary
//! size above that limit — 128 MiB by default — `decode` and `finish` fail
//! with [`Error::Unsupported`] from the first call, rather than decode with
//! a smaller window and call a valid far match corrupt.
//!
//! ## Contiguous output
//!
//! [`Decoder`] implements [`ContiguousDecoder`]:
//! when the whole decoded stream goes into one buffer, that buffer is the
//! dictionary. Matches are copied within it, uncompressed chunks are copied
//! into it, and **no window is allocated** whatever dictionary size is
//! configured; what remains is the model (probability tables) and one
//! chunk's compressed bytes (at most 64 KiB). A dictionary reset is where
//! history starts anew: a match reaching before it — or further back than
//! the configured dictionary size — is rejected exactly as in the streaming
//! mode, so both modes accept the same streams and fail the others with the
//! same error.
//!
//! Nor does [`DecoderConfig::max_dict_size`] apply: that limit is a memory
//! budget for the window, and there is none here. Distances are bounded by
//! the configured dictionary size itself, up to the format's 4 GiB − 1.
//!
//! Using both conventions on one stream, or passing a `filled` that is not
//! the number of bytes the decoder has written, fails with
//! [`Error::Unsupported`] without disturbing the decoder.
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
//!
//! ### Flush
//!
//! [`Encoder::flush`](crate::Encoder::flush) encodes every byte given so far
//! into complete chunks and emits them without the `0x00` end marker, so a
//! decoder fed the bytes produced so far outputs all of it.
//! [`Flush::Sync`] keeps the dictionary and model;
//! [`Flush::Full`] makes the next chunk a dictionary
//! reset (`0xE0` / `0x01`), so nothing after the flush references data
//! before it.

#![cfg_attr(docsrs, doc(cfg(feature = "lzma2")))]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;
pub use crate::lzma2_internal::lzma2_decoder::{DEFAULT_MAX_DICT_SIZE, MAX_DICT_SIZE};
use crate::lzma2_internal::lzma2_decoder::{
    Lzma2Props, LzmaCore, OutputMode, effective_max_dict_size, lzma2_dict_size,
};
use crate::traits::{
    Algorithm, ContiguousDecoder, Flush, Progress, RawDecoder, RawEncoder, RawProgress, Status,
};

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
/// The dictionary-size code (the 7z coder property byte) sizes the LZ
/// window; with no code a 4 MiB dictionary is used. `expected_len` is
/// advisory only — the stream self-terminates on its `0x00` control byte.
///
/// `max_dict_size` is the memory budget of the streaming calls: a
/// dictionary size above it is refused with [`Error::Unsupported`]. It does
/// not apply to the [`ContiguousDecoder`] calls, which allocate no window
/// (see the [module docs](self#contiguous-output)).
///
/// The struct is `#[non_exhaustive]`: build it with [`DecoderConfig::new`]
/// (or `default()`) and the `with_*` methods.
///
/// ```
/// use compcol::lzma2::{Decoder, DecoderConfig};
///
/// // A 7z coder property declaring a 1 GiB dictionary (code 36), and the
/// // permission to allocate that much for it.
/// let cfg = DecoderConfig::with_dict_prop(36).with_max_dict_size(1 << 30);
/// let _dec = Decoder::new(cfg);
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DecoderConfig {
    /// The 7z LZMA2 coder property: a 1-byte dictionary-size code, decoded
    /// the same way the xz LZMA2 filter property is. `None` → 4 MiB
    /// (unless `dict_size` is set).
    pub dict_prop: Option<u8>,
    /// Explicit dictionary size in bytes, overriding `dict_prop` when set.
    /// Values below 4 KiB are treated as 4 KiB and values above the
    /// format's maximum (4 GiB − 1) as that.
    pub dict_size: Option<usize>,
    /// Advisory uncompressed length, if known. Not required for decoding.
    pub expected_len: Option<usize>,
    /// Largest dictionary size (in bytes) the streaming calls
    /// ([`Decoder::decode`](crate::Decoder::decode) /
    /// [`finish`](crate::Decoder::finish)) will keep a window for.
    /// Defaults to [`DEFAULT_MAX_DICT_SIZE`] (128 MiB). Values below 4 KiB
    /// are treated as 4 KiB and values above [`MAX_DICT_SIZE`] as
    /// [`MAX_DICT_SIZE`]. Not applied by the contiguous calls.
    pub max_dict_size: u64,
}

impl DecoderConfig {
    /// The default configuration: a 4 MiB dictionary and a
    /// [`DEFAULT_MAX_DICT_SIZE`] limit.
    pub const fn new() -> Self {
        Self {
            dict_prop: None,
            dict_size: None,
            expected_len: None,
            max_dict_size: DEFAULT_MAX_DICT_SIZE,
        }
    }

    /// Configure the decoder with the 7z coder property (dictionary-size
    /// code byte).
    pub fn with_dict_prop(byte: u8) -> Self {
        Self {
            dict_prop: Some(byte),
            ..Self::new()
        }
    }

    /// Configure the decoder with an explicit dictionary size in bytes
    /// (at least 4 KiB, at most the format's 4 GiB − 1). Use this when the
    /// dictionary size is known directly rather than as a code byte.
    pub fn with_dict_size(bytes: usize) -> Self {
        Self {
            dict_size: Some(bytes),
            ..Self::new()
        }
    }

    /// Allow the streaming calls a window of up to `bytes` bytes (see
    /// [`max_dict_size`](Self::max_dict_size)).
    pub const fn with_max_dict_size(mut self, bytes: u64) -> Self {
        self.max_dict_size = bytes;
        self
    }

    /// Add an advisory expected uncompressed length (not required to decode).
    pub fn with_len(mut self, n: usize) -> Self {
        self.expected_len = Some(n);
        self
    }
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self::new()
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

/// Resolve the configured dictionary size (in bytes): the stream's true
/// one, brought into what the format can express (4 KiB..=4 GiB − 1) but
/// not limited by any memory budget — that is `max_dict_size`'s job, and
/// only where a window is allocated. An explicit `dict_size` wins;
/// otherwise the property byte is decoded; otherwise the 4 MiB default is
/// used.
fn resolve_dict_size(cfg: &DecoderConfig) -> Result<usize, Error> {
    let raw = match (cfg.dict_size, cfg.dict_prop) {
        (Some(n), _) => n as u64,
        (None, Some(b)) => lzma2_dict_size(b)? as u64,
        (None, None) => DEFAULT_DICT as u64,
    };
    // (`u32::MAX` fits `usize` on every supported target.)
    Ok(raw.clamp(4096, u32::MAX as u64) as usize)
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

    /// Emit every byte given so far as complete LZMA2 chunks (no `0x00` end
    /// marker), so a decoder fed the bytes produced so far outputs all of it.
    /// [`Flush::Full`] also makes the next chunk a dictionary reset, so
    /// nothing after the flush references data before it.
    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        loop {
            match self.phase {
                EncPhase::Body => {
                    if self.pending_idx < self.pending.len() {
                        self.phase = EncPhase::DrainPending;
                        continue;
                    }
                    // Encode whatever the stream encoder still buffers. Once it
                    // has been drained this is a no-op, which ends the loop.
                    if let Some(stream) = self.stream.as_mut() {
                        let chunks = stream.flush();
                        if mode == Flush::Full {
                            stream.reset_dict();
                        }
                        self.stage_chunks(chunks);
                    }
                    if self.pending_idx < self.pending.len() {
                        self.phase = EncPhase::DrainPending;
                    } else {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: true,
                        });
                    }
                }
                EncPhase::DrainPending => {
                    if !self.drain_pending(output, &mut written) {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    self.phase = EncPhase::Body;
                }
                // `finish` has started: everything is already on its way out.
                EncPhase::Finishing | EncPhase::DrainEnd | EncPhase::Done => {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: true,
                    });
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
    /// Draining the decoded chunk to the caller (contiguous mode: decoding
    /// the buffered chunk straight into the caller's buffer).
    CompDrain,
    /// Saw the `0x00` end control; stream complete.
    Done,
}

/// Streaming raw LZMA2 decoder.
///
/// Drive through the [`Decoder`](crate::Decoder) trait (or
/// [`crate::io::DecoderReader`]). Self-terminates on the `0x00` control byte.
///
/// Also a [`ContiguousDecoder`]: see the
/// [module docs](self#contiguous-output).
pub struct Decoder {
    /// The stream's dictionary size: the distance bound in both modes, and
    /// the most the window of the streaming mode grows to.
    dict_size: usize,
    /// `dict_size` is over the configured `max_dict_size`: the streaming
    /// calls, which would need a window that large, return
    /// [`Error::Unsupported`]. (Kept by `reset`: it is configuration.)
    over_limit: bool,
    lzma_core: Option<Box<LzmaCore>>,
    phase: Phase,
    poisoned: bool,

    /// First chunk in the stream must perform a dictionary reset.
    expecting_first: bool,
    /// The next compressed chunk must carry a properties byte (control
    /// `0xC0..=0xFF`): set at the start of the stream and by every
    /// dictionary reset, cleared by a chunk that brings properties
    /// (liblzma's `need_properties`).
    need_props: bool,

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

    /// Streaming or contiguous output, whichever the stream was started
    /// with.
    mode: OutputMode,
    /// The last [`Self::run`] stopped for want of output room (rather than
    /// of input).
    out_blocked: bool,
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
            over_limit: dict_size as u64 > effective_max_dict_size(cfg.max_dict_size),
            lzma_core: None,
            phase: Phase::Control,
            poisoned,
            expecting_first: true,
            need_props: true,
            scratch: Vec::new(),
            scratch_want: 0,
            comp_ctrl: 0,
            comp_uncomp_size: 0,
            comp_size: 0,
            comp_buf: Vec::new(),
            comp_decoded: Vec::new(),
            comp_decoded_pos: 0,
            chunk_remaining: 0,
            mode: OutputMode::default(),
            out_blocked: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Apply the dictionary reset of an uncompressed `0x01` chunk. An
    /// existing core (probability tables and dictionary allocation) is
    /// reused: a 4-byte `0x01` chunk must not cost an allocation, let alone
    /// one of the whole dictionary. With no core yet (the stream opens with
    /// an uncompressed chunk) one is created with the canonical default
    /// props, which are irrelevant for plain dictionary population.
    fn reset_dict_for_uncompressed(&mut self) {
        match self.lzma_core.as_mut() {
            Some(core) => core.reset_dict(),
            None => {
                let props = Lzma2Props::parse(LZMA2_PROPS_BYTE).unwrap_or(Lzma2Props {
                    lc: 3,
                    lp: 0,
                    pb: 2,
                });
                self.lzma_core = Some(Box::new(LzmaCore::new(props, self.dict_size)));
            }
        }
    }

    /// Feed raw uncompressed-chunk bytes into the LZMA2 dictionary so a later
    /// dictionary-continuing compressed chunk (`0xC0`) can reference them.
    /// The core exists by then: the stream's first chunk resets the
    /// dictionary, which creates it.
    ///
    /// In contiguous mode the bytes are history where the caller has them,
    /// in the output buffer; the core is only told how many there are.
    fn feed_uncompressed_dict(&mut self, src: &[u8]) {
        if let Some(core) = self.lzma_core.as_mut() {
            if self.mode.is_contiguous() {
                core.append_contiguous(src.len());
            } else {
                core.append_literals(src);
            }
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

impl Decoder {
    /// The chunk state machine, shared by both output conventions. Decoded
    /// bytes are written from `output[start..]`; the returned `written` is
    /// the *absolute* position reached in `output`.
    ///
    /// In streaming mode `start` is 0 and `output` is whatever buffer the
    /// caller passed to this call. In contiguous mode `output` is the whole
    /// decoded stream so far and `start` the caller's `filled`: compressed
    /// chunks are then decoded straight into it and read their history
    /// from it. Sets `out_blocked` when it returns for want of room.
    fn run(&mut self, input: &[u8], output: &mut [u8], start: usize) -> Result<RawProgress, Error> {
        let contiguous = self.mode.is_contiguous();
        self.out_blocked = false;
        let mut consumed = 0usize;
        let mut written = start;

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
                            self.reset_dict_for_uncompressed();
                            // Whatever properties were in force do not
                            // survive a dictionary reset.
                            self.need_props = true;
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
                        // After a dictionary reset the chunk must bring
                        // new properties: 0xC0..=0xFF.
                        if control >= 0xC0 {
                            self.need_props = false;
                        } else if self.need_props {
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
                        // back-reference them.
                        self.feed_uncompressed_dict(src);
                        self.chunk_remaining -= take;
                        consumed += take;
                        written += take;
                    }
                    if self.chunk_remaining == 0 {
                        self.phase = Phase::Control;
                    } else {
                        self.out_blocked = consumed < input.len();
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
                    let core = match self.lzma_core.as_mut() {
                        Some(c) => c,
                        None => return Err(self.poison(Error::Corrupt)),
                    };
                    if contiguous {
                        // Decoded by `CompDrain`, into the caller's buffer.
                        if let Err(e) = core.init_range(&self.comp_buf) {
                            return Err(self.poison(e));
                        }
                        self.comp_decoded_pos = 0;
                        self.phase = Phase::CompDrain;
                        continue;
                    }
                    // Decode the whole chunk into comp_decoded.
                    self.comp_decoded.clear();
                    self.comp_decoded.resize(self.comp_uncomp_size, 0u8);
                    if let Err(e) = core.init_range(&self.comp_buf) {
                        return Err(self.poison(e));
                    }
                    if let Err(e) = core.decode_chunk(&self.comp_buf, &mut self.comp_decoded) {
                        return Err(self.poison(e));
                    }
                    self.comp_decoded_pos = 0;
                    self.phase = Phase::CompDrain;
                }
                Phase::CompDrain if contiguous => {
                    // `comp_decoded_pos` counts the chunk's bytes decoded so
                    // far. Whatever does not fit in `output` — possibly the
                    // rest of a match — is decoded by a later call, with a
                    // longer buffer.
                    let left = self.comp_uncomp_size - self.comp_decoded_pos;
                    let before = written;
                    let core = match self.lzma_core.as_mut() {
                        Some(c) => c,
                        None => return Err(self.poison(Error::Corrupt)),
                    };
                    let r = core.decode_contiguous(&self.comp_buf, output, &mut written, left, 0);
                    self.comp_decoded_pos += written - before;
                    if let Err(e) = r {
                        return Err(self.poison(e));
                    }
                    if self.comp_decoded_pos < self.comp_uncomp_size {
                        self.out_blocked = true;
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if let Err(e) = core.finish_chunk(&self.comp_buf) {
                        return Err(self.poison(e));
                    }
                    self.phase = Phase::Control;
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
                        self.out_blocked = true;
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
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // The window is this decoder's memory budget: refuse a stream
        // that needs more than the caller allowed, rather than decode it
        // with a smaller one and fail on the first match reaching further.
        if self.over_limit {
            return Err(Error::Unsupported);
        }
        self.mode.enter_streaming()?;
        self.run(input, output, 0)
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if self.over_limit {
            return Err(Error::Unsupported);
        }
        self.mode.enter_streaming()?;
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
        self.need_props = true;
        self.scratch.clear();
        self.scratch_want = 0;
        self.comp_ctrl = 0;
        self.comp_uncomp_size = 0;
        self.comp_size = 0;
        self.comp_buf.clear();
        self.comp_decoded.clear();
        self.comp_decoded_pos = 0;
        self.chunk_remaining = 0;
        self.mode = OutputMode::default();
        self.out_blocked = false;
    }
}

/// See the [module docs](self#contiguous-output).
///
/// [`DecoderConfig::max_dict_size`] is not applied here: no window is
/// allocated, so there is nothing for it to bound.
impl ContiguousDecoder for Decoder {
    fn decode_contiguous(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        filled: usize,
    ) -> Result<(Progress, Status), Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        self.mode.enter_contiguous(output.len(), filled)?;
        // Any error is final here: the caller cannot know how much of
        // `output` the failed call wrote, so nothing can follow it.
        let p = match self.run(input, output, filled) {
            Ok(p) => p,
            Err(e) => return Err(self.poison(e)),
        };
        let written = p.written - filled;
        self.mode.advance(written);
        let status = if p.done {
            Status::StreamEnd
        } else if self.out_blocked || p.consumed < input.len() {
            Status::OutputFull
        } else {
            Status::InputEmpty
        };
        Ok((
            Progress {
                consumed: p.consumed,
                written,
            },
            status,
        ))
    }

    fn finish_contiguous(
        &mut self,
        output: &mut [u8],
        filled: usize,
    ) -> Result<(Progress, Status), Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        self.mode.enter_contiguous(output.len(), filled)?;
        // A buffered chunk may still have output to give.
        let p = match self.run(&[], output, filled) {
            Ok(p) => p,
            Err(e) => return Err(self.poison(e)),
        };
        let written = p.written - filled;
        self.mode.advance(written);
        let status = if p.done {
            Status::StreamEnd
        } else if self.out_blocked || written > 0 {
            // More is waiting for room in `output`; or this call still
            // wrote something, which an error would throw away: the
            // truncation is reported by the next call, the first with
            // nothing to hand over.
            Status::OutputFull
        } else {
            // Self-terminating: no `0x00` control and no input left to find
            // it in is truncation.
            return Err(self.poison(Error::UnexpectedEnd));
        };
        Ok((
            Progress {
                consumed: 0,
                written,
            },
            status,
        ))
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

    /// Every `0x01` chunk used to drop the LZMA core and build a new one,
    /// allocating and zeroing the whole configured dictionary (24 MiB here)
    /// for each 4 bytes of input.
    #[test]
    fn dict_reset_chunks_do_not_reallocate_the_dictionary() {
        use crate::lzma2_internal::lzma2_decoder::test_stats;
        let mut s = Vec::new();
        for i in 0..2500u32 {
            s.extend_from_slice(&[0x01, 0x00, 0x00, i as u8]);
        }
        s.push(0x00);
        test_stats::reset();
        let mut dec = Decoder::new(DecoderConfig::with_dict_prop(25));
        let mut out = vec![0u8; 1 << 12];
        let (mut pos, mut total) = (0, 0);
        loop {
            let (p, st) = dec.decode(&s[pos..], &mut out).unwrap();
            pos += p.consumed;
            total += p.written;
            if st == Status::StreamEnd {
                break;
            }
            assert!(p.consumed != 0 || p.written != 0, "no progress");
        }
        assert_eq!(total, 2500);
        assert!(
            test_stats::cores_built() <= 1,
            "{}",
            test_stats::cores_built()
        );
        // 2500 bytes of output need nowhere near the declared 24 MiB.
        assert!(
            test_stats::dict_bytes() <= 1 << 16,
            "{}",
            test_stats::dict_bytes()
        );
    }

    /// In contiguous mode the caller's buffer is the dictionary: none is
    /// allocated, however large the one configured and however much is
    /// decoded — through compressed chunks and stored ones.
    #[test]
    fn contiguous_mode_allocates_no_dictionary() {
        use crate::lzma2_internal::lzma2_decoder::test_stats;
        let mut data: Vec<u8> = (0u32..200_000)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        let mut x = 0x1234_5678u32;
        for b in data[90_000..160_000].iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
        let stream = encode_all(&data, 1 << 17);
        assert!(
            stream.len() > 70_000,
            "expected the noise to be stored uncompressed"
        );
        // 30: a 128 MiB dictionary.
        let cfg = DecoderConfig::with_dict_prop(30);

        // The streaming mode keeps a window as large as what it decoded.
        test_stats::reset();
        let mut dec = Decoder::new(cfg);
        let mut out = vec![0u8; data.len() + 1];
        let (p, status) = dec.decode(&stream, &mut out).unwrap();
        assert_eq!(status, Status::StreamEnd);
        assert!(out[..p.written] == data);
        assert!(test_stats::dict_bytes() >= data.len() as u64);

        test_stats::reset();
        let mut dec = Decoder::new(cfg);
        let mut out = vec![0u8; data.len()];
        let (p, status) = dec.decode_contiguous(&stream, &mut out, 0).unwrap();
        assert_eq!((p.consumed, status), (stream.len(), Status::StreamEnd));
        assert!(out[..p.written] == data);
        assert_eq!(test_stats::dict_bytes(), 0);
        assert_eq!(test_stats::cores_built(), 1);
    }

    /// A dictionary size above 128 MiB used to be clamped to 128 MiB —
    /// window and distance bound alike, so that a valid match reaching
    /// further back was "corrupt". Now the configured size is the bound,
    /// and the window is a budget: over `max_dict_size` the streaming calls
    /// are `Unsupported`; with the limit raised they decode (the window
    /// growing with the output, not the configuration); and the contiguous
    /// calls, which have no window, decode under any limit.
    #[test]
    fn dictionary_size_is_a_budget_not_a_distance_clamp() {
        use crate::lzma2_internal::lzma2_decoder::test_stats;
        let data: Vec<u8> = (0u32..100_000)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        let stream = encode_all(&data, 1 << 17);
        let mut out = vec![0u8; data.len() + 1];
        // 31: 192 MiB; 36: 1 GiB; 40: 4 GiB − 1.
        let cases = [
            (DecoderConfig::with_dict_prop(31), 192u64 << 20),
            (DecoderConfig::with_dict_prop(36), 1 << 30),
            (DecoderConfig::with_dict_size(1 << 30), 1 << 30),
            (DecoderConfig::with_dict_prop(40), u32::MAX as u64),
            (DecoderConfig::with_dict_size(usize::MAX), u32::MAX as u64),
        ];
        for (cfg, size) in cases {
            // Refused from the first call on, and again after a reset.
            let mut dec = Decoder::new(cfg);
            assert_eq!(dec.decode(&stream, &mut out), Err(Error::Unsupported));
            assert_eq!(dec.finish(&mut out), Err(Error::Unsupported));
            dec.reset();
            assert_eq!(dec.decode(&stream, &mut out), Err(Error::Unsupported));
            let mut dec = Decoder::new(cfg.with_max_dict_size(size - 1));
            assert_eq!(dec.decode(&stream, &mut out), Err(Error::Unsupported));

            if size <= MAX_DICT_SIZE {
                test_stats::reset();
                let mut dec = Decoder::new(cfg.with_max_dict_size(size));
                let (p, status) = dec.decode(&stream, &mut out).unwrap();
                assert_eq!(status, Status::StreamEnd);
                assert!(out[..p.written] == data);
                // The window grew with the 100 kB decoded, no further.
                let grown = test_stats::dict_bytes();
                assert!(grown >= data.len() as u64 && grown <= 1 << 20, "{grown}");
                // The distance bound is the configured size.
                let core = dec.lzma_core.as_ref().unwrap();
                assert_eq!(core.dict_capacity() as u64, size);
            }

            // Contiguous: no window, so no limit — and the true bound.
            test_stats::reset();
            let mut dec = Decoder::new(cfg);
            let (p, status) = dec.decode_contiguous(&stream, &mut out, 0).unwrap();
            assert_eq!(status, Status::StreamEnd);
            assert!(out[..p.written] == data);
            assert_eq!(test_stats::dict_bytes(), 0);
            let core = dec.lzma_core.as_ref().unwrap();
            assert_eq!(core.dict_capacity() as u64, size);
        }

        // Exactly the default limit is still accepted; so is a limit
        // lowered to the dictionary's size.
        let mut dec = Decoder::new(DecoderConfig::with_dict_prop(30));
        let (p, _) = dec.decode(&stream, &mut out).unwrap();
        assert!(out[..p.written] == data);
        assert_eq!(
            DecoderConfig::default().max_dict_size,
            DEFAULT_MAX_DICT_SIZE
        );
        let cfg = DecoderConfig::with_dict_size(1 << 16).with_max_dict_size(1 << 16);
        let (p, _) = Decoder::new(cfg).decode(&stream, &mut out).unwrap();
        assert!(out[..p.written] == data);
        let cfg = DecoderConfig::with_dict_size(1 << 17).with_max_dict_size(1 << 16);
        assert_eq!(
            Decoder::new(cfg).decode(&stream, &mut out),
            Err(Error::Unsupported)
        );
    }
}
