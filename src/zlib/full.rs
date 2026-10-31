//! The standard (heap-backed) build of the zlib container. Public items are
//! re-exported from `crate::zlib`.

use alloc::vec::Vec;

use crate::checksum::Adler32;
use crate::deflate;
use crate::deflate::Strategy;
use crate::deflate::encoder::{FlushKind, flush_result};
use crate::error::Error;
use crate::traits::{Flush, Progress, RawDecoder, RawEncoder, RawProgress, Status};

/// CM=8 (deflate) in the low nibble of CMF.
const CM_DEFLATE: u8 = 0x08;
/// FDICT bit of FLG.
const FDICT: u8 = 0x20;

/// Tunables for the zlib encoder.
///
/// `level` controls the speed/ratio trade-off of the inner deflate encoder:
/// `0` stores the data uncompressed, `1` is the fastest compressing level and
/// `9` the slowest and smallest. The default of `6` mirrors zlib's default.
/// Values above `9` act as `9`.
///
/// For strategy, window bits, memory level and a preset dictionary, use
/// [`Encoder::with_deflate_config`] and [`Encoder::with_dictionary`].
///
/// The chosen level is also reflected in the zlib header's two-bit `FLEVEL`
/// field, per RFC 1950 §2.2:
/// - levels `0..=1`    → FLEVEL = 0 (fastest)
/// - levels `2..=5`    → FLEVEL = 1 (fast)
/// - level `6`         → FLEVEL = 2 (default)
/// - levels `7..=9`    → FLEVEL = 3 (maximum)
///
/// As in zlib, the huffman-only, RLE and fixed strategies also give FLEVEL 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `0..=9` (`0` = stored blocks only).
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Build the zlib header: CMF, FLG and, with a dictionary, the 4-byte
/// big-endian DICTID. Returns the bytes and how many of them are used.
///
/// FLG carries FLEVEL (from level and strategy, as zlib picks it), FDICT,
/// and the FCHECK bits that make `CMF*256 + FLG` a multiple of 31
/// (RFC 1950 §2.2).
fn header_bytes(
    level: u8,
    strategy: Strategy,
    window_bits: u8,
    dictid: Option<u32>,
) -> ([u8; 6], u8) {
    let flevel: u8 = if level < 2
        || matches!(
            strategy,
            Strategy::HuffmanOnly | Strategy::Rle | Strategy::Fixed
        ) {
        0
    } else {
        match level {
            2..=5 => 1,
            6 => 2,
            _ => 3, // 7..=9
        }
    };
    let cmf = ((window_bits - 8) << 4) | CM_DEFLATE;
    let fdict = if dictid.is_some() { FDICT } else { 0 };
    // FCHECK = -(CMF*256 + FLG without FCHECK) mod 31.
    let partial = ((cmf as u32) << 8) | ((flevel as u32) << 6) | fdict as u32;
    let fcheck = (31 - (partial % 31)) % 31;
    let flg = (flevel << 6) | fdict | (fcheck as u8);
    let mut out = [cmf, flg, 0, 0, 0, 0];
    match dictid {
        Some(id) => {
            out[2..].copy_from_slice(&id.to_be_bytes());
            (out, 6)
        }
        None => (out, 2),
    }
}

/// Configuration for the zlib decoder.
///
/// Carries an optional preset dictionary used when the stream's `FDICT`
/// bit is set (RFC 1950 §2.2). If `FDICT=1` the wire format includes a
/// 4-byte `DICTID` field — the Adler-32 of the dictionary — that the
/// decoder verifies against the configured dictionary; mismatch surfaces
/// as [`Error::ChecksumMismatch`]. Streams with `FDICT=0` ignore
/// `dictionary` entirely.
///
/// With an empty dictionary (the default), an `FDICT=1` stream stops with
/// [`Error::NeedDictionary`] once its `DICTID` is read; supply the
/// dictionary then with [`Decoder::set_dictionary`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Bytes to seed the underlying deflate window with when the stream's
    /// `FDICT` bit is set. Up to the last 32 KiB are retained.
    pub dictionary: Vec<u8>,
}

// ─── decoder ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Reading the 2-byte header.
    Header,
    /// FDICT=1: reading the 4-byte big-endian DICTID (Adler-32 of dict).
    DictId,
    /// FDICT=1 with no dictionary configured: waiting for
    /// [`Decoder::set_dictionary`].
    NeedDict,
    /// Streaming the deflate payload.
    Deflate,
    /// Collecting the 4-byte Adler-32 trailer.
    Trailer,
    /// Header/trailer validated; nothing more to consume.
    Done,
}

pub struct Decoder {
    inner: deflate::Decoder,
    adler: Adler32,
    header: [u8; 2],
    header_idx: u8,
    /// Caller-supplied preset dictionary. Empty when no dictionary was
    /// configured; populated by [`Decoder::with_config`]. Used to verify
    /// the on-wire `DICTID` when `FDICT=1` and to seed the underlying
    /// deflate window before the first block.
    dictionary: Vec<u8>,
    /// `DICTID` bytes collected when `FDICT=1`.
    dictid: [u8; 4],
    dictid_idx: u8,
    trailer: [u8; 4],
    trailer_idx: u8,
    phase: DecPhase,
    /// Set by [`Decoder::decode_block`] for the duration of the call.
    stop_at_block: bool,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            inner: deflate::Decoder::new(),
            adler: Adler32::new(),
            header: [0u8; 2],
            header_idx: 0,
            dictionary: Vec::new(),
            dictid: [0u8; 4],
            dictid_idx: 0,
            trailer: [0u8; 4],
            trailer_idx: 0,
            phase: DecPhase::Header,
            stop_at_block: false,
            poisoned: false,
        }
    }

    /// Build a zlib decoder with the given [`DecoderConfig`]. The
    /// dictionary is held until the on-wire `FDICT` bit is parsed; if
    /// `FDICT=1` and its Adler-32 matches the on-wire `DICTID`, the
    /// underlying deflate window is seeded with it.
    pub fn with_config(config: DecoderConfig) -> Self {
        let mut d = Self::new();
        d.dictionary = config.dictionary;
        d
    }

    /// The stream's `DICTID` (the Adler-32 of its preset dictionary), once
    /// the header has been read and has `FDICT` set; `None` otherwise.
    pub fn dictionary_id(&self) -> Option<u32> {
        if self.dictid_idx == 4 {
            Some(u32::from_be_bytes(self.dictid))
        } else {
            None
        }
    }

    /// True while the decoder waits for [`set_dictionary`](Self::set_dictionary):
    /// the stream has `FDICT` set, its `DICTID` has been read and no
    /// dictionary was configured. Calls to `decode` or `finish` return
    /// [`Error::NeedDictionary`] until then.
    pub fn needs_dictionary(&self) -> bool {
        self.phase == DecPhase::NeedDict
    }

    /// Supply the preset dictionary an `FDICT` stream asked for, like
    /// zlib's `inflateSetDictionary`, then carry on decoding.
    ///
    /// Only valid while [`needs_dictionary`](Self::needs_dictionary) is
    /// true; otherwise returns [`Error::Unsupported`]. A dictionary whose
    /// Adler-32 is not the stream's `DICTID` is refused with
    /// [`Error::ChecksumMismatch`], and the decoder keeps waiting for the
    /// right one.
    pub fn set_dictionary(&mut self, dictionary: &[u8]) -> Result<(), Error> {
        if self.phase != DecPhase::NeedDict {
            return Err(Error::Unsupported);
        }
        if adler32(dictionary) != u32::from_be_bytes(self.dictid) {
            return Err(Error::ChecksumMismatch);
        }
        self.inner.load_dictionary(dictionary);
        self.phase = DecPhase::Deflate;
        Ok(())
    }

    /// Like [`decode`](crate::Decoder::decode), but returns at deflate
    /// block boundaries, like zlib's `inflate(Z_BLOCK)`: once right after
    /// the header (before the first block), then after each block but the
    /// last. See [`deflate::Decoder::decode_block`].
    pub fn decode_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(Progress, Status), Error> {
        self.stop_at_block = true;
        self.inner.set_stop_at_block(true);
        let r = crate::Decoder::decode(self, input, output);
        self.stop_at_block = false;
        self.inner.set_stop_at_block(false);
        r
    }

    /// True when the header has been read and the deflate data sits at a
    /// block boundary (before the first block, or between two blocks).
    pub fn at_block_boundary(&self) -> bool {
        self.phase == DecPhase::Deflate && self.inner.at_block_boundary()
    }

    /// True once the header of the final deflate block has been read.
    pub fn in_final_block(&self) -> bool {
        self.inner.in_final_block()
    }

    /// Bits of the deflate data taken from the input but not decoded yet;
    /// see [`deflate::Decoder::unused_bits`]. 0 outside the deflate data.
    pub fn unused_bits(&self) -> u32 {
        if self.phase == DecPhase::Deflate {
            self.inner.unused_bits()
        } else {
            0
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Validate the two header bytes we've collected. Returns the next
    /// phase to enter: [`DecPhase::DictId`] when `FDICT=1`, otherwise
    /// [`DecPhase::Deflate`].
    fn validate_header(&mut self) -> Result<DecPhase, Error> {
        let cmf = self.header[0];
        let flg = self.header[1];
        if cmf & 0x0F != 8 {
            return Err(self.poison(Error::Unsupported));
        }
        let total = ((cmf as u32) << 8) | (flg as u32);
        if !total.is_multiple_of(31) {
            return Err(self.poison(Error::BadHeader));
        }
        let fdict = (flg & 0x20) != 0;
        if fdict {
            Ok(DecPhase::DictId)
        } else {
            Ok(DecPhase::Deflate)
        }
    }

    /// With a configured dictionary, check it against the on-wire `DICTID`
    /// and seed the deflate window; without one, wait for
    /// [`set_dictionary`](Self::set_dictionary).
    fn after_dictid(&mut self) -> Result<DecPhase, Error> {
        if self.dictionary.is_empty() {
            return Ok(DecPhase::NeedDict);
        }
        if adler32(&self.dictionary) != u32::from_be_bytes(self.dictid) {
            return Err(self.poison(Error::ChecksumMismatch));
        }
        self.inner.load_dictionary(&self.dictionary);
        Ok(DecPhase::Deflate)
    }
}

fn adler32(data: &[u8]) -> u32 {
    let mut sum = Adler32::new();
    sum.update(data);
    sum.finalize()
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;
        let progress = |consumed, written, done| RawProgress {
            consumed,
            written,
            done,
        };

        loop {
            let initial_consumed = consumed;
            let initial_written = written;
            let initial_phase = self.phase;

            match self.phase {
                DecPhase::Header => {
                    while self.header_idx < 2 && consumed < input.len() {
                        self.header[self.header_idx as usize] = input[consumed];
                        self.header_idx += 1;
                        consumed += 1;
                    }
                    if self.header_idx == 2 {
                        self.phase = self.validate_header()?;
                    } else {
                        return Ok(progress(consumed, written, false));
                    }
                }
                DecPhase::DictId => {
                    while self.dictid_idx < 4 && consumed < input.len() {
                        self.dictid[self.dictid_idx as usize] = input[consumed];
                        self.dictid_idx += 1;
                        consumed += 1;
                    }
                    if self.dictid_idx == 4 {
                        self.phase = self.after_dictid()?;
                    } else {
                        return Ok(progress(consumed, written, false));
                    }
                }
                DecPhase::NeedDict => {
                    // Report the bytes taken so far first; the error comes
                    // from a call that consumes nothing, so no count is lost.
                    if consumed > 0 || written > 0 {
                        return Ok(progress(consumed, written, false));
                    }
                    return Err(Error::NeedDictionary);
                }
                DecPhase::Deflate => {
                    let before_written = written;
                    let p = self
                        .inner
                        .raw_decode(&input[consumed..], &mut output[written..])
                        .map_err(|e| self.poison(e))?;
                    consumed += p.consumed;
                    written += p.written;
                    self.adler.update(&output[before_written..written]);

                    if self.inner.is_complete() {
                        // The deflate decoder leaves every byte after its
                        // final block unconsumed: the trailer follows.
                        self.phase = DecPhase::Trailer;
                    } else if (p.consumed == 0 && p.written == 0)
                        || (self.stop_at_block && self.inner.at_block_boundary())
                    {
                        return Ok(progress(consumed, written, false));
                    }
                }
                DecPhase::Trailer => {
                    while self.trailer_idx < 4 && consumed < input.len() {
                        self.trailer[self.trailer_idx as usize] = input[consumed];
                        self.trailer_idx += 1;
                        consumed += 1;
                    }
                    if self.trailer_idx < 4 {
                        return Ok(progress(consumed, written, false));
                    }
                    let expected = u32::from_be_bytes(self.trailer);
                    if expected != self.adler.finalize() {
                        return Err(self.poison(Error::ChecksumMismatch));
                    }
                    self.phase = DecPhase::Done;
                }
                DecPhase::Done => {
                    // Report completion so the bridge maps this to
                    // `Status::StreamEnd`. Reporting `false` here left a
                    // stream with trailing bytes after the adler32 returning
                    // `OutputFull` with nothing consumed and nothing written,
                    // spinning any caller that loops until StreamEnd.
                    return Ok(progress(consumed, written, true));
                }
            }

            // zlib's `Z_BLOCK` also stops right after the header.
            if self.stop_at_block
                && self.phase == DecPhase::Deflate
                && initial_phase != DecPhase::Deflate
            {
                return Ok(progress(consumed, written, false));
            }
            if consumed == initial_consumed
                && written == initial_written
                && self.phase == initial_phase
            {
                return Ok(progress(
                    consumed,
                    written,
                    matches!(self.phase, DecPhase::Done),
                ));
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if self.phase == DecPhase::NeedDict {
            return Err(Error::NeedDictionary);
        }
        // Try to advance with empty input — useful when the caller fed all
        // bytes via decode() but didn't realise the trailer hadn't been
        // validated yet.
        let empty: [u8; 0] = [];
        let p = self.raw_decode(&empty, output)?;
        let done = matches!(self.phase, DecPhase::Done);
        // Output the deflate decoder still held, for want of room, is handed
        // out first; the caller comes back for the rest.
        if done || p.written > 0 {
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done,
            })
        } else {
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn raw_reset(&mut self) {
        self.inner.raw_reset();
        self.adler.reset();
        self.header_idx = 0;
        self.dictid_idx = 0;
        self.trailer_idx = 0;
        self.phase = DecPhase::Header;
        self.poisoned = false;
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    Header,
    Deflate,
    Trailer,
    Done,
}

pub struct Encoder {
    inner: deflate::Encoder,
    adler: Adler32,
    /// The header bytes (CMF, FLG, optional DICTID) we emit at the start of
    /// the stream; persisted across `reset` so configuration survives.
    header: [u8; 6],
    header_len: u8,
    header_idx: u8,
    /// Window bits for CINFO, from the deflate config's `max_distance`.
    window_bits: u8,
    /// Adler-32 of the preset dictionary, if one is set.
    dictid: Option<u32>,
    trailer: [u8; 4],
    trailer_idx: u8,
    phase: EncPhase,
}

impl Encoder {
    /// Build an encoder at the default compression level (6).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build an encoder with explicit configuration. `config.level` is
    /// passed to the inner deflate encoder (above 9 acts as 9); the zlib
    /// header's FLEVEL bits are set accordingly.
    pub fn with_config(config: EncoderConfig) -> Self {
        Self::with_deflate_config(deflate::EncoderConfig::default().with_level(config.level))
    }

    /// Build an encoder from a full deflate configuration: level, strategy,
    /// memory level and window (`max_distance`, e.g. set with
    /// [`deflate::EncoderConfig::with_window_bits`]). The header's CINFO
    /// is the smallest window (at least 512 bytes) that covers
    /// `max_distance`.
    pub fn with_deflate_config(config: deflate::EncoderConfig) -> Self {
        let window_bits = config.window_bits();
        let mut e = Self {
            inner: deflate::Encoder::with_config(config),
            adler: Adler32::new(),
            header: [0u8; 6],
            header_len: 2,
            header_idx: 0,
            window_bits,
            dictid: None,
            trailer: [0u8; 4],
            trailer_idx: 0,
            phase: EncPhase::Header,
        };
        e.rebuild_header();
        e
    }

    /// Use `dictionary` as a preset dictionary: sets FDICT and writes its
    /// Adler-32 as DICTID (RFC 1950), and lets matches refer into it. The
    /// decoder needs the same bytes ([`DecoderConfig::dictionary`]). An
    /// empty dictionary means none. Kept across resets; calling this resets
    /// the encoder, so do it before encoding.
    #[must_use]
    pub fn with_dictionary(mut self, dictionary: &[u8]) -> Self {
        self.dictid = if dictionary.is_empty() {
            None
        } else {
            let mut a = Adler32::new();
            a.update(dictionary);
            Some(a.finalize())
        };
        self.inner = self.inner.with_dictionary(dictionary);
        self.rebuild_header();
        self.raw_reset();
        self
    }

    /// Change level and strategy mid-stream; see
    /// [`deflate::Encoder::set_params`]. FLEVEL follows the change only if
    /// the header has not been written yet.
    pub fn set_params(&mut self, level: u8, strategy: Strategy) {
        self.inner.set_params(level, strategy);
        if self.header_idx == 0 {
            self.rebuild_header();
        }
    }

    /// zlib's `Z_PARTIAL_FLUSH`; see [`deflate::Encoder::flush_partial`].
    pub fn flush_partial(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        self.flush_kind(output, FlushKind::Partial)
            .map(flush_result)
    }

    /// zlib's `Z_BLOCK`; see [`deflate::Encoder::flush_block`].
    pub fn flush_block(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        self.flush_kind(output, FlushKind::Block).map(flush_result)
    }

    fn rebuild_header(&mut self) {
        let (level, strategy) = self.inner.level_and_strategy();
        let (header, len) = header_bytes(level, strategy, self.window_bits, self.dictid);
        self.header = header;
        self.header_len = len;
    }

    /// Push the header bytes one at a time as output room becomes available.
    /// Returns true if the header has been fully emitted.
    fn drain_header(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.header_idx < self.header_len && *written < output.len() {
            output[*written] = self.header[self.header_idx as usize];
            *written += 1;
            self.header_idx += 1;
        }
        self.header_idx == self.header_len
    }

    fn drain_trailer(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.trailer_idx < 4 && *written < output.len() {
            output[*written] = self.trailer[self.trailer_idx as usize];
            *written += 1;
            self.trailer_idx += 1;
        }
        self.trailer_idx == 4
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        // Header.
        if matches!(self.phase, EncPhase::Header) {
            if !self.drain_header(output, &mut written) {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
            self.phase = EncPhase::Deflate;
        }

        if !matches!(self.phase, EncPhase::Deflate) {
            return Err(Error::Corrupt);
        }

        // Pass-through to deflate, updating Adler-32 for each consumed byte.
        let before = consumed;
        let p = self
            .inner
            .raw_encode(&input[consumed..], &mut output[written..])?;
        consumed += p.consumed;
        written += p.written;
        self.adler.update(&input[before..before + p.consumed]);

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        // If finish is called before any encode, we still need to emit the header.
        if matches!(self.phase, EncPhase::Header) {
            if !self.drain_header(output, &mut written) {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            self.phase = EncPhase::Deflate;
        }

        if matches!(self.phase, EncPhase::Deflate) {
            loop {
                let p = self.inner.raw_finish(&mut output[written..])?;
                written += p.written;
                if p.done {
                    let adler = self.adler.finalize();
                    self.trailer = adler.to_be_bytes();
                    self.trailer_idx = 0;
                    self.phase = EncPhase::Trailer;
                    break;
                }
                if p.written == 0 {
                    // No output room and not done.
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
            }
        }

        if matches!(self.phase, EncPhase::Trailer) && self.drain_trailer(output, &mut written) {
            self.phase = EncPhase::Done;
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            });
        }

        if matches!(self.phase, EncPhase::Done) {
            return Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            });
        }

        Ok(RawProgress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn raw_reset(&mut self) {
        self.inner.raw_reset();
        self.adler.reset();
        self.header_idx = 0;
        self.trailer = [0u8; 4];
        self.trailer_idx = 0;
        self.phase = EncPhase::Header;
    }

    fn raw_flush(&mut self, output: &mut [u8], mode: Flush) -> Result<RawProgress, Error> {
        let kind = match mode {
            Flush::Sync => FlushKind::Sync,
            Flush::Full => FlushKind::Full,
        };
        self.flush_kind(output, kind)
    }
}

impl Encoder {
    fn flush_kind(&mut self, output: &mut [u8], kind: FlushKind) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        // Make sure the 2-byte header has been written before any deflate
        // output. A caller that flushes immediately after construction
        // still gets a valid zlib prefix; the deflate sync marker then
        // follows once it fits.
        if matches!(self.phase, EncPhase::Header) {
            if !self.drain_header(output, &mut written) {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            self.phase = EncPhase::Deflate;
        }

        if !matches!(self.phase, EncPhase::Deflate) {
            // Trailer / Done — flushing after finish() makes no sense.
            return Err(Error::Corrupt);
        }

        let p = self.inner.raw_flush_kind(&mut output[written..], kind)?;
        written += p.written;
        Ok(RawProgress {
            consumed: 0,
            written,
            // Forward the deflate-layer flush-complete signal upwards so
            // the bridge maps it to `Status::InputEmpty`. This is `done`
            // in the `raw_flush` sense (marker fully drained) — **not**
            // the stream-end sense; the zlib trailer is not emitted by
            // a flush.
            done: p.done,
        })
    }
}
