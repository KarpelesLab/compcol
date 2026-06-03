//! RFC 1950 zlib container around RFC 1951 deflate.
//!
//! Wire format:
//! ```text
//! +---+---+--- ... ---+---+---+---+---+
//! |CMF|FLG|  deflate  |   ADLER-32    |
//! +---+---+--- ... ---+---+---+---+---+
//! ```
//! - `CMF`: bits 0-3 = CM (8 = deflate), bits 4-7 = CINFO (`log2(WINDOW)-8`).
//! - `FLG`: bits 0-4 = FCHECK (chosen so `CMF*256 + FLG` is a multiple of 31),
//!   bit 5 = FDICT (must be 0 here), bits 6-7 = FLEVEL.
//! - 4-byte big-endian Adler-32 of the **uncompressed** data.

use alloc::vec::Vec;

use crate::checksum::Adler32;
use crate::deflate;
use crate::error::Error;
use crate::traits::{Algorithm, Flush, RawDecoder, RawEncoder, RawProgress};

/// CMF byte with CM=8 (deflate) and CINFO=7 (32 KiB window).
const HEADER_CMF: u8 = 0x78;

/// Tunables for the zlib encoder.
///
/// `level` controls the speed/ratio trade-off of the inner deflate encoder:
/// `1` is fastest and produces the largest output, `9` is slowest and produces
/// the smallest output. The default of `6` mirrors zlib's default. Values
/// outside `1..=9` are clamped at encoder construction time (matching
/// deflate's behaviour and zlib's `Z_BEST_*` snap-to-range semantics).
///
/// The chosen level is also reflected in the zlib header's two-bit `FLEVEL`
/// field, per RFC 1950 §2.2:
/// - level `1`         → FLEVEL = 0 (fastest)
/// - levels `2..=5`    → FLEVEL = 1 (fast)
/// - level `6`         → FLEVEL = 2 (default)
/// - levels `7..=9`    → FLEVEL = 3 (maximum)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Compute the two zlib header bytes for a given compression level.
///
/// Returns `(CMF, FLG)` where FLG is built from `FLEVEL << 6` plus the
/// FCHECK bits required to make `CMF*256 + FLG` divisible by 31 (RFC 1950
/// §2.2). FDICT is always 0.
fn header_bytes(level: u8) -> (u8, u8) {
    let level = level.clamp(1, 9);
    let flevel: u8 = match level {
        1 => 0,
        2..=5 => 1,
        6 => 2,
        _ => 3, // 7..=9
    };
    let cmf = HEADER_CMF;
    // FCHECK = -(CMF*256 + FLEVEL<<6) mod 31, packed into the low 5 bits of FLG.
    let partial = ((cmf as u32) << 8) | ((flevel as u32) << 6);
    let fcheck = (31 - (partial % 31)) % 31;
    let flg = (flevel << 6) | (fcheck as u8);
    (cmf, flg)
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
/// An empty dictionary (the default) preserves the older configless
/// behaviour: `FDICT=0` streams decode normally, `FDICT=1` streams error
/// out as [`Error::Unsupported`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Bytes to seed the underlying deflate window with when the stream's
    /// `FDICT` bit is set. Up to the last 32 KiB are retained.
    pub dictionary: Vec<u8>,
}

/// Zero-sized marker type implementing [`Algorithm`] for zlib.
#[derive(Debug, Clone, Copy, Default)]
pub struct Zlib;

impl Algorithm for Zlib {
    const NAME: &'static str = "zlib";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = DecoderConfig;

    fn encoder_with(c: Self::EncoderConfig) -> Encoder {
        Encoder::with_config(c)
    }
    fn decoder_with(c: Self::DecoderConfig) -> Decoder {
        Decoder::with_config(c)
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Reading the 2-byte header.
    Header,
    /// FDICT=1: reading the 4-byte big-endian DICTID (Adler-32 of dict).
    DictId,
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
    /// First trailer bytes recovered from the deflate decoder's bit-reader
    /// after the deflate stream ended.
    trailer_carryover: Vec<u8>,
    trailer_carryover_idx: usize,
    trailer: [u8; 4],
    trailer_idx: u8,
    phase: DecPhase,
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
            trailer_carryover: Vec::new(),
            trailer_carryover_idx: 0,
            trailer: [0u8; 4],
            trailer_idx: 0,
            phase: DecPhase::Header,
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
            if self.dictionary.is_empty() {
                // FDICT set but no dictionary was configured. Mirrors the
                // old behaviour where every FDICT=1 stream errored, just
                // worded more precisely.
                return Err(self.poison(Error::Unsupported));
            }
            Ok(DecPhase::DictId)
        } else {
            Ok(DecPhase::Deflate)
        }
    }

    /// Validate the on-wire `DICTID` against the configured dictionary's
    /// Adler-32 and, on match, seed the underlying deflate window.
    fn validate_dictid_and_seed(&mut self) -> Result<(), Error> {
        let on_wire = u32::from_be_bytes(self.dictid);
        let mut sum = Adler32::new();
        sum.update(&self.dictionary);
        if sum.finalize() != on_wire {
            return Err(self.poison(Error::ChecksumMismatch));
        }
        self.inner.load_dictionary(&self.dictionary);
        Ok(())
    }

    /// Pull the next trailer byte from the carry-over buffer or, if empty,
    /// from `input`. Returns `Some(byte_came_from_input)` on success
    /// (where the bool says whether the input slice was advanced),
    /// or `None` if neither source has a byte ready.
    fn next_trailer_byte(&mut self, input: &[u8], consumed: &mut usize) -> Option<bool> {
        if self.trailer_carryover_idx < self.trailer_carryover.len() {
            let b = self.trailer_carryover[self.trailer_carryover_idx];
            self.trailer_carryover_idx += 1;
            self.trailer[self.trailer_idx as usize] = b;
            self.trailer_idx += 1;
            Some(false)
        } else if *consumed < input.len() {
            self.trailer[self.trailer_idx as usize] = input[*consumed];
            *consumed += 1;
            self.trailer_idx += 1;
            Some(true)
        } else {
            None
        }
    }
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

        loop {
            let initial_consumed = consumed;
            let initial_written = written;

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
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::DictId => {
                    while self.dictid_idx < 4 && consumed < input.len() {
                        self.dictid[self.dictid_idx as usize] = input[consumed];
                        self.dictid_idx += 1;
                        consumed += 1;
                    }
                    if self.dictid_idx == 4 {
                        self.validate_dictid_and_seed()?;
                        self.phase = DecPhase::Deflate;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
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
                        self.trailer_carryover = self.inner.drain_trailing_bytes();
                        self.trailer_carryover_idx = 0;
                        self.phase = DecPhase::Trailer;
                    } else if p.consumed == 0 && p.written == 0 {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Trailer => {
                    while self.trailer_idx < 4 {
                        if self.next_trailer_byte(input, &mut consumed).is_none() {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                    }
                    let expected = u32::from_be_bytes(self.trailer);
                    if expected != self.adler.finalize() {
                        return Err(self.poison(Error::ChecksumMismatch));
                    }
                    self.phase = DecPhase::Done;
                }
                DecPhase::Done => {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == initial_consumed && written == initial_written {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // Try to advance with empty input — useful when the caller fed all
        // bytes via decode() but didn't realise the trailer hadn't been
        // validated yet.
        let empty: [u8; 0] = [];
        let p = self.raw_decode(&empty, output)?;
        if matches!(self.phase, DecPhase::Done) {
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: true,
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
        self.trailer_carryover.clear();
        self.trailer_carryover_idx = 0;
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
    /// The two header bytes (CMF, FLG) we emit at the start of the stream;
    /// derived from `config.level` at construction time and persisted across
    /// `reset` so configuration survives.
    header: [u8; 2],
    header_idx: u8,
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
    /// clamped to `1..=9` internally and propagated through to the inner
    /// deflate encoder; the zlib header's FLEVEL bits are set accordingly.
    pub fn with_config(config: EncoderConfig) -> Self {
        let (cmf, flg) = header_bytes(config.level);
        Self {
            inner: deflate::Encoder::with_config(deflate::EncoderConfig {
                level: config.level,
                ..deflate::EncoderConfig::default()
            }),
            adler: Adler32::new(),
            header: [cmf, flg],
            header_idx: 0,
            trailer: [0u8; 4],
            trailer_idx: 0,
            phase: EncPhase::Header,
        }
    }

    /// Push the 2 header bytes one at a time as output room becomes available.
    /// Returns true if the header has been fully emitted.
    fn drain_header(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.header_idx < 2 && *written < output.len() {
            output[*written] = self.header[self.header_idx as usize];
            *written += 1;
            self.header_idx += 1;
        }
        self.header_idx == 2
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

        let p = self.inner.raw_flush(&mut output[written..], mode)?;
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
