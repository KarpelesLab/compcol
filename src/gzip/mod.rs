//! RFC 1952 gzip container around RFC 1951 deflate.
//!
//! Wire format:
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---== ... ==---+---+---+---+---+---+---+---+---+
//! |1F |8B |CM |FLG|    MTIME      |XFL|OS |  optional |    deflate    |    CRC-32     |   ISIZE   |
//! +---+---+---+---+---+---+---+---+---+---+---== ... ==---+---+---+---+---+---+---+---+---+
//! ```
//! Fixed 10-byte header followed by optional fields gated by FLG bits:
//!   FEXTRA (bit 2)   — 2-byte XLEN + XLEN bytes
//!   FNAME  (bit 3)   — NUL-terminated filename
//!   FCOMMENT (bit 4) — NUL-terminated comment
//!   FHCRC  (bit 1)   — 2-byte header CRC16 (low 16 bits of CRC-32)
//! Then deflate, then 8-byte trailer (little-endian CRC-32 of original data +
//! ISIZE = uncompressed length mod 2^32).
//!
//! v1 limitations:
//! - Decoder ignores MTIME/XFL/OS and any optional metadata; it parses but
//!   doesn't expose the filename or comment.
//! - Encoder always emits a minimal 10-byte header (FLG = 0); the XFL byte
//!   is filled in from [`EncoderConfig::level`] per RFC 1952 §2.3.1.
//! - Concatenated gzip members are not supported — decoder stops at the
//!   first member's trailer. Multi-member streams (RFC 1952 §2.2,
//!   produced by `gzip --concatenate`, `tar zcf` on partial files,
//!   `logrotate`, etc.) are now decoded — the decoder restarts at the
//!   header phase whenever it sees another `1F 8B` magic after a
//!   trailer.

use crate::checksum::Crc32;
use crate::deflate;
use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

const MAGIC_ID1: u8 = 0x1F;
const MAGIC_ID2: u8 = 0x8B;
const CM_DEFLATE: u8 = 0x08;

const FTEXT: u8 = 1 << 0;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
/// Mask of reserved FLG bits that, if set, mean the file uses an extension
/// we don't understand.
const FLG_RESERVED: u8 = !(FTEXT | FHCRC | FEXTRA | FNAME | FCOMMENT);

/// Tunables for the gzip encoder.
///
/// `level` is forwarded to the inner deflate encoder, and also surfaces in
/// the emitted gzip header's XFL (extra-flags) byte: per RFC 1952 §2.3.1,
/// XFL=2 advertises "maximum compression / slowest algorithm" (level 9),
/// XFL=4 advertises "fastest algorithm" (level 1), and any other level
/// uses XFL=0.
///
/// The default of `6` matches gzip(1) and zlib's default. Values outside
/// `1..=9` are clamped by the inner deflate encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `1..=9`. Higher = smaller output, slower encode.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
    }
}

/// Zero-sized marker type implementing [`Algorithm`] for gzip.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gzip;

impl Algorithm for Gzip {
    const NAME: &'static str = "gzip";
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

// ─── decoder ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Reading the 10-byte fixed header into `header_bytes`.
    FixedHeader,
    /// Reading XLEN (2 bytes LE) for the FEXTRA field.
    ExtraLen,
    /// Skipping `remaining` extra-data bytes.
    ExtraData,
    /// Skipping bytes of the filename until a NUL is seen.
    Name,
    /// Skipping bytes of the comment until a NUL is seen.
    Comment,
    /// Skipping the 2-byte header-CRC trailer (validation deferred — v1).
    HeaderCrc,
    /// Streaming the deflate payload.
    Deflate,
    /// Collecting the 8-byte trailer (CRC-32 + ISIZE, little-endian).
    Trailer,
    /// Previous member's trailer validated. RFC 1952 §2.2 allows
    /// concatenated members; the next input byte decides whether
    /// we restart at `FixedHeader` for another member or settle into
    /// `Done`. With no input available we stay here so `raw_finish`
    /// can declare success cleanly.
    BetweenMembers,
    /// All members consumed; nothing more to do.
    Done,
}

pub struct Decoder {
    inner: deflate::Decoder,
    crc: Crc32,
    isize_count: u32, // running uncompressed byte count (mod 2^32)
    header_bytes: [u8; 10],
    header_idx: u8,
    flg: u8,
    aux_idx: u8,        // index inside the current sub-phase
    aux_xlen: u16,      // FEXTRA length captured from the 2-byte XLEN
    aux_remaining: u32, // bytes left to skip in the current sub-phase
    trailer_carryover: alloc::vec::Vec<u8>,
    trailer_carryover_idx: usize,
    trailer: [u8; 8],
    trailer_idx: u8,
    phase: DecPhase,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            inner: deflate::Decoder::new(),
            crc: Crc32::new(),
            isize_count: 0,
            header_bytes: [0u8; 10],
            header_idx: 0,
            flg: 0,
            aux_idx: 0,
            aux_xlen: 0,
            aux_remaining: 0,
            trailer_carryover: alloc::vec::Vec::new(),
            trailer_carryover_idx: 0,
            trailer: [0u8; 8],
            trailer_idx: 0,
            phase: DecPhase::FixedHeader,
            poisoned: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    fn validate_fixed_header(&mut self) -> Result<(), Error> {
        let b = &self.header_bytes;
        if b[0] != MAGIC_ID1 || b[1] != MAGIC_ID2 {
            return Err(self.poison(Error::BadHeader));
        }
        if b[2] != CM_DEFLATE {
            return Err(self.poison(Error::Unsupported));
        }
        let flg = b[3];
        if flg & FLG_RESERVED != 0 {
            return Err(self.poison(Error::Unsupported));
        }
        self.flg = flg;
        Ok(())
    }

    /// Decide which sub-phase comes after `after`, based on the FLG bits.
    fn next_after(&self, after: DecPhase) -> DecPhase {
        // The optional fields appear in this fixed order:
        //   FEXTRA, FNAME, FCOMMENT, FHCRC.
        // For each candidate, only consider it if `after` is strictly before it.
        let order = [
            (DecPhase::FixedHeader, FEXTRA, DecPhase::ExtraLen),
            (DecPhase::ExtraData, FNAME, DecPhase::Name),
            (DecPhase::Name, FCOMMENT, DecPhase::Comment),
            (DecPhase::Comment, FHCRC, DecPhase::HeaderCrc),
        ];
        // `after` ranks the phases by progress.
        let after_rank = phase_rank(after);
        for &(predecessor, flag, candidate) in &order {
            if phase_rank(predecessor) >= after_rank && self.flg & flag != 0 {
                return candidate;
            }
        }
        DecPhase::Deflate
    }
}

/// Total ordering of optional-header phases by progress; used by
/// [`Decoder::next_after`] to skip flag bits whose field is already behind us.
fn phase_rank(p: DecPhase) -> u8 {
    match p {
        DecPhase::FixedHeader => 0,
        DecPhase::ExtraLen => 1,
        DecPhase::ExtraData => 2,
        DecPhase::Name => 3,
        DecPhase::Comment => 4,
        DecPhase::HeaderCrc => 5,
        DecPhase::Deflate => 6,
        DecPhase::Trailer => 7,
        DecPhase::BetweenMembers => 8,
        DecPhase::Done => 9,
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
                DecPhase::FixedHeader => {
                    while (self.header_idx as usize) < 10 && consumed < input.len() {
                        self.header_bytes[self.header_idx as usize] = input[consumed];
                        self.header_idx += 1;
                        consumed += 1;
                    }
                    if self.header_idx == 10 {
                        self.validate_fixed_header()?;
                        self.phase = self.next_after(DecPhase::FixedHeader);
                        self.aux_idx = 0;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::ExtraLen => {
                    // Read 2 little-endian bytes.
                    while self.aux_idx < 2 && consumed < input.len() {
                        let b = input[consumed];
                        consumed += 1;
                        if self.aux_idx == 0 {
                            self.aux_xlen = b as u16;
                        } else {
                            self.aux_xlen |= (b as u16) << 8;
                        }
                        self.aux_idx += 1;
                    }
                    if self.aux_idx == 2 {
                        self.aux_remaining = self.aux_xlen as u32;
                        self.phase = DecPhase::ExtraData;
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::ExtraData => {
                    while self.aux_remaining > 0 && consumed < input.len() {
                        consumed += 1;
                        self.aux_remaining -= 1;
                    }
                    if self.aux_remaining == 0 {
                        self.phase = self.next_after(DecPhase::ExtraData);
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Name => {
                    let mut found_nul = false;
                    while consumed < input.len() {
                        let b = input[consumed];
                        consumed += 1;
                        if b == 0 {
                            found_nul = true;
                            break;
                        }
                    }
                    if found_nul {
                        self.phase = self.next_after(DecPhase::Name);
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Comment => {
                    let mut found_nul = false;
                    while consumed < input.len() {
                        let b = input[consumed];
                        consumed += 1;
                        if b == 0 {
                            found_nul = true;
                            break;
                        }
                    }
                    if found_nul {
                        self.phase = self.next_after(DecPhase::Comment);
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::HeaderCrc => {
                    // Skip 2 bytes — we don't validate the header CRC in v1.
                    while self.aux_idx < 2 && consumed < input.len() {
                        consumed += 1;
                        self.aux_idx += 1;
                    }
                    if self.aux_idx == 2 {
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
                    let new_bytes = &output[before_written..written];
                    self.crc.update(new_bytes);
                    self.isize_count = self.isize_count.wrapping_add(new_bytes.len() as u32);

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
                    while self.trailer_idx < 8 {
                        let byte = if self.trailer_carryover_idx < self.trailer_carryover.len() {
                            let b = self.trailer_carryover[self.trailer_carryover_idx];
                            self.trailer_carryover_idx += 1;
                            b
                        } else if consumed < input.len() {
                            let b = input[consumed];
                            consumed += 1;
                            b
                        } else {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        };
                        self.trailer[self.trailer_idx as usize] = byte;
                        self.trailer_idx += 1;
                    }
                    let expected_crc = u32::from_le_bytes([
                        self.trailer[0],
                        self.trailer[1],
                        self.trailer[2],
                        self.trailer[3],
                    ]);
                    let expected_isize = u32::from_le_bytes([
                        self.trailer[4],
                        self.trailer[5],
                        self.trailer[6],
                        self.trailer[7],
                    ]);
                    if expected_crc != self.crc.finalize() {
                        return Err(self.poison(Error::ChecksumMismatch));
                    }
                    if expected_isize != self.isize_count {
                        return Err(self.poison(Error::TrailerMismatch));
                    }
                    // RFC 1952 §2.2: multiple members can be concatenated.
                    // Park in BetweenMembers; whether the next byte starts
                    // another member or signals end-of-stream is decided
                    // on the next iteration / call.
                    self.phase = DecPhase::BetweenMembers;
                }
                DecPhase::BetweenMembers => {
                    if consumed >= input.len() {
                        // No more bytes to inspect. Caller may either
                        // hand us another member's bytes in a follow-up
                        // call or call raw_finish to settle Done.
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let next = input[consumed];
                    if next == 0x1F {
                        // Another member follows. Reset per-member state
                        // (keep `inner` deflate decoder reusable via reset)
                        // and re-enter the header. The 0x1F byte itself
                        // stays in `input` to be consumed by the header
                        // phase below. We `continue` instead of falling
                        // through so the outer no-progress check at the
                        // bottom of the loop doesn't immediately return:
                        // the transition is real even though no byte was
                        // consumed yet.
                        self.inner.raw_reset();
                        self.crc.reset();
                        self.isize_count = 0;
                        self.header_idx = 0;
                        self.flg = 0;
                        self.aux_idx = 0;
                        self.aux_xlen = 0;
                        self.aux_remaining = 0;
                        self.trailer_carryover.clear();
                        self.trailer_carryover_idx = 0;
                        self.trailer_idx = 0;
                        self.phase = DecPhase::FixedHeader;
                        continue;
                    }
                    // Anything other than the gzip magic means the
                    // stream ended. Fall through to Done, which will
                    // silently swallow the trailing bytes — gzip(1)
                    // does the same (the input could be a concatenated
                    // gzip+something-else file, and decoders are
                    // expected to be permissive).
                    self.phase = DecPhase::Done;
                }
                DecPhase::Done => {
                    // Swallow any trailing bytes the caller still has
                    // in `input` so the bridge reports Status::InputEmpty
                    // rather than spinning on Status::OutputFull. The
                    // payload is finished; nothing here is meaningful.
                    consumed = input.len();
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
        let empty: [u8; 0] = [];
        let p = self.raw_decode(&empty, output)?;
        if matches!(self.phase, DecPhase::Done | DecPhase::BetweenMembers) {
            // BetweenMembers with no more input == stream ended cleanly.
            // Promote to Done so subsequent calls are idempotent.
            self.phase = DecPhase::Done;
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
        self.crc.reset();
        self.isize_count = 0;
        self.header_idx = 0;
        self.flg = 0;
        self.aux_idx = 0;
        self.aux_xlen = 0;
        self.aux_remaining = 0;
        self.trailer_carryover.clear();
        self.trailer_carryover_idx = 0;
        self.trailer_idx = 0;
        self.phase = DecPhase::FixedHeader;
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

/// Map a clamped 1..=9 compression level to gzip's XFL byte
/// (RFC 1952 §2.3.1):
///   - level 9 → 2 ("maximum compression, slowest algorithm")
///   - level 1 → 4 ("fastest algorithm")
///   - anything else → 0
fn xfl_for_level(level: u8) -> u8 {
    let level = level.clamp(1, 9);
    match level {
        9 => 2,
        1 => 4,
        _ => 0,
    }
}

/// Build the minimal 10-byte gzip header for a given compression level.
///
/// Bytes:
///   0,1: ID1, ID2 magic           (0x1F, 0x8B)
///   2:   CM = deflate             (0x08)
///   3:   FLG = 0 (no optional fields)
///   4..8: MTIME = 0 (no timestamp)
///   8:   XFL = derived from level
///   9:   OS = 0xFF (unknown)
fn build_header(level: u8) -> [u8; 10] {
    [
        MAGIC_ID1,
        MAGIC_ID2,
        CM_DEFLATE,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        xfl_for_level(level),
        0xFF,
    ]
}

pub struct Encoder {
    inner: deflate::Encoder,
    crc: Crc32,
    isize_count: u32,
    header: [u8; 10],
    header_idx: u8,
    trailer: [u8; 8],
    trailer_idx: u8,
    phase: EncPhase,
    /// Saved configuration so `reset` can rebuild the header and the inner
    /// deflate encoder with the same level.
    config: EncoderConfig,
}

impl Encoder {
    /// Build a gzip encoder at the default compression level (6).
    pub fn new() -> Self {
        Self::with_config(EncoderConfig::default())
    }

    /// Build a gzip encoder with the supplied configuration. The level is
    /// forwarded to the inner deflate encoder and surfaced in the emitted
    /// XFL header byte.
    pub fn with_config(config: EncoderConfig) -> Self {
        Self {
            inner: deflate::Encoder::with_config(deflate::EncoderConfig {
                level: config.level,
            }),
            crc: Crc32::new(),
            isize_count: 0,
            header: build_header(config.level),
            header_idx: 0,
            trailer: [0u8; 8],
            trailer_idx: 0,
            phase: EncPhase::Header,
            config,
        }
    }

    fn drain_header(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while (self.header_idx as usize) < self.header.len() && *written < output.len() {
            output[*written] = self.header[self.header_idx as usize];
            *written += 1;
            self.header_idx += 1;
        }
        self.header_idx as usize == self.header.len()
    }

    fn drain_trailer(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.trailer_idx < 8 && *written < output.len() {
            output[*written] = self.trailer[self.trailer_idx as usize];
            *written += 1;
            self.trailer_idx += 1;
        }
        self.trailer_idx == 8
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
        let before = consumed;
        let p = self
            .inner
            .raw_encode(&input[consumed..], &mut output[written..])?;
        consumed += p.consumed;
        written += p.written;
        let new = &input[before..before + p.consumed];
        self.crc.update(new);
        self.isize_count = self.isize_count.wrapping_add(new.len() as u32);

        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

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
                    let crc = self.crc.finalize();
                    let isz = self.isize_count;
                    self.trailer = [
                        (crc & 0xFF) as u8,
                        ((crc >> 8) & 0xFF) as u8,
                        ((crc >> 16) & 0xFF) as u8,
                        ((crc >> 24) & 0xFF) as u8,
                        (isz & 0xFF) as u8,
                        ((isz >> 8) & 0xFF) as u8,
                        ((isz >> 16) & 0xFF) as u8,
                        ((isz >> 24) & 0xFF) as u8,
                    ];
                    self.trailer_idx = 0;
                    self.phase = EncPhase::Trailer;
                    break;
                }
                if p.written == 0 {
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
        self.crc.reset();
        self.isize_count = 0;
        // Reset preserves configuration: rebuild the header from the saved
        // level so the next stream advertises the same XFL.
        self.header = build_header(self.config.level);
        self.header_idx = 0;
        self.trailer = [0u8; 8];
        self.trailer_idx = 0;
        self.phase = EncPhase::Header;
    }
}
