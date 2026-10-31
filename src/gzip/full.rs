//! The standard (heap-backed) build of the gzip container. Public items are
//! re-exported from `crate::gzip`.

use crate::checksum::Crc32;
use crate::deflate;
use crate::deflate::Strategy;
use crate::deflate::encoder::{FlushKind, flush_result};
use crate::error::Error;
use crate::traits::{Flush, Progress, RawDecoder, RawEncoder, RawProgress, Status};

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
/// XFL=4 advertises "fastest algorithm" (levels 0 and 1), and any other
/// level uses XFL=0.
///
/// The default of `6` matches gzip(1) and zlib's default. Level `0` stores
/// the data uncompressed; values above `9` act as `9`. For strategy, window
/// bits and memory level use [`Encoder::with_deflate_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Compression level in `0..=9` (`0` = stored blocks only). Higher =
    /// smaller output, slower encode.
    pub level: u8,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { level: 6 }
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
    /// Reading the 2-byte header CRC (FHCRC) and checking it.
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
    trailer: [u8; 8],
    trailer_idx: u8,
    /// CRC-32 of the current member's header bytes, for FHCRC.
    hcrc: Crc32,
    /// The FHCRC field as read so far.
    hcrc_field: [u8; 2],
    /// Decode concatenated members as one stream (default `true`).
    multi_member: bool,
    /// Set by [`Decoder::decode_block`] for the duration of the call.
    stop_at_block: bool,
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
            trailer: [0u8; 8],
            trailer_idx: 0,
            hcrc: Crc32::new(),
            hcrc_field: [0u8; 2],
            multi_member: true,
            stop_at_block: false,
            phase: DecPhase::FixedHeader,
            poisoned: false,
        }
    }

    /// Choose whether concatenated members (RFC 1952 §2.2, `cat a.gz
    /// b.gz`) decode as one stream. Default `true`, like `gzip -d`.
    ///
    /// With `false` the decoder stops after the first member, like
    /// zlib's `inflate` with `windowBits` 16+: `decode` returns
    /// `StreamEnd` as soon as the trailer is read and leaves every byte
    /// after it unconsumed, so the caller can tell exactly where the
    /// member ended. [`reset`](crate::Decoder::reset) keeps the setting.
    pub fn with_multi_member(mut self, multi_member: bool) -> Self {
        self.multi_member = multi_member;
        self
    }

    /// Like [`decode`](crate::Decoder::decode), but returns at deflate
    /// block boundaries, like zlib's `inflate(Z_BLOCK)`: once right after
    /// each member's header (before its first block), then after each
    /// block but the last. See [`deflate::Decoder::decode_block`].
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

    /// True when a member's header has been read and its deflate data sits
    /// at a block boundary (before the first block, or between two blocks).
    pub fn at_block_boundary(&self) -> bool {
        self.phase == DecPhase::Deflate && self.inner.at_block_boundary()
    }

    /// True once the header of the current member's final deflate block
    /// has been read.
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
            let initial_phase = self.phase;

            match self.phase {
                DecPhase::FixedHeader => {
                    while (self.header_idx as usize) < 10 && consumed < input.len() {
                        self.header_bytes[self.header_idx as usize] = input[consumed];
                        self.header_idx += 1;
                        consumed += 1;
                    }
                    if self.header_idx == 10 {
                        self.validate_fixed_header()?;
                        self.hcrc.update(&self.header_bytes);
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
                        self.hcrc.update(&[b]);
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
                    let take = (input.len() - consumed).min(self.aux_remaining as usize);
                    self.hcrc.update(&input[consumed..consumed + take]);
                    consumed += take;
                    self.aux_remaining -= take as u32;
                    if self.aux_remaining == 0 {
                        self.phase = self.next_after(DecPhase::ExtraData);
                        // ExtraLen leaves `aux_idx == 2`; HeaderCrc reuses the
                        // same counter, so reset it on the transition into the
                        // CRC-skip phase or the loop there would consume 0 bytes
                        // and feed the FHCRC field into the deflate decoder.
                        if self.phase == DecPhase::HeaderCrc {
                            self.aux_idx = 0;
                        }
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Name => {
                    let start = consumed;
                    let mut found_nul = false;
                    while consumed < input.len() {
                        let b = input[consumed];
                        consumed += 1;
                        if b == 0 {
                            found_nul = true;
                            break;
                        }
                    }
                    self.hcrc.update(&input[start..consumed]);
                    if found_nul {
                        self.phase = self.next_after(DecPhase::Name);
                        // See ExtraData arm: HeaderCrc shares `aux_idx`.
                        if self.phase == DecPhase::HeaderCrc {
                            self.aux_idx = 0;
                        }
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Comment => {
                    let start = consumed;
                    let mut found_nul = false;
                    while consumed < input.len() {
                        let b = input[consumed];
                        consumed += 1;
                        if b == 0 {
                            found_nul = true;
                            break;
                        }
                    }
                    self.hcrc.update(&input[start..consumed]);
                    if found_nul {
                        self.phase = self.next_after(DecPhase::Comment);
                        // See ExtraData arm: HeaderCrc shares `aux_idx`.
                        if self.phase == DecPhase::HeaderCrc {
                            self.aux_idx = 0;
                        }
                    } else {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::HeaderCrc => {
                    // RFC 1952 §2.3.1: the two least significant bytes
                    // of the CRC-32 of every header byte before it.
                    while self.aux_idx < 2 && consumed < input.len() {
                        self.hcrc_field[self.aux_idx as usize] = input[consumed];
                        consumed += 1;
                        self.aux_idx += 1;
                    }
                    if self.aux_idx == 2 {
                        if u16::from_le_bytes(self.hcrc_field) != self.hcrc.finalize() as u16 {
                            return Err(self.poison(Error::ChecksumMismatch));
                        }
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
                        // The deflate decoder leaves every byte after its
                        // final block unconsumed: the trailer follows.
                        self.phase = DecPhase::Trailer;
                    } else if (p.consumed == 0 && p.written == 0)
                        || (self.stop_at_block && self.inner.at_block_boundary())
                    {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Trailer => {
                    while self.trailer_idx < 8 {
                        let byte = if consumed < input.len() {
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
                    // on the next iteration / call. A single-member
                    // decoder ends here.
                    self.phase = if self.multi_member {
                        DecPhase::BetweenMembers
                    } else {
                        DecPhase::Done
                    };
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
                        self.trailer_idx = 0;
                        self.hcrc.reset();
                        self.phase = DecPhase::FixedHeader;
                        continue;
                    }
                    // Anything other than the gzip magic means the
                    // stream ended; the bytes are not ours (the input
                    // could be a gzip+something-else file — gzip(1)
                    // ignores such trailing garbage). Hand off to Done.
                    //
                    // `continue` is required: match arms do not fall
                    // through, so without it the no-progress check at the
                    // bottom of the loop returns first (this iteration
                    // consumed nothing) and the Done arm never runs.
                    self.phase = DecPhase::Done;
                    continue;
                }
                DecPhase::Done => {
                    // The stream is complete, and the bytes after it are
                    // known not to start another member: report the end so
                    // the bridge answers `StreamEnd`, as the `Decoder`
                    // contract requires once the trailer is consumed.
                    // Trailing bytes stay unconsumed so the caller can see
                    // where the gzip data stops.
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
            }

            // zlib's `Z_BLOCK` also stops right after the header.
            if self.stop_at_block
                && self.phase == DecPhase::Deflate
                && initial_phase != DecPhase::Deflate
            {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
            if consumed == initial_consumed
                && written == initial_written
                && self.phase == initial_phase
            {
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
        self.trailer_idx = 0;
        self.hcrc.reset();
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

/// Map a compression level (`0..=9`) and strategy to gzip's XFL byte
/// (RFC 1952 §2.3.1), the way zlib picks it:
///   - level 9 → 2 ("maximum compression, slowest algorithm")
///   - level 0 or 1, or the huffman-only / RLE / fixed strategies → 4
///     ("fastest algorithm")
///   - anything else → 0
fn xfl_for(level: u8, strategy: Strategy) -> u8 {
    if level >= 9 {
        2
    } else if level < 2
        || matches!(
            strategy,
            Strategy::HuffmanOnly | Strategy::Rle | Strategy::Fixed
        )
    {
        4
    } else {
        0
    }
}

/// Build the minimal 10-byte gzip header for a given XFL.
///
/// Bytes:
///   0,1: ID1, ID2 magic           (0x1F, 0x8B)
///   2:   CM = deflate             (0x08)
///   3:   FLG = 0 (no optional fields)
///   4..8: MTIME = 0 (no timestamp)
///   8:   XFL = derived from level
///   9:   OS = 0xFF (unknown)
fn build_header(xfl: u8) -> [u8; 10] {
    [
        MAGIC_ID1, MAGIC_ID2, CM_DEFLATE, 0x00, 0x00, 0x00, 0x00, 0x00, xfl, 0xFF,
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
        Self::with_deflate_config(deflate::EncoderConfig::default().with_level(config.level))
    }

    /// Build a gzip encoder from a full deflate configuration: level,
    /// strategy, memory level and window (`max_distance`, e.g. set with
    /// [`deflate::EncoderConfig::with_window_bits`]). gzip has no field for
    /// the window size and no preset dictionary.
    pub fn with_deflate_config(config: deflate::EncoderConfig) -> Self {
        let inner = deflate::Encoder::with_config(config);
        let (level, strategy) = inner.level_and_strategy();
        Self {
            inner,
            crc: Crc32::new(),
            isize_count: 0,
            header: build_header(xfl_for(level, strategy)),
            header_idx: 0,
            trailer: [0u8; 8],
            trailer_idx: 0,
            phase: EncPhase::Header,
        }
    }

    /// Change level and strategy mid-stream; see
    /// [`deflate::Encoder::set_params`]. XFL follows the change only if the
    /// header has not been written yet.
    pub fn set_params(&mut self, level: u8, strategy: Strategy) {
        self.inner.set_params(level, strategy);
        if self.header_idx == 0 {
            let (level, strategy) = self.inner.level_and_strategy();
            self.header = build_header(xfl_for(level, strategy));
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
        // The header (XFL) is configuration and is kept as is.
        self.header_idx = 0;
        self.trailer = [0u8; 8];
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

        // Drain the 10-byte gzip header first if it hasn't been written
        // yet, so a "flush before any encode" still produces a valid
        // gzip prefix in front of the deflate sync marker.
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
            // Trailer / Done — flushing after finish() is meaningless.
            return Err(Error::Corrupt);
        }

        let p = self.inner.raw_flush_kind(&mut output[written..], kind)?;
        written += p.written;
        Ok(RawProgress {
            consumed: 0,
            written,
            // Forward the deflate-layer flush-complete signal so the
            // bridge maps it to `Status::InputEmpty`. `done` here is the
            // flush-call-complete semantic, not stream-end — the gzip
            // CRC/ISIZE trailer is not emitted by flush.
            done: p.done,
        })
    }
}
