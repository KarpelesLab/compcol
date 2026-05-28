//! RAR 1.x (1995-1996) — building-block library, no end-to-end decoder.
//!
//! RAR 1.x is the original Roshal Archive format and was in active use for
//! roughly twelve months in 1995-1996 before RAR 2.0 displaced it. There is
//! **no published specification** for the 1.x compression algorithm: the
//! only surviving open-source reference is The Unarchiver / XADMaster's
//! `XADRAR15Handle.m` (LGPL 2.1+, copyright MacPaw Inc.), which is itself a
//! reverse engineering of the original DOS-era binary.
//!
//! ## What this module ships
//!
//! Per [`crate::traits::Algorithm`] + [`Encoder`] / [`Decoder`], the public
//! types you'd expect are all here, but the decoder **does not produce
//! decoded output** — see "What does not work" below.
//!
//! Internally the module ships the well-defined building blocks any RAR1
//! decoder needs:
//!
//! - `bits::BitReader` — MSB-first bit reader matching
//!   `XADRAR15Handle.m`'s `CSInputNextBit`/`CSInputNextBitString` consumption
//!   order (Huffman codes are flagged `shortestCodeIsZeros:YES`).
//! - `huffman::StaticHuffman` — canonical Huffman decoder. RAR1's
//!   Huffman trees are **all static** — they're never transmitted — so this
//!   takes pre-baked code-length arrays. Maximum code length is 12 bits;
//!   the alphabet size is a const generic so the same type covers the
//!   256-symbol length trees, the 257-symbol literal trees, and the small
//!   short-match selector tables.
//! - `window::Window` — 64 KiB LZSS sliding-window output buffer with
//!   literal / match emission primitives and a drain cursor for streaming.
//! - `lookup::LookupTable` — the self-adjusting 256-entry symbol cache
//!   used as `flagtable` / `literaltable` / `offsettable` in the reference
//!   implementation. Implements the reset / swap / rank-bump machinery
//!   described by the reverse-engineered notes.
//! - `offset_history::OffsetHistory` — the 4-deep ring of recent match
//!   offsets plus the `lastoffset` / `lastlength` registers used by the
//!   short-match selector branch.
//!
//! ## What does not work
//!
//! [`crate::Decoder::decode`] / [`crate::Decoder::finish`] return
//! [`Error::Unsupported`] on any non-empty input. The reason is
//! **the static Huffman code-length
//! tables**: RAR1 doesn't transmit them, so any working decoder has to
//! ship them. They are not public-domain data; the only published forms
//! known to us are inside LGPL'd reverse-engineered code (The Unarchiver)
//! or in RARLAB's source whose licence forbids reuse. This crate is
//! permissively licensed, so the tables haven't been reproduced here.
//!
//! What this means concretely:
//!
//! 1. The bit reader, Huffman decoder, LZSS window, lookup tables, and
//!    offset history are all production-quality and unit-tested.
//! 2. A future change that introduces the static tables (either by
//!    clean-room re-derivation, or by re-licensing under terms compatible
//!    with the LGPL source) can wire them straight into
//!    `huffman::StaticHuffman::from_lengths` and into a new `decode`
//!    state machine — no rebuilding required.
//! 3. Until then, there is no way to decode an actual RAR1 stream from
//!    bytes alone.
//!
//! ## Fixture famine
//!
//! Even if the decoder existed, exercising it is hard: RAR1 files
//! essentially do not exist on the open internet in 2026. The few surviving
//! samples are tied up in archive-history mirrors and shareware
//! collections that often pre-date the algorithm's actual deployment
//! window. The integration tests under `tests/rar1.rs` therefore cover
//! the [`Decoder`] / [`Encoder`] surface (constructor, name, `Unsupported`
//! semantics) plus the building blocks via unit tests in each submodule.
//!
//! ## Encoder
//!
//! Permanently unsupported. RARLAB's unRAR licence forbids using its
//! source code to reconstruct the compression algorithm, and there is no
//! clean-room encoder for RAR1 anywhere. The [`Encoder`] type returns
//! [`Error::Unsupported`] from every method.

mod bits;
mod huffman;
mod lookup;
mod offset_history;
mod window;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Zero-sized marker type implementing [`Algorithm`] for RAR1.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar1;

impl Algorithm for Rar1 {
    const NAME: &'static str = "rar1";
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

// ─── encoder ──────────────────────────────────────────────────────────────

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

// ─── decoder ──────────────────────────────────────────────────────────────

/// RAR1 decoder skeleton.
///
/// The decoder owns the building blocks needed for a real implementation
/// (bit reader, optional Huffman trees, 64 KiB window, lookup tables,
/// offset history) but no `decode` path is wired up — see the module-level
/// "What does not work" section.
///
/// `unpack_size` is the declared decompressed length, supplied by the RAR
/// container (the bytes-in-block header). It is recorded for symmetry with
/// other decoders in this crate that need it (e.g.
/// [`crate::quantum::Decoder`]) but, since `decode` is unimplemented, it
/// has no effect on observable output.
pub struct Decoder {
    /// Declared decompressed length, in bytes. `None` for a freshly
    /// constructed decoder where the caller hasn't supplied one yet —
    /// `decode` would return [`Error::Unsupported`] in either case for
    /// this build, so it's purely informational.
    unpack_size: Option<u64>,
    /// The streaming-bit reader. Currently unused outside unit tests but
    /// kept so the public types match what a real decoder will need.
    bit_reader: bits::BitReader,
    /// 64 KiB sliding window — same reason.
    #[allow(dead_code)]
    window: window::Window,
    /// `flagtable` analogue.
    #[allow(dead_code)]
    flagtable: lookup::LookupTable,
    /// `literaltable` analogue.
    #[allow(dead_code)]
    literaltable: lookup::LookupTable,
    /// `offsettable` analogue.
    #[allow(dead_code)]
    offsettable: lookup::LookupTable,
    /// Recent-offset ring.
    #[allow(dead_code)]
    offset_history: offset_history::OffsetHistory,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("rar1::Decoder")
            .field("unpack_size", &self.unpack_size)
            .field("bits_buffered", &self.bit_reader.bits_available())
            .finish()
    }
}

impl Decoder {
    /// Construct a decoder with no declared decompressed length. This is
    /// equivalent to calling [`Decoder::with_unpack_size`] with `0`.
    pub fn new() -> Self {
        Self {
            unpack_size: None,
            bit_reader: bits::BitReader::new(),
            window: window::Window::new(),
            // Match `XADRAR15Handle.m`'s `resetLZSSHandle` initial state:
            // `flagtable[i] = ((-i) & 0xff) << 8`, `literaltable[i] = i << 8`,
            // and `offsettable[i] = i << 8` (then re-initialised by
            // `ResetTable`, which is what `LookupTable::new` already
            // emulates). The exact rank-limit used by RAR1 is 32 (the size
            // of one group); see `lookup` module docs for the caveats.
            flagtable: lookup::LookupTable::new(lookup::LookupKind::Complement, 32),
            literaltable: lookup::LookupTable::new(lookup::LookupKind::Identity, 32),
            offsettable: lookup::LookupTable::new(lookup::LookupKind::Identity, 32),
            offset_history: offset_history::OffsetHistory::new(),
        }
    }

    /// Construct a decoder that knows the declared decompressed length up
    /// front. RAR1 itself transmits this in the container's per-file
    /// header — callers parsing a real archive would supply that value
    /// here.
    pub fn with_unpack_size(n: u64) -> Self {
        let mut d = Self::new();
        d.unpack_size = Some(n);
        d
    }

    /// The declared decompressed length, if one was supplied to
    /// [`Decoder::with_unpack_size`].
    pub fn unpack_size(&self) -> Option<u64> {
        self.unpack_size
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        // No work is possible without the static Huffman tables — see the
        // module-level docs. The trait contract permits a zero-progress
        // return when the codec genuinely cannot make progress on the
        // given input/output sizes, but here we cannot make progress on
        // *any* sizes: surface that as a clear error.
        //
        // Empty inputs are a degenerate "are you alive?" probe and should
        // not error.
        if input.is_empty() {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: false,
            });
        }
        Err(Error::Unsupported)
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        // A decoder that never produced any output and was never fed any
        // input may legitimately be "done" with zero work — but as soon
        // as the caller drove `decode` with real data they got
        // `Unsupported`, so by the time they reach `finish` they already
        // know what's going on. We mirror that here: report done only
        // when nothing has been fed.
        if self.bit_reader.bits_available() == 0 && self.window.in_flight() == 0 {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        Err(Error::Unsupported)
    }

    fn raw_reset(&mut self) {
        self.unpack_size = None;
        self.bit_reader.reset();
        self.window.reset();
        self.flagtable = lookup::LookupTable::new(lookup::LookupKind::Complement, 32);
        self.literaltable = lookup::LookupTable::new(lookup::LookupKind::Identity, 32);
        self.offsettable = lookup::LookupTable::new(lookup::LookupKind::Identity, 32);
        self.offset_history.reset();
    }
}
