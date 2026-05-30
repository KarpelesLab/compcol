//! BCJ branch-converter filters (from the public-domain LZMA SDK lineage,
//! as used by xz).
//!
//! These are *filters*, not compressors: a forward transform rewrites the
//! relative target operands of CALL/JUMP machine instructions into an
//! absolute form that is more compressible (many calls to the same target
//! become byte-identical), and the inverse transform restores the original
//! relative encoding. Output length always equals input length.
//!
//! A *converter* is parameterised by CPU architecture. Each architecture
//! knows the instruction encoding it cares about and the alignment at
//! which such instructions can appear. The transform is **stateful over a
//! running byte position** (`ip`, the address of the first byte in the
//! stream plus an optional start offset), because the relative→absolute
//! rewrite depends on where the instruction sits.
//!
//! ## Streaming
//!
//! The public [`Encoder`]/[`Decoder`] are driven through the crate's
//! 1-byte-in/1-byte-out streaming loop. To process one instruction that
//! may straddle a chunk boundary, the engine keeps a small bounded buffer
//! (`MAX_INSN` bytes) of input it has accepted but cannot yet fully
//! convert. Bytes are only emitted once they are past the region any
//! future instruction could still touch, so the result is independent of
//! how the input is chunked.
//!
//! ## Arithmetic
//!
//! The address math is modular by design (the instruction operands are
//! fixed-width little/big-endian fields that wrap). We use `wrapping_*`
//! ops throughout so that encode∘decode is the exact identity for every
//! input, including operands whose absolute form overflows the field —
//! overflow is the format's defined behaviour, not an error.
//!
//! ## Architectures
//!
//! [`BcjX86`], [`BcjArm`], [`BcjArmThumb`], [`BcjArm64`], [`BcjPpc`]
//! (big-endian), [`BcjSparc`], [`BcjIa64`], [`BcjRiscV`]. All are
//! implemented clean-room from the documented transforms; the LZMA SDK
//! filters are public domain.

#![cfg_attr(docsrs, doc(cfg(feature = "bcj")))]

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

mod arch;

pub use arch::{Arm, Arm64, ArmThumb, Ia64, Ppc, RiscV, Sparc, X86};

/// An architecture-specific branch converter.
///
/// Implementors are zero-sized. The engine calls [`convert`](BcjArch::convert)
/// with a slice of buffered input, the absolute position (`ip`) of that
/// slice's first byte, and whether we are encoding (relative→absolute) or
/// decoding (absolute→relative). The method rewrites operands in place and
/// returns how many bytes it fully processed; bytes after that may belong
/// to an instruction that is not yet completely buffered and are left for
/// the next call.
pub trait BcjArch {
    /// Stable lowercase filter name (`"bcj-x86"`, `"bcj-arm"`, …).
    const NAME: &'static str;
    /// Conventional file extension.
    const EXT: &'static str;
    /// Instruction alignment in bytes. The engine keeps the running `ip`
    /// aligned to this so `convert` always sees `data[0]` at an instruction
    /// boundary (x86 = 1, Thumb = 2, most RISC = 4, IA-64 = 16).
    const ALIGN: usize;
    /// Per-stream converter state. Most architectures are stateless within
    /// a buffer and use [`NoState`]; x86 carries a small running mask.
    type State: Default + Clone + core::fmt::Debug;

    /// Convert operands in `data` in place. `ip` is the absolute stream
    /// position of `data[0]`; `state` persists across calls for the whole
    /// stream. Returns the number of bytes whose transform is now
    /// **final** — guaranteed not to change if more bytes were appended
    /// after `data`. The remaining `data.len() - returned` bytes are an
    /// incomplete-instruction tail that the engine retains (raw) and
    /// retries once more input arrives.
    ///
    /// The engine only commits (`state` mutations + ip advance) for the
    /// returned prefix; the tail is reprocessed from raw next round, so the
    /// passed-in `state` must reflect only fully-committed bytes.
    fn convert(data: &mut [u8], ip: u32, encode: bool, state: &mut Self::State) -> usize;
}

/// The unit converter state used by every architecture except x86.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoState;

// Largest instruction/bundle any architecture buffers (IA-64 bundle = 16).
const MAX_INSN: usize = 16;

/// Configuration shared by every BCJ encoder/decoder: the absolute address
/// assigned to the first byte of the stream. xz uses a per-filter
/// `start_offset` for this; [`Default`] is 0.
#[derive(Debug, Clone, Copy, Default)]
pub struct Config {
    /// Absolute address of the first stream byte (the initial `ip`).
    pub start_offset: u32,
}

/// Engine shared by encoder and decoder; `ENCODE` picks the direction.
///
/// Pipeline: caller bytes → `hold` (raw, awaiting a complete instruction) →
/// [`convert`](BcjArch::convert) → `pending` (transformed, awaiting output
/// space) → caller `output`. Decoupling the two queues lets the filter run
/// in a 1-byte-in / 1-byte-out loop even though instructions are multi-byte
/// and must stay aligned: `ip` only advances when a full aligned chunk
/// moves from `hold` to `pending`, never per output byte.
#[derive(Debug, Clone)]
struct Bcj<A: BcjArch, const ENCODE: bool> {
    /// Raw, untransformed input bytes not yet converted. Bounded by
    /// `MAX_INSN`: once it reaches a full instruction window we convert.
    hold: Vec<u8>,
    /// Transformed bytes produced by `convert`, awaiting `output` space.
    pending: Vec<u8>,
    head: usize,
    /// Absolute position (`ip`) of `hold[0]` — always `A::ALIGN`-aligned
    /// relative to `start_ip` because only whole aligned chunks leave
    /// `hold`.
    ip: u32,
    /// Initial ip captured at construction so `reset` can restore it.
    start_ip: u32,
    /// Per-stream architecture state (e.g. x86's running mask).
    state: A::State,
    _arch: core::marker::PhantomData<A>,
}

impl<A: BcjArch, const ENCODE: bool> Bcj<A, ENCODE> {
    fn new(cfg: Config) -> Self {
        Self {
            hold: Vec::new(),
            pending: Vec::new(),
            head: 0,
            ip: cfg.start_offset,
            start_ip: cfg.start_offset,
            state: A::State::default(),
            _arch: core::marker::PhantomData,
        }
    }

    fn reset(&mut self) {
        self.hold.clear();
        self.pending.clear();
        self.head = 0;
        self.ip = self.start_ip;
        self.state = A::State::default();
    }

    fn drain_pending(&mut self, out: &mut [u8]) -> usize {
        let avail = self.pending.len() - self.head;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.pending[self.head..self.head + n]);
        self.head += n;
        if self.head == self.pending.len() {
            self.pending.clear();
            self.head = 0;
        }
        n
    }

    /// Convert as much of `hold` as is final into `pending`, advancing `ip`.
    /// `flush_tail` (final flush only) additionally moves any leftover raw
    /// tail — a partial trailing instruction `convert` could not handle —
    /// verbatim into `pending`, matching the SDK filters.
    fn convert_hold(&mut self, flush_tail: bool) {
        if !self.hold.is_empty() {
            let mut scratch = [0u8; MAX_INSN];
            let len = self.hold.len();
            scratch[..len].copy_from_slice(&self.hold);
            let processed = A::convert(&mut scratch[..len], self.ip, ENCODE, &mut self.state);
            debug_assert!(processed % A::ALIGN == 0 || A::ALIGN == 1);
            if processed > 0 {
                self.pending.extend_from_slice(&scratch[..processed]);
                self.hold.drain(..processed);
                self.ip = self.ip.wrapping_add(processed as u32);
            }
        }
        if flush_tail && !self.hold.is_empty() {
            // Emit the partial trailing instruction unchanged.
            let tail_len = self.hold.len();
            self.pending.extend_from_slice(&self.hold);
            self.hold.clear();
            self.ip = self.ip.wrapping_add(tail_len as u32);
        }
    }

    /// Core step driving both directions through the two-queue pipeline.
    fn step(&mut self, input: &[u8], output: &mut [u8], final_call: bool) -> (usize, usize, bool) {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            // 1. Drain already-converted output first.
            if self.head < self.pending.len() && written < output.len() {
                written += self.drain_pending(&mut output[written..]);
            }
            if written == output.len() && !output.is_empty() {
                // Output full; stop (more pending may remain for next call).
                if self.head < self.pending.len() {
                    break;
                }
            }

            // 2. Refill the raw hold buffer up to a full instruction window.
            let before = consumed;
            while self.hold.len() < MAX_INSN && consumed < input.len() {
                self.hold.push(input[consumed]);
                consumed += 1;
            }
            let refilled = consumed > before;

            // 3. Convert what we can. On a non-final call we only convert
            //    once `hold` is full (so a straddling instruction is
            //    complete); a partially-filled hold with input drained waits
            //    for the next chunk. On the final call we convert and flush
            //    the tail.
            if final_call {
                self.convert_hold(true);
            } else if self.hold.len() == MAX_INSN {
                self.convert_hold(false);
            }

            // 4. Drain freshly-produced output.
            if self.head < self.pending.len() && written < output.len() {
                written += self.drain_pending(&mut output[written..]);
            }

            // 5. Termination: no progress possible this round?
            let pending_left = self.head < self.pending.len();
            let can_make_pending =
                self.hold.len() == MAX_INSN || (final_call && !self.hold.is_empty());
            if !pending_left && !refilled && !can_make_pending {
                break;
            }
            if written == output.len() && !output.is_empty() && pending_left {
                break;
            }
            // Avoid spinning when output is zero-length and nothing drains.
            if output.is_empty() && !refilled {
                break;
            }
        }

        let done = final_call && self.hold.is_empty() && self.head >= self.pending.len();
        (consumed, written, done)
    }
}

// ─── per-architecture marker types ───────────────────────────────────────

/// Build the public marker type, its `Encoder`/`Decoder` newtypes, the
/// `Algorithm` impl, and the `RawEncoder`/`RawDecoder` bridges for one
/// architecture.
macro_rules! bcj_filter {
    ($(#[$m:meta])* $marker:ident, $arch:ty, $enc:ident, $dec:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $marker;

        #[doc = concat!("Streaming encoder for the `", stringify!($marker), "` filter.")]
        #[derive(Debug, Clone)]
        pub struct $enc(Bcj<$arch, true>);

        #[doc = concat!("Streaming decoder for the `", stringify!($marker), "` filter.")]
        #[derive(Debug, Clone)]
        pub struct $dec(Bcj<$arch, false>);

        impl $enc {
            /// Construct an encoder with the given configuration.
            pub fn new(cfg: Config) -> Self {
                Self(Bcj::new(cfg))
            }
        }
        impl $dec {
            /// Construct a decoder with the given configuration.
            pub fn new(cfg: Config) -> Self {
                Self(Bcj::new(cfg))
            }
        }

        impl Algorithm for $marker {
            const NAME: &'static str = <$arch as BcjArch>::NAME;
            type Encoder = $enc;
            type Decoder = $dec;
            type EncoderConfig = Config;
            type DecoderConfig = Config;
            fn encoder_with(cfg: Config) -> $enc {
                $enc::new(cfg)
            }
            fn decoder_with(cfg: Config) -> $dec {
                $dec::new(cfg)
            }
        }

        impl RawEncoder for $enc {
            fn raw_encode(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<RawProgress, Error> {
                let (consumed, written, _) = self.0.step(input, output, false);
                Ok(RawProgress { consumed, written, done: false })
            }
            fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
                let (_, written, done) = self.0.step(&[], output, true);
                Ok(RawProgress { consumed: 0, written, done })
            }
            fn raw_reset(&mut self) {
                self.0.reset();
            }
        }

        impl RawDecoder for $dec {
            fn raw_decode(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<RawProgress, Error> {
                let (consumed, written, _) = self.0.step(input, output, false);
                Ok(RawProgress { consumed, written, done: false })
            }
            fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
                let (_, written, done) = self.0.step(&[], output, true);
                Ok(RawProgress { consumed: 0, written, done })
            }
            fn raw_reset(&mut self) {
                self.0.reset();
            }
        }

        impl Default for $enc {
            fn default() -> Self {
                Self::new(Config::default())
            }
        }
        impl Default for $dec {
            fn default() -> Self {
                Self::new(Config::default())
            }
        }
    };
}

bcj_filter!(
    /// x86 BCJ filter (the classic E8/E9 CALL/JUMP converter).
    BcjX86, X86, X86Encoder, X86Decoder
);
bcj_filter!(
    /// 32-bit ARM BL converter.
    BcjArm, Arm, ArmEncoder, ArmDecoder
);
bcj_filter!(
    /// ARM Thumb BL/BLX converter.
    BcjArmThumb, ArmThumb, ArmThumbEncoder, ArmThumbDecoder
);
bcj_filter!(
    /// ARM64 (AArch64) BL/ADRP converter.
    BcjArm64, Arm64, Arm64Encoder, Arm64Decoder
);
bcj_filter!(
    /// PowerPC (big-endian) bl converter.
    BcjPpc, Ppc, PpcEncoder, PpcDecoder
);
bcj_filter!(
    /// SPARC CALL converter.
    BcjSparc, Sparc, SparcEncoder, SparcDecoder
);
bcj_filter!(
    /// IA-64 (Itanium) bundle converter.
    BcjIa64, Ia64, Ia64Encoder, Ia64Decoder
);
bcj_filter!(
    /// RISC-V converter (JAL / AUIPC+inst pairs).
    BcjRiscV, RiscV, RiscVEncoder, RiscVDecoder
);
