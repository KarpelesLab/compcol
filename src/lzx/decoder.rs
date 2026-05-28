//! Streaming LZX decoder.
//!
//! Implements [MS-PATCH] §2 (LZX DELTA Compression and Decompression),
//! restricted to the CAB profile: window sizes 15..=21, no DELTA-specific
//! extensions. All three block types — verbatim (1), aligned-offset (2),
//! and uncompressed (3) — are accepted.
//!
//! ## Stream framing
//!
//! Standard LZX is framed externally (CAB CFFOLDER, WIM resource header,
//! etc.). Since this crate is a stand-alone codec it adds the *minimal*
//! header documented in [`super`]:
//!
//! ```text
//! byte 0      : window_bits        (15..=21)
//! bytes 1..=4 : little-endian u32 of total uncompressed length
//! bytes 5..   : the LZX bitstream proper
//! ```
//!
//! When the uncompressed length is reached the decoder transitions to
//! `Done`; any trailing bits are tolerated.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decoder as DecoderTrait, Progress};

use super::bitreader::BitReader;
use super::huffman::LzxHuffman;
use super::tables::{
    ALIGNED_NUM_ELEMENTS, BLOCKTYPE_ALIGNED, BLOCKTYPE_UNCOMPRESSED, BLOCKTYPE_VERBATIM,
    EXTRA_BITS, FRAME_SIZE, MAIN_TREE_MAX, MAX_WINDOW_BITS, MIN_MATCH, MIN_WINDOW_BITS, NUM_CHARS,
    NUM_PRIMARY_LENGTHS, NUM_SECONDARY_LENGTHS, POSITION_BASE, PRETREE_NUM_ELEMENTS,
    main_tree_size,
};

// Maximum *encoded* block size (the 24-bit BLOCK_SIZE field). We use u32 for
// the remainder counter so any value fits.
const _: () = assert!(MAIN_TREE_MAX <= 656);

/// Streaming LZX decoder. See module docs for framing.
pub struct Decoder {
    state: DecState,
    poisoned: bool,
}

enum DecState {
    /// Awaiting the 1-byte window_bits + 4-byte LE uncompressed-length header.
    Header { buf: [u8; 5], have: u8 },
    /// Header parsed; running the LZX state machine.
    Running(Box<RunCtx>),
    /// Reached the declared uncompressed length; absorbing.
    Done,
}

struct RunCtx {
    bit_reader: BitReader,
    window_bits: u8,
    window: Vec<u8>,
    window_pos: usize,
    /// How many output bytes have actually been emitted so far.
    output_so_far: u64,
    /// Total uncompressed length declared in the header.
    output_total: u64,
    /// LZX header_read flag — false until the leading "intel translation"
    /// preamble bit (plus possible 32-bit filesize) has been consumed.
    header_read: bool,
    /// True iff the intel-translation post-filter is active for this stream.
    intel_started: bool,
    intel_filesize: u32,
    /// Current LRU repeat offsets.
    r0: u32,
    r1: u32,
    r2: u32,

    /// Per-block state.
    block: BlockState,

    /// Last-decoded MAIN_TREE / LENGTH_TREE / ALIGNED_TREE — survive across
    /// blocks (verbatim/aligned blocks may reuse the previous tree by
    /// emitting code lengths of zero for symbols they don't redefine).
    main_lens: Vec<u8>, // size = main_tree_size(window_bits)
    length_lens: [u8; NUM_SECONDARY_LENGTHS],
    aligned_lens: [u8; ALIGNED_NUM_ELEMENTS],

    main_tree: Option<Box<LzxHuffman<MAIN_TREE_MAX>>>,
    length_tree: Option<Box<LzxHuffman<NUM_SECONDARY_LENGTHS>>>,
    aligned_tree: Option<Box<LzxHuffman<ALIGNED_NUM_ELEMENTS>>>,

    /// Bytes still owed from the current frame before the E8 filter is
    /// applied. We buffer per-frame because the E8 transform is defined to
    /// happen across whole 32 KiB frames.
    frame_buf: Vec<u8>,
    /// Number of bytes from `frame_buf` already emitted to the caller.
    frame_emitted: usize,
}

enum BlockState {
    /// Need to read a new block header.
    AwaitBlockHeader,
    /// Block in progress.
    Verbatim {
        remaining: u32,
        ph: HuffPhase,
    },
    Aligned {
        remaining: u32,
        ph: HuffPhase,
    },
    /// Uncompressed block: align to word, read R0/R1/R2, then read raw bytes.
    UncompressedAlign {
        remaining: u32,
    },
    UncompressedRRR {
        remaining: u32,
        rrr_buf: [u8; 12],
        rrr_have: u8,
    },
    UncompressedData {
        remaining: u32,
        /// Whether `remaining` was originally odd → must consume a pad byte
        /// after the data is exhausted.
        original_was_odd: bool,
    },
    /// After an uncompressed block with odd `block_length`, swallow one pad
    /// byte.
    UncompressedPad,
}

/// Sub-state for verbatim / aligned-offset blocks while reading the headers
/// and individual match elements.
enum HuffPhase {
    /// Need to (re)build the block's Huffman trees from code-length data.
    BuildingTrees(Box<TreeBuild>),
    /// Trees ready — about to decode the next main-tree symbol.
    NextMain,
    /// Decoded a length-header == 7; need a length_tree symbol next.
    LengthFooter { pos_slot: u16 },
    /// Have length + position slot; need to read verbatim extra bits.
    VerbatimExtra { length: u16, pos_slot: u16 },
    /// Aligned block, slot with extra >= 3: need (extra-3) verbatim bits.
    AlignedHighBits {
        length: u16,
        pos_slot: u16,
        extra: u8,
    },
    /// Aligned block: need the 3-bit aligned-tree footer.
    AlignedFooter { length: u16, high_offset: u32 },
    /// Have a finished match — copy it into the window/frame.
    EmittingMatch { length: u16, distance: u32 },
    /// Pending literal that the caller hasn't drained yet.
    #[allow(dead_code)]
    PendingLiteral { byte: u8 },
}

/// While building MAIN_TREE / LENGTH_TREE / ALIGNED_TREE for a block we walk
/// through several sub-phases. This struct is heap-boxed to keep enum
/// variants small.
struct TreeBuild {
    #[allow(dead_code)]
    btype: u8,
    sub: TreeSub,
    /// For aligned blocks: the 8 ALIGNED_TREE lengths (3 bits each).
    aligned: [u8; ALIGNED_NUM_ELEMENTS],
    aligned_idx: u8,
    /// Pre-tree state for the current main/length pass.
    pretree_lens: [u8; PRETREE_NUM_ELEMENTS],
    pretree_idx: u8,
    pretree: Option<LzxHuffman<PRETREE_NUM_ELEMENTS>>,
    /// Cursor into the lens array currently being decoded.
    cursor: u16,
    /// End cursor (exclusive) for the current pass.
    end: u16,
    /// When a pretree symbol has multi-bit extra and we're waiting for them.
    pending: PendingPretree,
}

#[derive(Default, Clone, Copy)]
enum PendingPretree {
    #[default]
    None,
    /// Symbol 17 — need 4 extra bits, run of zeros = value+4.
    SeventeenExtra,
    /// Symbol 18 — need 5 extra bits, run of zeros = value+20.
    EighteenExtra,
    /// Symbol 19 — need 1 extra bit (run = value+4), then a second pretree
    /// symbol z, then `lens[x] = (prev_len - z) mod 17` for that run.
    NineteenExtra,
    /// Symbol 19, run length known, need a second pretree symbol.
    NineteenSecond { run: u8 },
}

#[derive(Clone, Copy)]
enum TreeSub {
    /// Aligned block only — read 8×3 bits for ALIGNED_TREE.
    AlignedTreeLens,
    /// Main tree pass 1: pretree for symbols 0..256.
    MainPretree1Lens,
    /// Main tree pass 1: decode pretree symbols into main_lens[0..256].
    MainPretree1Data,
    /// Main tree pass 2: pretree for symbols 256..main_tree_size.
    MainPretree2Lens,
    /// Main tree pass 2: decode pretree symbols into main_lens[256..].
    MainPretree2Data,
    /// Length tree: pretree for symbols 0..NUM_SECONDARY_LENGTHS.
    LengthPretreeLens,
    /// Length tree: decode pretree symbols into length_lens[..].
    LengthPretreeData,
    /// All trees built; transition out.
    Done,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            state: DecState::Header {
                buf: [0; 5],
                have: 0,
            },
            poisoned: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let progress_before = (consumed, written);
            match &mut self.state {
                DecState::Header { buf, have } => {
                    while (*have as usize) < buf.len() && consumed < input.len() {
                        buf[*have as usize] = input[consumed];
                        consumed += 1;
                        *have += 1;
                    }
                    if (*have as usize) < buf.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let window_bits = buf[0];
                    if !(MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&window_bits) {
                        return Err(self.poison(Error::Unsupported));
                    }
                    let total = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64;
                    let main_size = main_tree_size(window_bits);
                    let ctx = RunCtx {
                        bit_reader: BitReader::new(),
                        window_bits,
                        window: vec![0u8; 1usize << window_bits],
                        window_pos: 0,
                        output_so_far: 0,
                        output_total: total,
                        header_read: false,
                        intel_started: false,
                        intel_filesize: 0,
                        r0: 1,
                        r1: 1,
                        r2: 1,
                        block: BlockState::AwaitBlockHeader,
                        main_lens: vec![0u8; main_size],
                        length_lens: [0u8; NUM_SECONDARY_LENGTHS],
                        aligned_lens: [0u8; ALIGNED_NUM_ELEMENTS],
                        main_tree: None,
                        length_tree: None,
                        aligned_tree: None,
                        frame_buf: Vec::with_capacity(FRAME_SIZE),
                        frame_emitted: 0,
                    };
                    // Trivially-empty streams (total == 0) skip straight to Done
                    // without parsing a single block.
                    if ctx.output_total == 0 {
                        self.state = DecState::Done;
                    } else {
                        self.state = DecState::Running(Box::new(ctx));
                    }
                }

                DecState::Running(ctx) => {
                    // First, drain the existing frame buffer into the caller's
                    // output. This must happen before we attempt to refill the
                    // bit reader and decode more, because the decoder is
                    // permitted to stall while output is full.
                    if drain_frame(ctx, output, &mut written) {
                        // Frame fully drained — fall through to keep going.
                    }
                    if written == output.len() && ctx.frame_emitted < ctx.frame_buf.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if ctx.output_so_far == ctx.output_total {
                        self.state = DecState::Done;
                        continue;
                    }

                    // Refill the bit reader.
                    while ctx.bit_reader.can_accept_word() && consumed < input.len() {
                        ctx.bit_reader.feed(input[consumed]);
                        consumed += 1;
                    }

                    // Run the state machine — but only if we made progress or
                    // there is buffered work.
                    let res = step(ctx);
                    match res {
                        Ok(_) => {}
                        Err(e) => return Err(self.poison(e)),
                    }
                    // Drain any newly-finished frame bytes into output.
                    drain_frame(ctx, output, &mut written);

                    if ctx.output_so_far >= ctx.output_total
                        && ctx.frame_emitted == ctx.frame_buf.len()
                    {
                        self.state = DecState::Done;
                        continue;
                    }
                }

                DecState::Done => {
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            // Termination: no progress in this iteration, and not because we
            // were blocked waiting on more output — break and let the caller
            // supply more input.
            if (consumed, written) == progress_before {
                break;
            }
        }

        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;
        if let DecState::Running(ctx) = &mut self.state {
            drain_frame(ctx, output, &mut written);
            if ctx.output_so_far == ctx.output_total && ctx.frame_emitted == ctx.frame_buf.len() {
                self.state = DecState::Done;
            }
        }
        match &self.state {
            DecState::Done => Ok(Progress {
                consumed: 0,
                written,
                done: true,
            }),
            DecState::Header { have, .. } => {
                if *have == 0 {
                    // Empty stream — treat as Done.
                    self.state = DecState::Done;
                    Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    })
                } else {
                    Err(self.poison(Error::UnexpectedEnd))
                }
            }
            DecState::Running(_) => {
                if written == 0 {
                    Err(self.poison(Error::UnexpectedEnd))
                } else {
                    Ok(Progress {
                        consumed: 0,
                        written,
                        done: false,
                    })
                }
            }
        }
    }

    fn reset(&mut self) {
        self.state = DecState::Header {
            buf: [0; 5],
            have: 0,
        };
        self.poisoned = false;
    }
}

/// Drain finished frame bytes into the caller's output, never exceeding
/// the declared total uncompressed length. Returns `true` once the frame
/// buffer is fully drained.
fn drain_frame(ctx: &mut RunCtx, output: &mut [u8], written: &mut usize) -> bool {
    while ctx.frame_emitted < ctx.frame_buf.len() && *written < output.len() {
        let remaining_total = ctx.output_total.saturating_sub(ctx.output_so_far) as usize;
        if remaining_total == 0 {
            break;
        }
        let n = (ctx.frame_buf.len() - ctx.frame_emitted)
            .min(output.len() - *written)
            .min(remaining_total);
        output[*written..*written + n]
            .copy_from_slice(&ctx.frame_buf[ctx.frame_emitted..ctx.frame_emitted + n]);
        ctx.frame_emitted += n;
        *written += n;
        ctx.output_so_far += n as u64;
    }
    // Even when we don't pass them to the caller, we've still "consumed"
    // them from the bitstream — drop any trailing pad bytes inside the
    // frame buffer once the total cap is reached.
    if ctx.output_so_far >= ctx.output_total {
        ctx.frame_emitted = ctx.frame_buf.len();
    }
    if ctx.frame_emitted == ctx.frame_buf.len() && !ctx.frame_buf.is_empty() {
        ctx.frame_buf.clear();
        ctx.frame_emitted = 0;
        true
    } else {
        ctx.frame_buf.is_empty()
    }
}

/// Push a single byte into both the LZ sliding window and the current frame.
fn emit_window(ctx: &mut RunCtx, b: u8) {
    let win_size = ctx.window.len();
    ctx.window[ctx.window_pos] = b;
    ctx.window_pos = (ctx.window_pos + 1) % win_size;
    ctx.frame_buf.push(b);
}

/// Run one or more state-machine substeps. Returns Ok when progress is
/// blocked on more input or the frame buffer is full (callers re-enter).
fn step(ctx: &mut RunCtx) -> Result<(), Error> {
    loop {
        // Enforce frame boundary — once frame_buf hits FRAME_SIZE we must
        // apply the E8 filter (if active) and yield to the caller for drain.
        if ctx.frame_buf.len() >= FRAME_SIZE {
            apply_e8_to_frame(ctx);
            return Ok(());
        }
        if ctx.output_so_far + ctx.frame_buf.len() as u64 >= ctx.output_total {
            // Final partial frame — apply E8 (if active and large enough) and
            // hand back for drain.
            apply_e8_to_frame(ctx);
            return Ok(());
        }

        // ── one-time stream header ─────────────────────────────────────
        if !ctx.header_read {
            if ctx.bit_reader.bits_available() < 1 {
                return Ok(());
            }
            let flag = ctx.bit_reader.peek(1);
            ctx.bit_reader.drop_bits(1);
            if flag != 0 {
                ctx.intel_started = true;
                // Sentinel: we've consumed the flag bit but haven't read the
                // 32-bit filesize yet. The next iteration polls for it.
                ctx.intel_filesize = u32::MAX;
            }
            ctx.header_read = true;
            continue;
        }

        // Finish a possibly-deferred intel_filesize read.
        if ctx.intel_started && ctx.intel_filesize == u32::MAX {
            if ctx.bit_reader.bits_available() < 32 {
                return Ok(());
            }
            let hi = ctx.bit_reader.peek(16);
            ctx.bit_reader.drop_bits(16);
            let lo = ctx.bit_reader.peek(16);
            ctx.bit_reader.drop_bits(16);
            ctx.intel_filesize = (hi << 16) | lo;
            // Edge case: real LZX with filesize == 0xFFFFFFFF would collide
            // with our sentinel. In practice filesizes are bounded by
            // 2 GiB per LZX spec, so this is fine — but document the
            // invariant.
            continue;
        }

        // Use ownership transitions to avoid mutable-borrow conflicts when
        // calling helpers like emit_window(ctx, …).
        let blk = core::mem::replace(&mut ctx.block, BlockState::AwaitBlockHeader);
        match blk {
            BlockState::AwaitBlockHeader => {
                if ctx.bit_reader.bits_available() < 27 {
                    ctx.block = BlockState::AwaitBlockHeader;
                    return Ok(());
                }
                let btype = ctx.bit_reader.peek(3) as u8;
                ctx.bit_reader.drop_bits(3);
                let hi = ctx.bit_reader.peek(16);
                ctx.bit_reader.drop_bits(16);
                let lo = ctx.bit_reader.peek(8);
                ctx.bit_reader.drop_bits(8);
                let block_size: u32 = (hi << 8) | lo;
                if block_size == 0 {
                    return Err(Error::Corrupt);
                }
                match btype {
                    BLOCKTYPE_VERBATIM | BLOCKTYPE_ALIGNED => {
                        let build = TreeBuild {
                            btype,
                            sub: if btype == BLOCKTYPE_ALIGNED {
                                TreeSub::AlignedTreeLens
                            } else {
                                TreeSub::MainPretree1Lens
                            },
                            aligned: [0u8; ALIGNED_NUM_ELEMENTS],
                            aligned_idx: 0,
                            pretree_lens: [0u8; PRETREE_NUM_ELEMENTS],
                            pretree_idx: 0,
                            pretree: None,
                            cursor: 0,
                            end: NUM_CHARS as u16,
                            pending: PendingPretree::None,
                        };
                        let ph = HuffPhase::BuildingTrees(Box::new(build));
                        ctx.block = if btype == BLOCKTYPE_VERBATIM {
                            BlockState::Verbatim {
                                remaining: block_size,
                                ph,
                            }
                        } else {
                            BlockState::Aligned {
                                remaining: block_size,
                                ph,
                            }
                        };
                    }
                    BLOCKTYPE_UNCOMPRESSED => {
                        ctx.block = BlockState::UncompressedAlign {
                            remaining: block_size,
                        };
                    }
                    _ => return Err(Error::InvalidBlockType),
                }
            }

            BlockState::UncompressedAlign { remaining } => {
                ctx.bit_reader.align_to_word();
                ctx.block = BlockState::UncompressedRRR {
                    remaining,
                    rrr_buf: [0u8; 12],
                    rrr_have: 0,
                };
            }

            BlockState::UncompressedRRR {
                remaining,
                mut rrr_buf,
                mut rrr_have,
            } => {
                while (rrr_have as usize) < 12 && ctx.bit_reader.bits_available() >= 16 {
                    let word = ctx.bit_reader.peek(16);
                    ctx.bit_reader.drop_bits(16);
                    let lo = (word & 0xFF) as u8;
                    let hi = (word >> 8) as u8;
                    // Wire byte order: low byte of word first, then high byte.
                    rrr_buf[rrr_have as usize] = lo;
                    rrr_have += 1;
                    if (rrr_have as usize) < 12 {
                        rrr_buf[rrr_have as usize] = hi;
                        rrr_have += 1;
                    } else {
                        // Word-aligned reads should leave us on a word
                        // boundary after the 12-byte (= 6-word) dump; the
                        // single-byte exit is unreachable.
                        return Err(Error::Corrupt);
                    }
                }
                if (rrr_have as usize) < 12 {
                    ctx.block = BlockState::UncompressedRRR {
                        remaining,
                        rrr_buf,
                        rrr_have,
                    };
                    return Ok(());
                }
                let r0 = u32::from_le_bytes([rrr_buf[0], rrr_buf[1], rrr_buf[2], rrr_buf[3]]);
                let r1 = u32::from_le_bytes([rrr_buf[4], rrr_buf[5], rrr_buf[6], rrr_buf[7]]);
                let r2 = u32::from_le_bytes([rrr_buf[8], rrr_buf[9], rrr_buf[10], rrr_buf[11]]);
                ctx.r0 = r0;
                ctx.r1 = r1;
                ctx.r2 = r2;
                let original_was_odd = remaining & 1 == 1;
                ctx.block = BlockState::UncompressedData {
                    remaining,
                    original_was_odd,
                };
            }

            BlockState::UncompressedData {
                mut remaining,
                original_was_odd,
            } => {
                // Drain pre-buffered words byte-by-byte (low byte of word first).
                while remaining > 0 && ctx.bit_reader.bits_available() >= 16 {
                    let word = ctx.bit_reader.peek(16);
                    ctx.bit_reader.drop_bits(16);
                    let lo = (word & 0xFF) as u8;
                    let hi = (word >> 8) as u8;
                    emit_window(ctx, lo);
                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                    emit_window(ctx, hi);
                    remaining -= 1;
                    if ctx.frame_buf.len() >= FRAME_SIZE
                        || ctx.output_so_far + ctx.frame_buf.len() as u64 >= ctx.output_total
                    {
                        break;
                    }
                }
                if remaining > 0 {
                    ctx.block = BlockState::UncompressedData {
                        remaining,
                        original_was_odd,
                    };
                    return Ok(());
                }
                if original_was_odd {
                    ctx.block = BlockState::UncompressedPad;
                } else {
                    ctx.block = BlockState::AwaitBlockHeader;
                }
            }

            BlockState::UncompressedPad => {
                // Odd-length uncompressed blocks aren't producible by our
                // encoder; supporting them on decode would require expanding
                // the bit reader with a "drop low bits" primitive. Reject for
                // now.
                ctx.block = BlockState::UncompressedPad;
                return Err(Error::Unsupported);
            }

            BlockState::Verbatim { remaining, ph } => {
                ctx.block = BlockState::Verbatim { remaining, ph };
                let made = step_huff(ctx)?;
                if !made {
                    return Ok(());
                }
            }
            BlockState::Aligned { remaining, ph } => {
                ctx.block = BlockState::Aligned { remaining, ph };
                let made = step_huff(ctx)?;
                if !made {
                    return Ok(());
                }
            }
        }
    }
}

/// One sub-step inside a verbatim or aligned block. Returns true if forward
/// progress happened. The block-level `remaining` counter is updated whenever
/// a literal or match completes (counted in *output bytes*, matching the LZX
/// spec's BLOCK_SIZE semantics).
fn step_huff(ctx: &mut RunCtx) -> Result<bool, Error> {
    let is_aligned = matches!(ctx.block, BlockState::Aligned { .. });
    let (mut remaining, mut ph) =
        match core::mem::replace(&mut ctx.block, BlockState::AwaitBlockHeader) {
            BlockState::Verbatim { remaining, ph } => (remaining, ph),
            BlockState::Aligned { remaining, ph } => (remaining, ph),
            other => {
                ctx.block = other;
                return Ok(false);
            }
        };

    // Helper macros to repack the current phase before yielding back to the
    // outer loop. They're inline-expanded (so `ph` and `remaining` are still
    // in scope at the return site).
    macro_rules! yield_blocked {
        ($phase:expr) => {{
            let phase: HuffPhase = $phase;
            ctx.block = if is_aligned {
                BlockState::Aligned {
                    remaining,
                    ph: phase,
                }
            } else {
                BlockState::Verbatim {
                    remaining,
                    ph: phase,
                }
            };
            return Ok(false);
        }};
    }
    macro_rules! yield_progress {
        ($phase:expr) => {{
            let phase: HuffPhase = $phase;
            ctx.block = if is_aligned {
                BlockState::Aligned {
                    remaining,
                    ph: phase,
                }
            } else {
                BlockState::Verbatim {
                    remaining,
                    ph: phase,
                }
            };
            return Ok(true);
        }};
    }

    loop {
        // Take ownership of the current phase for this iteration.
        let cur = ph;
        match cur {
            HuffPhase::BuildingTrees(mut build) => {
                let progress = step_tree_build(ctx, &mut build)?;
                if matches!(build.sub, TreeSub::Done) {
                    yield_progress!(HuffPhase::NextMain);
                }
                ph = HuffPhase::BuildingTrees(build);
                if !progress {
                    let phase = core::mem::replace(&mut ph, HuffPhase::NextMain);
                    yield_blocked!(phase);
                }
            }
            HuffPhase::NextMain => {
                let mt = ctx.main_tree.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                match mt.decode(&mut ctx.bit_reader) {
                    Ok(Some(sym)) => {
                        if (sym as usize) < NUM_CHARS {
                            if remaining == 0 {
                                return Err(Error::Corrupt);
                            }
                            emit_window(ctx, sym as u8);
                            remaining -= 1;
                            if remaining == 0 {
                                ctx.block = BlockState::AwaitBlockHeader;
                                return Ok(true);
                            }
                            if ctx.frame_buf.len() >= FRAME_SIZE {
                                yield_progress!(HuffPhase::NextMain);
                            }
                            ph = HuffPhase::NextMain;
                            continue;
                        }
                        let m = sym - NUM_CHARS as u16;
                        let length_header = m & NUM_PRIMARY_LENGTHS;
                        let pos_slot = m >> 3;
                        if length_header == NUM_PRIMARY_LENGTHS {
                            ph = HuffPhase::LengthFooter { pos_slot };
                        } else {
                            let length = MIN_MATCH + length_header;
                            ph = if is_aligned {
                                start_offset_decode_aligned(ctx, length, pos_slot)?
                            } else {
                                start_offset_decode_verbatim(ctx, length, pos_slot)?
                            };
                        }
                    }
                    Ok(None) => yield_blocked!(HuffPhase::NextMain),
                    Err(e) => return Err(e),
                }
            }
            HuffPhase::LengthFooter { pos_slot } => {
                let lt = ctx.length_tree.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                if lt.is_empty() {
                    return Err(Error::Corrupt);
                }
                match lt.decode(&mut ctx.bit_reader) {
                    Ok(Some(lsym)) => {
                        let length = MIN_MATCH + NUM_PRIMARY_LENGTHS + lsym;
                        ph = if is_aligned {
                            start_offset_decode_aligned(ctx, length, pos_slot)?
                        } else {
                            start_offset_decode_verbatim(ctx, length, pos_slot)?
                        };
                    }
                    Ok(None) => yield_blocked!(HuffPhase::LengthFooter { pos_slot }),
                    Err(e) => return Err(e),
                }
            }
            HuffPhase::VerbatimExtra { length, pos_slot } => {
                let extra = if (pos_slot as usize) < EXTRA_BITS.len() {
                    EXTRA_BITS[pos_slot as usize]
                } else {
                    17
                };
                if ctx.bit_reader.bits_available() < extra as u32 {
                    yield_blocked!(HuffPhase::VerbatimExtra { length, pos_slot });
                }
                let footer = if extra == 0 {
                    0
                } else {
                    ctx.bit_reader.peek(extra as u32)
                };
                ctx.bit_reader.drop_bits(extra as u32);
                let match_offset = compute_offset(ctx, pos_slot, footer)?;
                ph = HuffPhase::EmittingMatch {
                    length,
                    distance: match_offset,
                };
            }
            HuffPhase::AlignedHighBits {
                length,
                pos_slot,
                extra,
            } => {
                let high_bits = extra - 3;
                if ctx.bit_reader.bits_available() < high_bits as u32 {
                    yield_blocked!(HuffPhase::AlignedHighBits {
                        length,
                        pos_slot,
                        extra,
                    });
                }
                let high = if high_bits == 0 {
                    0
                } else {
                    ctx.bit_reader.peek(high_bits as u32)
                };
                ctx.bit_reader.drop_bits(high_bits as u32);
                let base = POSITION_BASE[pos_slot as usize];
                let high_offset = base.wrapping_sub(2).wrapping_add(high << 3);
                ph = HuffPhase::AlignedFooter {
                    length,
                    high_offset,
                };
            }
            HuffPhase::AlignedFooter {
                length,
                high_offset,
            } => {
                let at = ctx.aligned_tree.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                match at.decode(&mut ctx.bit_reader) {
                    Ok(Some(asym)) => {
                        let match_offset = high_offset.wrapping_add(asym as u32);
                        ctx.r2 = ctx.r1;
                        ctx.r1 = ctx.r0;
                        ctx.r0 = match_offset;
                        ph = HuffPhase::EmittingMatch {
                            length,
                            distance: match_offset,
                        };
                    }
                    Ok(None) => yield_blocked!(HuffPhase::AlignedFooter {
                        length,
                        high_offset
                    }),
                    Err(e) => return Err(e),
                }
            }
            HuffPhase::EmittingMatch { length, distance } => {
                if distance == 0 || (distance as usize) > ctx.window.len() {
                    return Err(Error::InvalidDistance);
                }
                let mut copied = 0u16;
                while copied < length {
                    if ctx.frame_buf.len() >= FRAME_SIZE {
                        yield_progress!(HuffPhase::EmittingMatch {
                            length: length - copied,
                            distance,
                        });
                    }
                    if remaining == 0 {
                        return Err(Error::Corrupt);
                    }
                    let win_size = ctx.window.len();
                    let src = (ctx.window_pos + win_size - distance as usize) % win_size;
                    let b = ctx.window[src];
                    emit_window(ctx, b);
                    copied += 1;
                    remaining -= 1;
                    if remaining == 0 {
                        ctx.block = BlockState::AwaitBlockHeader;
                        return Ok(true);
                    }
                }
                ph = HuffPhase::NextMain;
            }
            HuffPhase::PendingLiteral { byte } => {
                if ctx.frame_buf.len() >= FRAME_SIZE {
                    yield_progress!(HuffPhase::PendingLiteral { byte });
                }
                emit_window(ctx, byte);
                if remaining == 0 {
                    ctx.block = BlockState::AwaitBlockHeader;
                    return Ok(true);
                }
                remaining -= 1;
                if remaining == 0 {
                    ctx.block = BlockState::AwaitBlockHeader;
                    return Ok(true);
                }
                ph = HuffPhase::NextMain;
            }
        }
    }
}

fn start_offset_decode_verbatim(
    _ctx: &mut RunCtx,
    length: u16,
    pos_slot: u16,
) -> Result<HuffPhase, Error> {
    Ok(HuffPhase::VerbatimExtra { length, pos_slot })
}

fn start_offset_decode_aligned(
    ctx: &mut RunCtx,
    length: u16,
    pos_slot: u16,
) -> Result<HuffPhase, Error> {
    let extra = if (pos_slot as usize) < EXTRA_BITS.len() {
        EXTRA_BITS[pos_slot as usize]
    } else {
        17
    };
    if pos_slot < 3 {
        // LRU slot — handled like verbatim path.
        let match_offset = compute_offset(ctx, pos_slot, 0)?;
        Ok(HuffPhase::EmittingMatch {
            length,
            distance: match_offset,
        })
    } else if extra >= 3 {
        Ok(HuffPhase::AlignedHighBits {
            length,
            pos_slot,
            extra,
        })
    } else {
        // extra in 0..3 with pos_slot >= 3: read verbatim bits, then update LRU.
        Ok(HuffPhase::VerbatimExtra { length, pos_slot })
    }
}

fn compute_offset(ctx: &mut RunCtx, pos_slot: u16, footer: u32) -> Result<u32, Error> {
    let match_offset = match pos_slot {
        0 => ctx.r0,
        1 => {
            core::mem::swap(&mut ctx.r1, &mut ctx.r0);
            ctx.r0
        }
        2 => {
            core::mem::swap(&mut ctx.r2, &mut ctx.r0);
            ctx.r0
        }
        _ => {
            let base = POSITION_BASE[pos_slot as usize];
            let mo = base.wrapping_sub(2).wrapping_add(footer);
            ctx.r2 = ctx.r1;
            ctx.r1 = ctx.r0;
            ctx.r0 = mo;
            mo
        }
    };
    if match_offset == 0 {
        return Err(Error::InvalidDistance);
    }
    Ok(match_offset)
}

// ─── Tree-building substeps ─────────────────────────────────────────────

fn step_tree_build(ctx: &mut RunCtx, build: &mut TreeBuild) -> Result<bool, Error> {
    loop {
        match build.sub {
            TreeSub::AlignedTreeLens => {
                while (build.aligned_idx as usize) < ALIGNED_NUM_ELEMENTS {
                    if ctx.bit_reader.bits_available() < 3 {
                        return Ok(false);
                    }
                    let v = ctx.bit_reader.peek(3) as u8;
                    ctx.bit_reader.drop_bits(3);
                    build.aligned[build.aligned_idx as usize] = v;
                    build.aligned_idx += 1;
                }
                ctx.aligned_lens.copy_from_slice(&build.aligned);
                ctx.aligned_tree = Some(Box::new(
                    LzxHuffman::<ALIGNED_NUM_ELEMENTS>::from_lengths(&ctx.aligned_lens)?,
                ));
                build.sub = TreeSub::MainPretree1Lens;
                build.pretree_idx = 0;
                return Ok(true);
            }
            TreeSub::MainPretree1Lens | TreeSub::MainPretree2Lens | TreeSub::LengthPretreeLens => {
                while (build.pretree_idx as usize) < PRETREE_NUM_ELEMENTS {
                    if ctx.bit_reader.bits_available() < 4 {
                        return Ok(false);
                    }
                    let v = ctx.bit_reader.peek(4) as u8;
                    ctx.bit_reader.drop_bits(4);
                    build.pretree_lens[build.pretree_idx as usize] = v;
                    build.pretree_idx += 1;
                }
                build.pretree = Some(LzxHuffman::<PRETREE_NUM_ELEMENTS>::from_lengths(
                    &build.pretree_lens,
                )?);
                build.cursor = match build.sub {
                    TreeSub::MainPretree1Lens => 0,
                    TreeSub::MainPretree2Lens => NUM_CHARS as u16,
                    TreeSub::LengthPretreeLens => 0,
                    _ => unreachable!(),
                };
                build.end = match build.sub {
                    TreeSub::MainPretree1Lens => NUM_CHARS as u16,
                    TreeSub::MainPretree2Lens => main_tree_size(ctx.window_bits) as u16,
                    TreeSub::LengthPretreeLens => NUM_SECONDARY_LENGTHS as u16,
                    _ => unreachable!(),
                };
                build.sub = match build.sub {
                    TreeSub::MainPretree1Lens => TreeSub::MainPretree1Data,
                    TreeSub::MainPretree2Lens => TreeSub::MainPretree2Data,
                    TreeSub::LengthPretreeLens => TreeSub::LengthPretreeData,
                    _ => unreachable!(),
                };
                build.pending = PendingPretree::None;
                return Ok(true);
            }
            TreeSub::MainPretree1Data | TreeSub::MainPretree2Data | TreeSub::LengthPretreeData => {
                let kind = build.sub;
                let progress = step_pretree_data(ctx, build, kind)?;
                if build.cursor >= build.end {
                    match build.sub {
                        TreeSub::MainPretree1Data => {
                            build.sub = TreeSub::MainPretree2Lens;
                            build.pretree_idx = 0;
                            build.pretree = None;
                            return Ok(true);
                        }
                        TreeSub::MainPretree2Data => {
                            // Build main tree.
                            ctx.main_tree = Some(Box::new(
                                LzxHuffman::<MAIN_TREE_MAX>::from_lengths(&ctx.main_lens)?,
                            ));
                            build.sub = TreeSub::LengthPretreeLens;
                            build.pretree_idx = 0;
                            build.pretree = None;
                            build.cursor = 0;
                            return Ok(true);
                        }
                        TreeSub::LengthPretreeData => {
                            ctx.length_tree =
                                Some(Box::new(LzxHuffman::<NUM_SECONDARY_LENGTHS>::from_lengths(
                                    &ctx.length_lens,
                                )?));
                            build.sub = TreeSub::Done;
                            return Ok(true);
                        }
                        _ => unreachable!(),
                    }
                }
                if !progress {
                    return Ok(false);
                }
            }
            TreeSub::Done => return Ok(false),
        }
    }
}

/// Decode pretree-coded length deltas into the target `lens` array, advancing
/// `cursor` until `end`. Returns true if any forward progress was made.
fn step_pretree_data(
    ctx: &mut RunCtx,
    build: &mut TreeBuild,
    target: TreeSub,
) -> Result<bool, Error> {
    let mut progress = false;
    loop {
        if build.cursor >= build.end {
            return Ok(progress);
        }
        // Handle pending multi-bit reads.
        match build.pending {
            PendingPretree::None => {}
            PendingPretree::SeventeenExtra => {
                if ctx.bit_reader.bits_available() < 4 {
                    return Ok(progress);
                }
                let n = ctx.bit_reader.peek(4) as u16 + 4;
                ctx.bit_reader.drop_bits(4);
                if build.cursor + n > build.end {
                    return Err(Error::Corrupt);
                }
                for _ in 0..n {
                    write_len(ctx, target, build.cursor, 0)?;
                    build.cursor += 1;
                }
                build.pending = PendingPretree::None;
                progress = true;
                continue;
            }
            PendingPretree::EighteenExtra => {
                if ctx.bit_reader.bits_available() < 5 {
                    return Ok(progress);
                }
                let n = ctx.bit_reader.peek(5) as u16 + 20;
                ctx.bit_reader.drop_bits(5);
                if build.cursor + n > build.end {
                    return Err(Error::Corrupt);
                }
                for _ in 0..n {
                    write_len(ctx, target, build.cursor, 0)?;
                    build.cursor += 1;
                }
                build.pending = PendingPretree::None;
                progress = true;
                continue;
            }
            PendingPretree::NineteenExtra => {
                if ctx.bit_reader.bits_available() < 1 {
                    return Ok(progress);
                }
                let run = ctx.bit_reader.peek(1) as u8 + 4;
                ctx.bit_reader.drop_bits(1);
                build.pending = PendingPretree::NineteenSecond { run };
                progress = true;
                continue;
            }
            PendingPretree::NineteenSecond { run } => {
                let pt = build.pretree.as_ref().ok_or(Error::InvalidHuffmanTree)?;
                match pt.decode(&mut ctx.bit_reader) {
                    Ok(Some(z)) => {
                        if z >= 17 {
                            return Err(Error::Corrupt);
                        }
                        if build.cursor + run as u16 > build.end {
                            return Err(Error::Corrupt);
                        }
                        for _ in 0..run {
                            let prev = read_len(ctx, target, build.cursor);
                            let new_len = mod17(prev as i16 - z as i16);
                            write_len(ctx, target, build.cursor, new_len)?;
                            build.cursor += 1;
                        }
                        build.pending = PendingPretree::None;
                        progress = true;
                    }
                    Ok(None) => return Ok(progress),
                    Err(e) => return Err(e),
                }
                continue;
            }
        }

        // No pending — decode a fresh pretree symbol.
        let pt = build.pretree.as_ref().ok_or(Error::InvalidHuffmanTree)?;
        match pt.decode(&mut ctx.bit_reader) {
            Ok(Some(sym)) => {
                progress = true;
                match sym {
                    0..=16 => {
                        let prev = read_len(ctx, target, build.cursor);
                        let new_len = mod17(prev as i16 - sym as i16);
                        write_len(ctx, target, build.cursor, new_len)?;
                        build.cursor += 1;
                    }
                    17 => build.pending = PendingPretree::SeventeenExtra,
                    18 => build.pending = PendingPretree::EighteenExtra,
                    19 => build.pending = PendingPretree::NineteenExtra,
                    _ => return Err(Error::Corrupt),
                }
            }
            Ok(None) => return Ok(progress),
            Err(e) => return Err(e),
        }
    }
}

fn read_len(ctx: &RunCtx, target: TreeSub, idx: u16) -> u8 {
    match target {
        TreeSub::MainPretree1Data => ctx.main_lens[idx as usize],
        TreeSub::MainPretree2Data => ctx.main_lens[idx as usize],
        TreeSub::LengthPretreeData => ctx.length_lens[idx as usize],
        _ => 0,
    }
}

fn write_len(ctx: &mut RunCtx, target: TreeSub, idx: u16, val: u8) -> Result<(), Error> {
    match target {
        TreeSub::MainPretree1Data => {
            ctx.main_lens[idx as usize] = val;
        }
        TreeSub::MainPretree2Data => {
            ctx.main_lens[idx as usize] = val;
        }
        TreeSub::LengthPretreeData => {
            ctx.length_lens[idx as usize] = val;
        }
        _ => return Err(Error::Corrupt),
    }
    Ok(())
}

fn mod17(x: i16) -> u8 {
    let mut r = x % 17;
    if r < 0 {
        r += 17;
    }
    r as u8
}

// ─── E8 filter ──────────────────────────────────────────────────────────

/// Apply the LZX intel-call-translation filter to the bytes accumulated in
/// `ctx.frame_buf` (which represents one decoded frame, ≤ FRAME_SIZE bytes).
///
/// Per spec §2.4 the filter only fires when:
///   - intel_started == true (the leading flag bit was set),
///   - intel_filesize != 0,
///   - the current frame's *absolute* start offset is < 0x40000000 (1 GiB),
///   - the frame size is > 10 bytes.
///
/// For each 0xE8 byte at index `i` (scanning `i = 0..frame_size-10`) the next
/// four little-endian bytes hold a *relative* call offset which is rewritten
/// into a different scheme. The transform is its own inverse.
fn apply_e8_to_frame(ctx: &mut RunCtx) {
    if !ctx.intel_started || ctx.intel_filesize == 0 {
        return;
    }
    let frame_size = ctx.frame_buf.len();
    if frame_size <= 10 {
        return;
    }
    // Absolute start of this frame in the *uncompressed* stream.
    let frame_start = ctx.output_so_far as i64;
    if frame_start >= 0x4000_0000 {
        return;
    }

    let filesize = ctx.intel_filesize as i64;
    let scan_end = frame_size - 10;
    let mut i = 0usize;
    while i < scan_end {
        if ctx.frame_buf[i] != 0xE8 {
            i += 1;
            continue;
        }
        let abs_off = frame_start + i as i64 + 1; // byte after 0xE8
        let rel = i32::from_le_bytes([
            ctx.frame_buf[i + 1],
            ctx.frame_buf[i + 2],
            ctx.frame_buf[i + 3],
            ctx.frame_buf[i + 4],
        ]) as i64;
        // Decoding rule: if (-abs_off <= rel < filesize), rewrite
        //   new = rel - abs_off   if rel >= 0
        //   new = rel + filesize  if rel <  0
        // The transform's inverse (used by the encoder) maps the opposite way.
        if (-abs_off <= rel) && (rel < filesize) {
            let new = if rel >= 0 {
                rel - abs_off
            } else {
                rel + filesize
            };
            let bytes = (new as i32).to_le_bytes();
            ctx.frame_buf[i + 1] = bytes[0];
            ctx.frame_buf[i + 2] = bytes[1];
            ctx.frame_buf[i + 3] = bytes[2];
            ctx.frame_buf[i + 4] = bytes[3];
        }
        // Skip the 4 bytes we just inspected to avoid overlapping rewrites.
        i += 5;
    }
}
