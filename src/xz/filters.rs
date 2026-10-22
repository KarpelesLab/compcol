//! Non-last filters of an xz Block's filter chain (xz-file-format.txt §5.3.2
//! and §5.3.3): Delta and the BCJ branch converters, undone in place on the
//! LZMA2 output before it reaches the caller.
//!
//! The transforms themselves are this crate's `delta` and `bcj` codecs; this
//! module only parses their xz Filter Properties and runs them over one
//! shared buffer. Every filter here is length-preserving, so the chain works
//! in place: each stage keeps a cursor up to which its output is final, the
//! cursors never increase along the chain (a stage can only finalise bytes
//! the stage before it has), and the bytes before the last stage's cursor
//! are ready for the caller. A BCJ stage leaves an instruction that may
//! straddle the end of the data so far raw until more data (or the end of
//! the Block) arrives; Delta has no such tail.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bcj::{Arm, Arm64, ArmThumb, BcjArch, Ia64, MAX_INSN, Ppc, RiscV, Sparc, X86};
use crate::delta;
use crate::error::Error;

/// Filter ID of the Delta filter.
const FILTER_ID_DELTA: u64 = 0x03;

/// One BCJ architecture, with the per-stream state its converter carries.
enum BcjKind {
    X86(<X86 as BcjArch>::State),
    Ppc,
    Ia64,
    Arm,
    ArmThumb,
    Sparc,
    Arm64,
    RiscV,
}

enum Filter {
    Delta(Box<delta::Decoder>),
    Bcj {
        kind: BcjKind,
        /// Stream position of the stage's first not-yet-final byte (the
        /// Filter Properties' start offset plus the bytes finalised so far).
        ip: u32,
    },
}

/// Run one BCJ decoder over `data` starting at stream position `ip`,
/// returning how many leading bytes are final. The rest is an instruction
/// that may still continue past `data`; it is left raw so the next call
/// reconverts it from the original bytes.
fn bcj_convert<A: BcjArch>(data: &mut [u8], ip: u32, state: &mut A::State) -> usize {
    let len = data.len();
    let keep = len.min(MAX_INSN);
    let mut raw_tail = [0u8; MAX_INSN];
    raw_tail[..keep].copy_from_slice(&data[len - keep..]);
    let done = A::convert(data, ip, false, state);
    debug_assert!(len - done <= keep);
    let start = done.max(len - keep);
    data[start..].copy_from_slice(&raw_tail[start - (len - keep)..keep]);
    done
}

impl Filter {
    /// Parse a non-last Filter Flags entry: `id` and its properties.
    fn parse(id: u64, props: &[u8]) -> Result<Self, Error> {
        if id == FILTER_ID_DELTA {
            // One byte: distance - 1.
            return match props {
                [d] => Ok(Self::Delta(Box::new(delta::Decoder::new(*d as usize + 1)))),
                _ => Err(Error::Unsupported),
            };
        }
        let kind = match id {
            0x04 => BcjKind::X86(Default::default()),
            0x05 => BcjKind::Ppc,
            0x06 => BcjKind::Ia64,
            0x07 => BcjKind::Arm,
            0x08 => BcjKind::ArmThumb,
            0x09 => BcjKind::Sparc,
            0x0A => BcjKind::Arm64,
            0x0B => BcjKind::RiscV,
            // LZMA2 is only valid last; anything else is unknown.
            _ => return Err(Error::Unsupported),
        };
        // No properties, or a 4-byte little-endian start offset.
        let ip = match props {
            [] => 0,
            [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
            _ => return Err(Error::Unsupported),
        };
        Ok(Self::Bcj { kind, ip })
    }

    /// Undo the filter on `data` (bytes the previous stage has finalised;
    /// any leading ones are this stage's tail from the last call). Returns
    /// how many leading bytes are now final. `end` means no more data
    /// follows in this Block: a BCJ tail too short to be an instruction then
    /// passes through unchanged, as in liblzma.
    fn run(&mut self, data: &mut [u8], end: bool) -> Result<usize, Error> {
        match self {
            Self::Delta(d) => {
                d.decode_in_place(data)?;
                Ok(data.len())
            }
            Self::Bcj { kind, ip } => {
                let done = match kind {
                    BcjKind::X86(state) => bcj_convert::<X86>(data, *ip, state),
                    BcjKind::Ppc => bcj_convert::<Ppc>(data, *ip, &mut Default::default()),
                    BcjKind::Ia64 => bcj_convert::<Ia64>(data, *ip, &mut Default::default()),
                    BcjKind::Arm => bcj_convert::<Arm>(data, *ip, &mut Default::default()),
                    BcjKind::ArmThumb => {
                        bcj_convert::<ArmThumb>(data, *ip, &mut Default::default())
                    }
                    BcjKind::Sparc => bcj_convert::<Sparc>(data, *ip, &mut Default::default()),
                    BcjKind::Arm64 => bcj_convert::<Arm64>(data, *ip, &mut Default::default()),
                    BcjKind::RiscV => bcj_convert::<RiscV>(data, *ip, &mut Default::default()),
                };
                let done = if end { data.len() } else { done };
                *ip = ip.wrapping_add(done as u32);
                Ok(done)
            }
        }
    }
}

struct Stage {
    filter: Filter,
    /// `buf` index up to which this stage's output is final.
    done: usize,
}

/// The non-last filters of one Block, in decode order (the reverse of the
/// Block Header's order: the filter listed just before LZMA2 runs first).
pub(super) struct FilterChain {
    stages: Vec<Stage>,
    /// LZMA2 output being filtered: `[out_pos..ready)` is final and waiting
    /// for the caller, the rest is still in some stage's tail.
    buf: Vec<u8>,
    out_pos: usize,
}

impl FilterChain {
    /// Build from the Block Header's non-last filters, given in header
    /// order as `(id, properties)`.
    pub(super) fn new(filters: &[(u64, &[u8])]) -> Result<Self, Error> {
        let mut stages = Vec::with_capacity(filters.len());
        for &(id, props) in filters.iter().rev() {
            stages.push(Stage {
                filter: Filter::parse(id, props)?,
                done: 0,
            });
        }
        Ok(Self {
            stages,
            buf: Vec::new(),
            out_pos: 0,
        })
    }

    fn ready_end(&self) -> usize {
        self.stages.last().map_or(self.buf.len(), |s| s.done)
    }

    /// Final bytes not yet handed to the caller.
    pub(super) fn ready(&self) -> &[u8] {
        &self.buf[self.out_pos..self.ready_end()]
    }

    /// Mark `n` bytes of [`ready`](Self::ready) as handed out.
    pub(super) fn consume(&mut self, n: usize) {
        self.out_pos += n;
        debug_assert!(self.out_pos <= self.ready_end());
    }

    /// Append LZMA2 output and filter as much of it as is final.
    pub(super) fn push(&mut self, data: &[u8]) -> Result<(), Error> {
        // Drop what the caller already has; the rest is at most the stages'
        // short tails (the decoder pushes only once `ready` is drained).
        if self.out_pos > 0 {
            self.buf.drain(..self.out_pos);
            for s in &mut self.stages {
                s.done -= self.out_pos;
            }
            self.out_pos = 0;
        }
        self.buf.extend_from_slice(data);
        self.run(false)
    }

    /// The Block's LZMA2 data ended: finalise every stage's tail.
    pub(super) fn finish(&mut self) -> Result<(), Error> {
        self.run(true)
    }

    fn run(&mut self, end: bool) -> Result<(), Error> {
        let mut limit = self.buf.len();
        for s in &mut self.stages {
            s.done += s.filter.run(&mut self.buf[s.done..limit], end)?;
            limit = s.done;
        }
        Ok(())
    }
}
