//! Streaming Zstandard encoder that emits only `Raw_Block`s.
//!
//! This is a *valid Zstd frame*, but it performs no compression: every byte
//! of input is copied into a raw block. The encoder is included primarily so
//! that the [`Algorithm`](crate::Algorithm) impl has both halves and so the
//! decoder can be round-trip tested against itself.
//!
//! Frame layout we emit:
//! - 4 bytes magic (`0x28 0xB5 0x2F 0xFD`)
//! - 1 byte Frame_Header_Descriptor = `0x00`
//!     - FCS_Field_Size = 0 (no Frame_Content_Size — we're streaming)
//!     - Single_Segment_Flag = 0 (so Window_Descriptor is present)
//!     - Content_Checksum_Flag = 0 (we don't ship XXH64)
//!     - Dictionary_ID_Flag = 0
//! - 1 byte Window_Descriptor = `0x50` (Exponent=10, Mantissa=0 → 1 KiB)
//! - One or more Raw_Blocks; the last carries `Last_Block = 1`.
//!
//! The encoder buffers input in chunks of [`MAX_RAW_CHUNK`] bytes and emits a
//! `Raw_Block` per chunk. `finish()` flushes the trailing chunk with the
//! Last_Block bit set; if the trailing chunk is empty, it emits a zero-length
//! Last_Block Raw_Block.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Encoder as EncoderTrait, Progress};

/// 4-byte zstd Frame_Magic_Number, little-endian on disk.
const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// FHD = 0x00 → see module docs.
const FHD: u8 = 0x00;
/// WD = 0x50 → Exponent=10, Mantissa=0 → Window_Size = 1024.
const WD: u8 = 0x50;

/// Threshold at which we cut a Raw_Block. Smaller than the 128 KiB spec cap
/// so latency stays bounded for very-long streams.
const MAX_RAW_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EncPhase {
    /// Need to emit 4-byte magic + FHD + WD.
    Header,
    /// Body: buffering up to [`MAX_RAW_CHUNK`] bytes into `pending`.
    ///
    /// When `pending.len()` reaches the threshold, we serialize a non-final
    /// Raw_Block into `out_buf` and drain it.
    Body,
    /// `out_buf` is loaded with bytes (header bytes, a serialized block
    /// header, or the trailer Last_Block header) and is being drained to the
    /// caller's output.
    DrainOut,
    /// Streaming the current Raw_Block body directly from `pending` into
    /// the caller's output, byte-for-byte.
    DrainBody,
    /// `finish()` has been called and we've emitted the final block.
    Done,
}

/// Streaming Zstandard encoder. Produces a single Zstd frame containing only
/// `Raw_Block`s — see module docs for layout details.
pub struct Encoder {
    phase: EncPhase,
    /// Pending input bytes not yet committed to a block.
    pending: Vec<u8>,
    /// "Output staging": header bytes, serialized 3-byte block header, etc.
    out_buf: Vec<u8>,
    /// Cursor into `out_buf`.
    out_idx: usize,
    /// Cursor into `pending` while in `DrainBody`.
    body_idx: usize,
    /// Length of the body currently being drained (subset of `pending`).
    body_len: usize,
    /// Are we draining the final block? If so we transition to `Done` after
    /// `DrainBody`, otherwise we drop back to `Body`.
    last_block_drained: bool,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            phase: EncPhase::Header,
            pending: Vec::new(),
            out_buf: Vec::with_capacity(6),
            out_idx: 0,
            body_idx: 0,
            body_len: 0,
            last_block_drained: false,
        }
    }

    /// Push the 4-byte magic + FHD + WD into `out_buf`.
    fn load_frame_header(&mut self) {
        self.out_buf.clear();
        self.out_buf.extend_from_slice(&MAGIC);
        self.out_buf.push(FHD);
        self.out_buf.push(WD);
        self.out_idx = 0;
    }

    /// Pack a 3-byte Raw_Block header into `out_buf`.
    fn load_block_header(&mut self, body_size: u32, last: bool) {
        debug_assert!(body_size < (1u32 << 21));
        // Block_Header (24-bit LE): bit 0 = Last_Block, bits 1..3 = Type, bits 3..24 = Block_Size.
        // Block_Type = 0 (Raw_Block) contributes 0; omitted from the OR.
        let bh: u32 = (if last { 1 } else { 0 }) | (body_size << 3);
        self.out_buf.clear();
        self.out_buf.push((bh & 0xFF) as u8);
        self.out_buf.push(((bh >> 8) & 0xFF) as u8);
        self.out_buf.push(((bh >> 16) & 0xFF) as u8);
        self.out_idx = 0;
    }

    /// Copy as much of `out_buf[out_idx..]` into `output[*written..]` as fits.
    fn drain_into(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let avail = output.len() - *written;
        let remaining = self.out_buf.len() - self.out_idx;
        let n = core::cmp::min(avail, remaining);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.out_buf[self.out_idx..self.out_idx + n]);
            *written += n;
            self.out_idx += n;
        }
        self.out_idx == self.out_buf.len()
    }

    /// Stage a Raw_Block: load its header and queue the pending body to be
    /// drained. The caller decides whether this is the final block.
    fn stage_block(&mut self, last: bool) {
        let body_size = self.pending.len() as u32;
        self.load_block_header(body_size, last);
        self.body_idx = 0;
        self.body_len = self.pending.len();
        self.last_block_drained = last;
        self.phase = EncPhase::DrainOut;
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let initial_consumed = consumed;
            let initial_written = written;

            match self.phase {
                EncPhase::Header => {
                    // Lazily build the header on first call so callers that
                    // never get past `new` don't allocate.
                    if self.out_buf.is_empty() && self.out_idx == 0 {
                        self.load_frame_header();
                    }
                    if !self.drain_into(output, &mut written) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.phase = EncPhase::Body;
                }
                EncPhase::Body => {
                    // Accumulate input up to MAX_RAW_CHUNK.
                    let space = MAX_RAW_CHUNK - self.pending.len();
                    let take = core::cmp::min(space, input.len() - consumed);
                    if take > 0 {
                        self.pending
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.pending.len() == MAX_RAW_CHUNK {
                        self.stage_block(false);
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::DrainOut => {
                    if !self.drain_into(output, &mut written) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Header drained; move on to body or skip body if empty.
                    if self.body_len == 0 {
                        if self.last_block_drained {
                            self.phase = EncPhase::Done;
                            self.pending.clear();
                            return Ok(Progress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        // Empty non-final block — drop pending (already empty)
                        // and continue body buffering. We don't actually emit
                        // empty non-final blocks; `stage_block` is only called
                        // with a full pending in `encode`. Defensive branch.
                        self.pending.clear();
                        self.phase = EncPhase::Body;
                    } else {
                        self.phase = EncPhase::DrainBody;
                    }
                }
                EncPhase::DrainBody => {
                    let out_avail = output.len() - written;
                    let body_remaining = self.body_len - self.body_idx;
                    let n = core::cmp::min(out_avail, body_remaining);
                    if n > 0 {
                        output[written..written + n]
                            .copy_from_slice(&self.pending[self.body_idx..self.body_idx + n]);
                        written += n;
                        self.body_idx += n;
                    }
                    if self.body_idx == self.body_len {
                        // Body fully drained — clear pending and decide what's next.
                        self.pending.clear();
                        if self.last_block_drained {
                            self.phase = EncPhase::Done;
                            return Ok(Progress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        self.phase = EncPhase::Body;
                    } else {
                        // Output is full; suspend.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
                    // `encode` never reports `done`; the caller must call
                    // `finish` once they're out of input, and only `finish`
                    // sets `done: true`.
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == initial_consumed && written == initial_written {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        loop {
            let initial_written = written;
            let initial_phase = self.phase;

            match self.phase {
                EncPhase::Header => {
                    if self.out_buf.is_empty() && self.out_idx == 0 {
                        self.load_frame_header();
                    }
                    if !self.drain_into(output, &mut written) {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    self.phase = EncPhase::Body;
                }
                EncPhase::Body => {
                    // Emit pending as a Last_Block Raw_Block.
                    self.stage_block(true);
                }
                EncPhase::DrainOut => {
                    if !self.drain_into(output, &mut written) {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    if self.body_len == 0 {
                        if self.last_block_drained {
                            self.phase = EncPhase::Done;
                            self.pending.clear();
                        } else {
                            // Shouldn't be reachable in finish, since finish
                            // always stages a last block.
                            self.pending.clear();
                            self.phase = EncPhase::Body;
                        }
                    } else {
                        self.phase = EncPhase::DrainBody;
                    }
                }
                EncPhase::DrainBody => {
                    let out_avail = output.len() - written;
                    let body_remaining = self.body_len - self.body_idx;
                    let n = core::cmp::min(out_avail, body_remaining);
                    if n > 0 {
                        output[written..written + n]
                            .copy_from_slice(&self.pending[self.body_idx..self.body_idx + n]);
                        written += n;
                        self.body_idx += n;
                    }
                    if self.body_idx == self.body_len {
                        self.pending.clear();
                        if self.last_block_drained {
                            self.phase = EncPhase::Done;
                        } else {
                            self.phase = EncPhase::Body;
                        }
                    } else {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }

            if written == initial_written
                && self.phase == initial_phase
                && !matches!(self.phase, EncPhase::Done)
            {
                // No write and no phase change this iteration — output is
                // full and we owe more bytes. Suspend.
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }
    }

    fn reset(&mut self) {
        self.phase = EncPhase::Header;
        self.pending.clear();
        self.out_buf.clear();
        self.out_idx = 0;
        self.body_idx = 0;
        self.body_len = 0;
        self.last_block_drained = false;
    }
}
