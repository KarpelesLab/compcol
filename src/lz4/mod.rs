//! LZ4 block format with a tiny multi-block framing for streaming.
//!
//! Reference: <https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md>.
//!
//! The on-disk LZ4 *block* format is a single contiguous payload with no
//! length prefix or terminator. To round-trip arbitrary-length streams
//! through our streaming trait we layer a minimal framing on top:
//!
//! ```text
//! stream := block* terminator
//! block  := u32_le(N != 0) || N bytes of LZ4 block payload
//! terminator := u32_le(0)
//! ```
//!
//! The encoder buffers up to [`BLOCK_SIZE`] bytes of raw input, then emits a
//! compressed block prefixed by its length. `finish` flushes any trailing
//! partial block and then writes the zero-length terminator. The decoder
//! reads a length, accumulates that many bytes, decompresses them, and
//! emits the result; it stops at the first zero-length terminator.
//!
//! This is intentionally not the canonical LZ4 frame format (which has a
//! magic number, flag byte, optional content-size, checksums, etc.); this
//! crate's higher-level containers can be added later if needed.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

mod block;

/// Raw-input block size. 64 KiB is the canonical LZ4 block size and the
/// largest value for which the 16-bit back-reference offset can address the
/// full block.
pub const BLOCK_SIZE: usize = 64 * 1024;

/// Zero-sized marker type implementing [`Algorithm`] for LZ4.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lz4;

impl Algorithm for Lz4 {
    const NAME: &'static str = "lz4";
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    /// Accepting raw input bytes into `raw`.
    Buffering,
    /// `compressed` holds an encoded block waiting to be drained to the
    /// caller's output buffer. `compressed_idx` tracks how much has been
    /// drained so far. The 4-byte length prefix is included in `compressed`.
    Flushing,
    /// All blocks flushed; waiting to emit the 4-byte zero terminator.
    /// `terminator_idx` is how many of those 4 bytes have been written.
    Terminating,
    /// Terminator fully written. `finish` will now return `done = true`.
    Done,
}

pub struct Encoder {
    raw: Vec<u8>,
    compressed: Vec<u8>,
    compressed_idx: usize,
    terminator_idx: u8,
    phase: EncPhase,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            raw: Vec::with_capacity(BLOCK_SIZE),
            compressed: Vec::with_capacity(block::compress_bound(BLOCK_SIZE) + 4),
            compressed_idx: 0,
            terminator_idx: 0,
            phase: EncPhase::Buffering,
        }
    }

    /// Compress `self.raw` and stage it (with its length prefix) in
    /// `self.compressed`. After this call, `phase` is `Flushing` if there
    /// were any bytes to flush, otherwise `Buffering` (unchanged).
    fn build_block(&mut self) {
        if self.raw.is_empty() {
            return;
        }
        // Stage: [u32 LE length][block bytes].
        self.compressed.clear();
        // Reserve 4 bytes for the length prefix; we'll fill it in after we
        // know the compressed size.
        self.compressed.extend_from_slice(&[0, 0, 0, 0]);
        let prefix_len = self.compressed.len();
        // Encode appends — but we need it to write past the prefix without
        // clearing it. The block encoder clears its `out` arg, so we use a
        // temporary buffer and concatenate.
        let mut tmp = Vec::with_capacity(block::compress_bound(self.raw.len()));
        block::encode_block(&self.raw, &mut tmp);
        // The block format never emits zero bytes for a non-empty input;
        // even a single-byte input becomes at least a 1-byte token plus the
        // literal byte itself.
        debug_assert!(!tmp.is_empty());
        let len = tmp.len() as u32;
        self.compressed[0..4].copy_from_slice(&len.to_le_bytes());
        self.compressed.extend_from_slice(&tmp);
        let _ = prefix_len; // explicit anchor; helps a reader follow the layout
        self.raw.clear();
        self.compressed_idx = 0;
        self.phase = EncPhase::Flushing;
    }

    /// Drain as many bytes of `self.compressed` into `output[written..]` as
    /// will fit. Returns the number of bytes written. Once the staged block
    /// is fully drained, returns to `Buffering`.
    fn drain_compressed(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.compressed.len() - self.compressed_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.compressed[self.compressed_idx..self.compressed_idx + n]);
            self.compressed_idx += n;
            *written += n;
        }
        if self.compressed_idx == self.compressed.len() {
            self.compressed.clear();
            self.compressed_idx = 0;
            self.phase = EncPhase::Buffering;
        }
    }

    /// Drain remaining bytes of the 4-byte zero terminator into `output`.
    fn drain_terminator(&mut self, output: &mut [u8], written: &mut usize) {
        while self.terminator_idx < 4 && *written < output.len() {
            output[*written] = 0;
            *written += 1;
            self.terminator_idx += 1;
        }
        if self.terminator_idx == 4 {
            self.phase = EncPhase::Done;
        }
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

        loop {
            // Always drain any staged compressed bytes first; consuming more
            // input could overwrite them.
            if self.phase == EncPhase::Flushing {
                self.drain_compressed(output, &mut written);
                if self.phase == EncPhase::Flushing {
                    // Output ran out before the block was fully drained.
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if self.phase != EncPhase::Buffering {
                // `Terminating` / `Done` are reachable only after `finish`;
                // `encode` should not see them. Bail out gracefully.
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            if consumed == input.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            // Copy as much as will fit in the current block buffer.
            let room = BLOCK_SIZE - self.raw.len();
            let take = (input.len() - consumed).min(room);
            self.raw
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;

            if self.raw.len() == BLOCK_SIZE {
                self.build_block();
                // Loop: try to drain the newly built block.
                continue;
            }
            // We consumed all the input we could without filling a block.
            return Ok(RawProgress {
                consumed,
                written,
                done: false,
            });
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Buffering => {
                    if !self.raw.is_empty() {
                        self.build_block();
                        // Fall through to flush.
                    } else {
                        self.phase = EncPhase::Terminating;
                    }
                }
                EncPhase::Flushing => {
                    self.drain_compressed(output, &mut written);
                    if self.phase == EncPhase::Flushing {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    // Drained — Buffering again. If `raw` was already empty
                    // we'll skip straight to Terminating on the next pass.
                }
                EncPhase::Terminating => {
                    self.drain_terminator(output, &mut written);
                    if self.phase == EncPhase::Terminating {
                        return Ok(RawProgress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::Done => {
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
        self.raw.clear();
        self.compressed.clear();
        self.compressed_idx = 0;
        self.terminator_idx = 0;
        self.phase = EncPhase::Buffering;
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Collecting the 4-byte little-endian block length.
    Length,
    /// Accumulating `expected_len` compressed bytes into `compressed`.
    BlockData,
    /// `decoded` holds a fully-decoded block; `decoded_idx` of it has been
    /// drained to the caller. Once drained, we return to `Length`.
    Draining,
    /// Saw a zero-length block. No more input will be consumed.
    Done,
}

pub struct Decoder {
    /// Length prefix being assembled, low byte first.
    length_buf: [u8; 4],
    length_idx: u8,
    /// Block size announced by the current length prefix.
    expected_len: usize,
    /// Bytes accumulated for the current compressed block.
    compressed: Vec<u8>,
    /// Decoded output of the current block, waiting to be emitted.
    decoded: Vec<u8>,
    decoded_idx: usize,
    phase: DecPhase,
    /// Once a corrupt sequence has been emitted, refuse further input rather
    /// than try to continue from a broken state.
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            length_buf: [0; 4],
            length_idx: 0,
            expected_len: 0,
            compressed: Vec::new(),
            decoded: Vec::new(),
            decoded_idx: 0,
            phase: DecPhase::Length,
            poisoned: false,
        }
    }

    fn drain_decoded(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.decoded.len() - self.decoded_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.decoded[self.decoded_idx..self.decoded_idx + n]);
            self.decoded_idx += n;
            *written += n;
        }
        if self.decoded_idx == self.decoded.len() {
            self.decoded.clear();
            self.decoded_idx = 0;
            self.phase = DecPhase::Length;
            self.length_idx = 0;
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
            match self.phase {
                DecPhase::Length => {
                    // Read up to 4 length bytes.
                    while self.length_idx < 4 && consumed < input.len() {
                        self.length_buf[self.length_idx as usize] = input[consumed];
                        self.length_idx += 1;
                        consumed += 1;
                    }
                    if self.length_idx < 4 {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.expected_len = u32::from_le_bytes(self.length_buf) as usize;
                    if self.expected_len == 0 {
                        self.phase = DecPhase::Done;
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.compressed.clear();
                    self.compressed.reserve(self.expected_len);
                    self.phase = DecPhase::BlockData;
                }
                DecPhase::BlockData => {
                    let need = self.expected_len - self.compressed.len();
                    let avail = input.len() - consumed;
                    let take = need.min(avail);
                    if take > 0 {
                        self.compressed
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.compressed.len() < self.expected_len {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Block fully gathered — decompress it.
                    self.decoded.clear();
                    if let Err(e) = block::decode_block(&self.compressed, &mut self.decoded) {
                        self.poisoned = true;
                        return Err(e);
                    }
                    self.decoded_idx = 0;
                    self.phase = DecPhase::Draining;
                }
                DecPhase::Draining => {
                    self.drain_decoded(output, &mut written);
                    if self.phase == DecPhase::Draining {
                        // Caller's output ran out.
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Done => {
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
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut written = 0usize;

        // Drain whatever is staged.
        if self.phase == DecPhase::Draining {
            self.drain_decoded(output, &mut written);
            if self.phase == DecPhase::Draining {
                return Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }

        match self.phase {
            DecPhase::Done => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            DecPhase::Length if self.length_idx == 0 => {
                // Stream ended cleanly at a block boundary — but without a
                // zero-length terminator. We accept this leniently: any
                // bytes already delivered are correct, and the absence of a
                // terminator just means the producer never wrote one. The
                // alternative (Error::UnexpectedEnd) would force every
                // caller to remember to call `encode` with the terminator
                // before `finish`, which is not the trait contract.
                Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: true,
                })
            }
            DecPhase::Length | DecPhase::BlockData => Err(Error::UnexpectedEnd),
            DecPhase::Draining => unreachable!(),
        }
    }

    fn raw_reset(&mut self) {
        self.length_buf = [0; 4];
        self.length_idx = 0;
        self.expected_len = 0;
        self.compressed.clear();
        self.decoded.clear();
        self.decoded_idx = 0;
        self.phase = DecPhase::Length;
        self.poisoned = false;
    }
}
