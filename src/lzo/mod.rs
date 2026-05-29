//! LZO1X-1 (Lempel–Ziv–Oberhumer) with a tiny multi-block framing for
//! streaming.
//!
//! Reference: <https://www.oberhumer.com/opensource/lzo/> for the algorithm,
//! and <https://docs.kernel.org/staging/lzo.html> for the wire-format details.
//!
//! The raw LZO1X block is self-delimiting (it ends with the canonical
//! `0x11 0x00 0x00` end-of-stream marker), but to round-trip arbitrary-length
//! streams through this crate's streaming trait we layer a minimal multi-block
//! framing on top, identical to [`crate::lz4`]'s framing:
//!
//! ```text
//! stream := block* terminator
//! block  := u32_le(N != 0) || N bytes of LZO1X block payload
//! terminator := u32_le(0)
//! ```
//!
//! The encoder buffers up to [`BLOCK_SIZE`] bytes of raw input, then emits a
//! length-prefixed compressed block. `finish` flushes any trailing partial
//! block and then writes the zero-length terminator. The decoder reads a
//! length, accumulates that many bytes, decompresses them, and emits the
//! result; it stops at the first zero-length terminator.
//!
//! This is intentionally not the `lzop`/`.lzo` container format (which has a
//! magic header, file metadata, and per-block uncompressed-size + adler32
//! fields). A higher-level container could be layered on top later.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

pub mod block;

/// Raw-input block size. Capped at 48 KiB so the encoder's worst-case
/// back-reference distance fits within the LZO1X format's `M4_MAX_DISTANCE`
/// of 49151 bytes (every byte we accept must be reachable from the *end*
/// of the block).
pub const BLOCK_SIZE: usize = 48 * 1024;

/// Zero-sized marker type implementing [`Algorithm`] for LZO.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzo;

impl Algorithm for Lzo {
    const NAME: &'static str = "lzo";
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
    /// `compressed` holds an encoded block (with its 4-byte length prefix)
    /// waiting to be drained to the caller's output buffer.
    Flushing,
    /// All blocks flushed; waiting to emit the 4-byte zero terminator.
    Terminating,
    /// Terminator fully written.
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
        self.compressed.clear();
        self.compressed.extend_from_slice(&[0, 0, 0, 0]);
        let mut tmp = Vec::with_capacity(block::compress_bound(self.raw.len()));
        block::encode_block(&self.raw, &mut tmp);
        debug_assert!(!tmp.is_empty());
        let len = tmp.len() as u32;
        self.compressed[0..4].copy_from_slice(&len.to_le_bytes());
        self.compressed.extend_from_slice(&tmp);
        self.raw.clear();
        self.compressed_idx = 0;
        self.phase = EncPhase::Flushing;
    }

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
            if self.phase == EncPhase::Flushing {
                self.drain_compressed(output, &mut written);
                if self.phase == EncPhase::Flushing {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if self.phase != EncPhase::Buffering {
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

            let room = BLOCK_SIZE - self.raw.len();
            let take = (input.len() - consumed).min(room);
            self.raw
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;

            if self.raw.len() == BLOCK_SIZE {
                self.build_block();
                continue;
            }
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
    Length,
    BlockData,
    Draining,
    Done,
}

pub struct Decoder {
    length_buf: [u8; 4],
    length_idx: u8,
    expected_len: usize,
    compressed: Vec<u8>,
    decoded: Vec<u8>,
    decoded_idx: usize,
    phase: DecPhase,
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
                    // Defend against malformed/malicious length prefixes
                    // (see lz4's matching guard). Our encoder caps at
                    // compress_bound(BLOCK_SIZE); double the cap for
                    // headroom against foreign-encoder streams that
                    // packed less efficiently.
                    let max_block = block::compress_bound(BLOCK_SIZE)
                        .saturating_add(4)
                        .saturating_mul(2);
                    if self.expected_len > max_block {
                        self.poisoned = true;
                        return Err(Error::Corrupt);
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
            DecPhase::Length if self.length_idx == 0 => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
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
