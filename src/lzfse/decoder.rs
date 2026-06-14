//! Streaming LZFSE decoder.
//!
//! Buffers input until a whole block (magic + header + payload) can be
//! decoded, then drains the decoded payload into the caller's output slice
//! across as many `decode` calls as the caller needs.

use alloc::vec::Vec;

use crate::error::Error;
use crate::lzfse::{lzfse_v2, lzvn};
use crate::traits::{RawDecoder, RawProgress};

/// 4-byte block magics.
const MAGIC_UNCOMPRESSED: [u8; 4] = *b"bvx-";
const MAGIC_LZVN: [u8; 4] = *b"bvxn";
const MAGIC_V1: [u8; 4] = *b"bvx1";
const MAGIC_V2: [u8; 4] = *b"bvx2";
const MAGIC_EOS: [u8; 4] = *b"bvx$";

/// Streaming decoder state machine.
pub struct Decoder {
    /// Bytes the caller has fed us that we haven't yet consumed.
    input_buf: Vec<u8>,
    /// Decoded bytes pending delivery to the caller.
    output_buf: Vec<u8>,
    /// Read cursor into `output_buf`. We keep the buffer around so we don't
    /// have to shift bytes on every partial drain; once `output_pos ==
    /// output_buf.len()`, we clear both.
    output_pos: usize,
    /// State.
    state: State,
    /// Once we hit the end-of-stream marker (or have signalled it once), we
    /// short-circuit further calls.
    eos: bool,
    /// Set on any decode error so callers don't accidentally resume.
    poisoned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the next 4-byte block magic.
    AwaitMagic,
    /// Read magic; waiting for the block-specific header bytes.
    AwaitHeader(BlockKind),
    /// Header parsed; waiting for the rest of the payload, then decode + drain.
    AwaitPayload {
        kind: BlockKind,
        /// For uncompressed blocks: bytes to copy. For LZVN: compressed bytes
        /// to decode.
        payload_len: usize,
        /// For LZVN: expected decoded size from the header.
        decoded_size: usize,
    },
    /// Stream is finished.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Uncompressed,
    Lzvn,
    /// `bvx2` (LZFSE v2): FSE + LZ77. Decoded by [`lzfse_v2::decode_block`]
    /// once the whole block (variable-length header + both payload streams)
    /// is buffered.
    V2,
    /// `bvx1` (LZFSE v1, uncompressed-freq variant): not emitted by modern
    /// encoders; returns [`Error::Unsupported`].
    V1,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            input_buf: Vec::new(),
            output_buf: Vec::new(),
            output_pos: 0,
            state: State::AwaitMagic,
            eos: false,
            poisoned: false,
        }
    }

    fn raw_decode_inner(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            // 1. Drain any pending decoded output first.
            if self.output_pos < self.output_buf.len() {
                let want = (self.output_buf.len() - self.output_pos).min(output.len() - written);
                output[written..written + want]
                    .copy_from_slice(&self.output_buf[self.output_pos..self.output_pos + want]);
                self.output_pos += want;
                written += want;
                if self.output_pos == self.output_buf.len() {
                    // Fully drained; reset.
                    self.output_buf.clear();
                    self.output_pos = 0;
                }
                if written == output.len() {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
                // If we just drained and output still has room, loop to
                // try to make more progress.
            }

            // 2. If we've already hit end-of-stream, signal done.
            if self.eos {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: true,
                });
            }

            // 3. Pull from caller's `input` into `input_buf`. We pull lazily:
            //    only as much as the current state needs.
            if consumed < input.len() {
                self.input_buf.extend_from_slice(&input[consumed..]);
                consumed = input.len();
            }

            // 4. Advance the state machine.
            match self.state {
                State::AwaitMagic => {
                    if self.input_buf.len() < 4 {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let mut magic = [0u8; 4];
                    magic.copy_from_slice(&self.input_buf[..4]);
                    // Drop the magic.
                    self.input_buf.drain(..4);
                    match magic {
                        MAGIC_EOS => {
                            self.state = State::Done;
                            self.eos = true;
                            // loop to emit done on next iteration
                        }
                        MAGIC_UNCOMPRESSED => {
                            self.state = State::AwaitHeader(BlockKind::Uncompressed);
                        }
                        MAGIC_LZVN => {
                            self.state = State::AwaitHeader(BlockKind::Lzvn);
                        }
                        MAGIC_V1 => {
                            self.state = State::AwaitHeader(BlockKind::V1);
                        }
                        MAGIC_V2 => {
                            self.state = State::AwaitHeader(BlockKind::V2);
                        }
                        _ => {
                            self.poisoned = true;
                            return Err(Error::BadHeader);
                        }
                    }
                }

                State::AwaitHeader(kind) => match kind {
                    BlockKind::Uncompressed => {
                        // 4-byte LE n_raw_bytes.
                        if self.input_buf.len() < 4 {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        let n_raw = u32::from_le_bytes([
                            self.input_buf[0],
                            self.input_buf[1],
                            self.input_buf[2],
                            self.input_buf[3],
                        ]) as usize;
                        self.input_buf.drain(..4);
                        self.state = State::AwaitPayload {
                            kind: BlockKind::Uncompressed,
                            payload_len: n_raw,
                            decoded_size: n_raw,
                        };
                    }
                    BlockKind::Lzvn => {
                        // 8-byte header: n_raw_bytes (u32 LE) + n_payload_bytes (u32 LE).
                        if self.input_buf.len() < 8 {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        let n_raw = u32::from_le_bytes([
                            self.input_buf[0],
                            self.input_buf[1],
                            self.input_buf[2],
                            self.input_buf[3],
                        ]) as usize;
                        let n_payload = u32::from_le_bytes([
                            self.input_buf[4],
                            self.input_buf[5],
                            self.input_buf[6],
                            self.input_buf[7],
                        ]) as usize;
                        self.input_buf.drain(..8);
                        self.state = State::AwaitPayload {
                            kind: BlockKind::Lzvn,
                            payload_len: n_payload,
                            decoded_size: n_raw,
                        };
                    }
                    BlockKind::V2 => {
                        // The v2 header is variable-length (FSE frequency
                        // tables follow the fixed packed fields). Buffer the
                        // fixed 28 bytes (post-magic: n_raw + three u64 words)
                        // first so we can read `header_size` and the payload
                        // sizes, then arrange to buffer the whole block (header
                        // + payload) before decoding it in one shot.
                        let fixed = lzfse_v2::V2_HEADER_FIXED_BYTES;
                        if self.input_buf.len() < fixed {
                            return Ok(RawProgress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                        let header_size = match lzfse_v2::parse_header_size(&self.input_buf) {
                            Ok(h) => h as usize,
                            Err(e) => {
                                self.poisoned = true;
                                return Err(e);
                            }
                        };
                        let n_payload = match lzfse_v2::parse_payload_size(&self.input_buf) {
                            Ok(n) => n as usize,
                            Err(e) => {
                                self.poisoned = true;
                                return Err(e);
                            }
                        };
                        // `header_size` includes the 4-byte magic we already
                        // dropped; remaining block bytes after the magic are
                        // `header_size - 4 + n_payload`.
                        let header_len = match header_size.checked_sub(4) {
                            Some(h) if h >= fixed => h,
                            _ => {
                                self.poisoned = true;
                                return Err(Error::Corrupt);
                            }
                        };
                        let block_len = match header_len.checked_add(n_payload) {
                            Some(b) => b,
                            None => {
                                self.poisoned = true;
                                return Err(Error::Corrupt);
                            }
                        };
                        self.state = State::AwaitPayload {
                            kind: BlockKind::V2,
                            payload_len: block_len,
                            decoded_size: 0,
                        };
                    }
                    BlockKind::V1 => {
                        self.poisoned = true;
                        return Err(Error::Unsupported);
                    }
                },

                State::AwaitPayload {
                    kind,
                    payload_len,
                    decoded_size,
                } => {
                    if self.input_buf.len() < payload_len {
                        return Ok(RawProgress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    match kind {
                        BlockKind::Uncompressed => {
                            // Copy payload_len bytes into output_buf for drain.
                            self.output_buf
                                .extend_from_slice(&self.input_buf[..payload_len]);
                            self.input_buf.drain(..payload_len);
                            self.state = State::AwaitMagic;
                        }
                        BlockKind::Lzvn => {
                            // Decode in one shot into output_buf.
                            //
                            // Bound the capacity hint by what the payload could
                            // plausibly produce so an attacker-controlled
                            // `decoded_size` (n_raw_bytes) cannot force a huge
                            // up-front allocation (DoS / OOM): a single 1-byte
                            // LZVN opcode expands to at most ~16 output bytes.
                            // `decode_block` still enforces the real output size
                            // against `decoded_size`, so under-hinting only makes
                            // the Vec grow as actual bytes are produced.
                            let capacity_hint =
                                decoded_size.min(payload_len.saturating_mul(16).saturating_add(64));
                            let mut block_out = Vec::with_capacity(capacity_hint);
                            if let Err(e) = lzvn::decode_block(
                                &self.input_buf[..payload_len],
                                payload_len,
                                decoded_size,
                                &mut block_out,
                            ) {
                                self.poisoned = true;
                                return Err(e);
                            }
                            self.output_buf.append(&mut block_out);
                            self.input_buf.drain(..payload_len);
                            self.state = State::AwaitMagic;
                        }
                        BlockKind::V2 => {
                            // The whole block (header + both payload streams)
                            // is now buffered in `payload_len` bytes. Decode in
                            // one shot. Bound the up-front output reservation by
                            // a payload-derived hint (an FSE block can expand
                            // more than LZVN, but is still bounded; the decoder
                            // enforces the exact `n_raw_bytes` internally).
                            let cap_hint = payload_len.saturating_mul(32).saturating_add(1 << 16);
                            let mut block_out = Vec::new();
                            match lzfse_v2::decode_block(
                                &self.input_buf[..payload_len],
                                &mut block_out,
                                cap_hint,
                            ) {
                                Ok(consumed_block) => {
                                    debug_assert_eq!(consumed_block, payload_len);
                                }
                                Err(e) => {
                                    self.poisoned = true;
                                    return Err(e);
                                }
                            }
                            self.output_buf.append(&mut block_out);
                            self.input_buf.drain(..payload_len);
                            self.state = State::AwaitMagic;
                        }
                        BlockKind::V1 => {
                            // Unreachable — header step would have errored.
                            self.poisoned = true;
                            return Err(Error::Unsupported);
                        }
                    }
                }

                State::Done => {
                    self.eos = true;
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: true,
                    });
                }
            }
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
        self.raw_decode_inner(input, output)
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        // finish drains any pending output and, if the stream has reached
        // the end-of-stream marker, returns `done`. Otherwise we surface
        // an UnexpectedEnd to signal truncation.
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let p = self.raw_decode_inner(&[], output)?;
        if p.done {
            return Ok(p);
        }
        // No more input is coming. If we haven't seen the EOS marker but
        // we have nothing buffered and nothing pending, treat as
        // unexpected-end. If we still have decoded bytes to drain, signal
        // OutputFull-style (done=false, written>0).
        if p.written > 0 || !self.output_buf.is_empty() {
            return Ok(p);
        }
        if self.state == State::AwaitMagic && self.input_buf.is_empty() {
            // No partial block in flight. Empty input followed by finish on
            // a fresh decoder is fine — return StreamEnd.
            self.eos = true;
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        // Mid-block at EOI — truncated.
        self.poisoned = true;
        Err(Error::UnexpectedEnd)
    }

    fn raw_reset(&mut self) {
        self.input_buf.clear();
        self.output_buf.clear();
        self.output_pos = 0;
        self.state = State::AwaitMagic;
        self.eos = false;
        self.poisoned = false;
    }
}
