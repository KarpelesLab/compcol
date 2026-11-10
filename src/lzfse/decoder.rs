//! Streaming LZFSE decoder.
//!
//! Buffers input until a whole block (magic + header + payload) can be
//! decoded, then drains the decoded payload into the caller's output slice
//! across as many `decode` calls as the caller needs. A `bvxn` (LZVN) block
//! is decoded incrementally from its buffered payload, at most about
//! 64 KiB ahead of what the caller has taken, so its expansion is bounded
//! by the caller's output handling rather than by the block header.

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
    /// Tail of the decoded stream (at least [`HISTORY_WINDOW`] bytes once
    /// that much has been produced). `bvx2` match distances may reach back
    /// into earlier blocks, so each v2 block is decoded on top of this.
    history: Vec<u8>,
    /// Position inside the `bvxn` block being decoded (its payload is the
    /// front of `input_buf`); meaningful only in the LZVN payload state.
    lzvn: lzvn::BlockState,
}

/// Decoded bytes one `bvxn` step may add to the output backlog before the
/// caller has to drain it (a step can overshoot by less than one opcode's
/// output, [`lzvn::MAX_OPCODE_OUTPUT`]).
const LZVN_STEP: usize = 64 * 1024;

/// Largest match distance a `bvx2` block can encode (D symbol 63: base
/// 229_372 plus 15 extra bits), rounded up.
const HISTORY_WINDOW: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the next 4-byte block magic.
    AwaitMagic,
    /// Read magic; waiting for the block-specific header bytes.
    AwaitHeader(BlockKind),
    /// Header parsed; waiting for the rest of the payload, then decode + drain.
    /// An LZVN block stays in this state, payload buffered, until all of
    /// its output has been produced.
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
            history: Vec::new(),
            lzvn: lzvn::BlockState::default(),
        }
    }

    /// Total bytes `input_buf` must hold for the current state to advance.
    fn bytes_needed(&self) -> usize {
        match self.state {
            State::AwaitMagic => 4,
            State::AwaitHeader(BlockKind::Uncompressed) => 4,
            State::AwaitHeader(BlockKind::Lzvn) => 8,
            State::AwaitHeader(BlockKind::V2) => lzfse_v2::V2_HEADER_FIXED_BYTES,
            State::AwaitHeader(BlockKind::V1) => 0,
            State::AwaitPayload { payload_len, .. } => payload_len,
            State::Done => 0,
        }
    }

    /// Keep the match history bounded. The front is only discarded once it
    /// holds two windows' worth, so the memmove is amortised O(1) per byte
    /// even for tiny blocks.
    fn trim_history(&mut self) {
        if self.history.len() > 2 * HISTORY_WINDOW {
            let excess = self.history.len() - HISTORY_WINDOW;
            self.history.drain(..excess);
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
            //    only as much as the current state needs, so bytes after the
            //    end-of-stream marker are never reported as consumed.
            let need = self.bytes_needed().saturating_sub(self.input_buf.len());
            let take = need.min(input.len() - consumed);
            if take > 0 {
                self.input_buf
                    .extend_from_slice(&input[consumed..consumed + take]);
                consumed += take;
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
                        self.lzvn = lzvn::BlockState::default();
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
                            self.history
                                .extend_from_slice(&self.input_buf[..payload_len]);
                            self.trim_history();
                            self.input_buf.drain(..payload_len);
                            self.state = State::AwaitMagic;
                        }
                        BlockKind::Lzvn => {
                            // The payload is buffered, but it can expand
                            // ~135x, so produce it a slice at a time: the
                            // backlog (empty here — step 1 drained it or
                            // returned) must reach the caller before the
                            // next slice is decoded. Matches are resolved
                            // in `history`, which the slice is appended to.
                            debug_assert!(self.output_buf.is_empty());
                            let before = self.history.len();
                            let block_done = match lzvn::decode_step(
                                &self.input_buf[..payload_len],
                                decoded_size,
                                &mut self.lzvn,
                                &mut self.history,
                                LZVN_STEP,
                            ) {
                                Ok(d) => d,
                                Err(e) => {
                                    self.poisoned = true;
                                    return Err(e);
                                }
                            };
                            self.output_buf.extend_from_slice(&self.history[before..]);
                            debug_assert!(
                                self.output_buf.len() < LZVN_STEP + lzvn::MAX_OPCODE_OUTPUT
                            );
                            // Keeps at least `HISTORY_WINDOW` bytes, more
                            // than any LZVN distance (65535).
                            self.trim_history();
                            if block_done {
                                self.input_buf.drain(..payload_len);
                                self.state = State::AwaitMagic;
                            }
                        }
                        BlockKind::V2 => {
                            // The whole block (header + both payload streams)
                            // is now buffered in `payload_len` bytes. Decode in
                            // one shot. Bound the up-front output reservation by
                            // a payload-derived hint (an FSE block can expand
                            // more than LZVN, but is still bounded; the decoder
                            // enforces the exact `n_raw_bytes` internally).
                            let cap_hint = payload_len.saturating_mul(32).saturating_add(1 << 16);
                            // Decode on top of the stream history so matches
                            // can reach into earlier blocks.
                            let mut block_out = core::mem::take(&mut self.history);
                            let history_len = block_out.len();
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
                            self.output_buf.extend_from_slice(&block_out[history_len..]);
                            self.history = block_out;
                            self.trim_history();
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
        self.history.clear();
        self.lzvn = lzvn::BlockState::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::RawDecoder;
    use alloc::vec;

    /// Wrap an LZVN payload as a complete `bvxn` + `bvx$` stream.
    fn bvxn_stream(n_raw: usize, payload: &[u8]) -> Vec<u8> {
        let mut s = b"bvxn".to_vec();
        s.extend_from_slice(&(n_raw as u32).to_le_bytes());
        s.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        s.extend_from_slice(payload);
        s.extend_from_slice(b"bvx$");
        s
    }

    /// Decode `stream` with `in_chunk`-byte input slices and an
    /// `out_chunk`-byte output buffer, calling `check` after every call.
    fn decode_with(
        stream: &[u8],
        in_chunk: usize,
        out_chunk: usize,
        mut check: impl FnMut(&Decoder),
    ) -> Result<Vec<u8>, Error> {
        let mut dec = Decoder::new();
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        let mut pos = 0usize;
        loop {
            let end = pos.saturating_add(in_chunk).min(stream.len());
            let p = dec.raw_decode(&stream[pos..end], &mut buf)?;
            check(&dec);
            pos += p.consumed;
            out.extend_from_slice(&buf[..p.written]);
            if p.done {
                return Ok(out);
            }
            if p.consumed == 0 && p.written == 0 {
                assert_eq!(pos, stream.len(), "decoder stalled at {pos}");
                let p = dec.raw_finish(&mut buf)?;
                assert!(p.done && p.written == 0);
                return Ok(out);
            }
        }
    }

    /// A `bvxn` block expands up to ~135x (`lrg_m`: 2 bytes -> 271). It used
    /// to be decoded whole — into a block buffer, the history and the output
    /// backlog — before one byte reached the caller, so the caller's output
    /// limit could not bound the decoder's memory.
    #[test]
    fn lzvn_block_is_decoded_with_back_pressure() {
        const N_RAW: usize = 8 << 20;
        let mut p = vec![0xE1, b'a', 0x00, 0x01]; // 1 literal; sml_d M=3 D=1
        let mut made = 4usize;
        while made + 271 <= N_RAW {
            p.extend_from_slice(&[0xF0, 0xFF]); // lrg_m, 271 bytes
            made += 271;
        }
        while made < N_RAW {
            let m = (N_RAW - made).min(15);
            p.push(0xF0 | m as u8); // sml_m
            made += m;
        }
        p.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]); // eos
        let stream = bvxn_stream(N_RAW, &p);

        let mut peak_backlog = 0usize;
        let mut peak_history = 0usize;
        let out = decode_with(&stream, usize::MAX, 4096, |dec| {
            peak_backlog = peak_backlog.max(dec.output_buf.capacity());
            peak_history = peak_history.max(dec.history.capacity());
        })
        .unwrap();
        assert_eq!(out.len(), N_RAW);
        assert!(out.iter().all(|&b| b == b'a'));
        assert!(peak_backlog <= 256 << 10, "output backlog {peak_backlog}");
        assert!(peak_history <= 2 << 20, "history {peak_history}");
    }

    /// Text with literal runs and repeats up to 65535 bytes back — every
    /// LZVN opcode class shows up in its encoding.
    fn lzvn_sample(n: usize) -> Vec<u8> {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let mut v: Vec<u8> = Vec::with_capacity(n + 512);
        while v.len() < n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            if v.len() > 100 && s.is_multiple_of(3) {
                let d = 1 + ((s >> 8) as usize) % v.len().min(65_535);
                let l = 3 + ((s >> 40) as usize) % 400;
                let st = v.len() - d;
                for i in 0..l {
                    let b = v[st + i % d];
                    v.push(b);
                }
            } else {
                for i in 0..1 + ((s >> 30) as usize) % 40 {
                    v.push(b"abcdefgh ijk\n"[((s >> (i % 20)) as usize) % 13]);
                }
            }
        }
        v.truncate(n);
        v
    }

    /// A `bvxn` block far larger than one decode step must come out the
    /// same however the input and output are chunked, including matches
    /// that reach back across step boundaries and history trims.
    #[test]
    fn large_lzvn_block_is_chunking_independent() {
        let data = lzvn_sample(700_000);
        let payload = lzvn::encode_block(&data);
        assert!(payload.len() < data.len() / 2);
        // A stored block first, so the LZVN block starts on non-empty history.
        let mut stream = b"bvx-".to_vec();
        stream.extend_from_slice(&5u32.to_le_bytes());
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(&bvxn_stream(data.len(), &payload));
        let mut expected = b"hello".to_vec();
        expected.extend_from_slice(&data);

        for (in_chunk, out_chunk) in [
            (usize::MAX, 1 << 21),
            (usize::MAX, 1),
            (1, 1 << 16),
            (3, 7),
            (4093, 70_001),
            (usize::MAX, LZVN_STEP),
        ] {
            let out = decode_with(&stream, in_chunk, out_chunk, |dec| {
                let step = LZVN_STEP + lzvn::MAX_OPCODE_OUTPUT;
                assert!(dec.output_buf.len() - dec.output_pos <= step);
                assert!(dec.history.len() <= 2 * HISTORY_WINDOW + step);
            })
            .unwrap();
            assert!(
                out == expected,
                "mismatch with in_chunk={in_chunk} out_chunk={out_chunk}"
            );
        }
    }

    /// Step size must not change what `decode_step` produces or accepts.
    #[test]
    fn lzvn_decode_step_matches_single_pass() {
        let data = lzvn_sample(150_000);
        let payload = lzvn::encode_block(&data);
        for budget in [1usize, 2, 271, 1000, usize::MAX] {
            let mut out = b"prefix".to_vec();
            let mut st = lzvn::BlockState::default();
            let mut steps = 0usize;
            while !lzvn::decode_step(&payload, data.len(), &mut st, &mut out, budget).unwrap() {
                steps += 1;
            }
            assert_eq!(steps == 0, budget == usize::MAX);
            assert!(out[6..] == data[..], "budget {budget}");
        }
    }

    /// The declared size is enforced exactly, also when the mismatch only
    /// shows up several steps into the block.
    #[test]
    fn lzvn_block_size_mismatch_is_corrupt() {
        let data = lzvn_sample(200_000);
        let payload = lzvn::encode_block(&data);
        for n_raw in [0, 1, 100_000, data.len() - 1, data.len() + 1, 1 << 30] {
            let stream = bvxn_stream(n_raw, &payload);
            for out_chunk in [1 << 20, 4096] {
                assert_eq!(
                    decode_with(&stream, usize::MAX, out_chunk, |_| ()),
                    Err(Error::Corrupt),
                    "n_raw={n_raw}"
                );
            }
        }
        // A match may not reach before the start of its block.
        let mut stream = b"bvx-".to_vec();
        stream.extend_from_slice(&4u32.to_le_bytes());
        stream.extend_from_slice(b"abcd");
        // 1 literal, then sml_d M=3 D=2; eos.
        let p = [0x40, 0x02, b'x', 0x06, 0, 0, 0, 0, 0, 0, 0];
        stream.extend_from_slice(&bvxn_stream(4, &p));
        assert_eq!(
            decode_with(&stream, usize::MAX, 64, |_| ()),
            Err(Error::Corrupt)
        );
    }
}
