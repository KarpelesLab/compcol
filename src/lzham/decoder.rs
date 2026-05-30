//! Streaming `LZH0` container parser.
//!
//! Reads the 13-byte header, validates the magic and `dict_size_log2`
//! field, and then returns [`Error::Unsupported`] when the inner LZHAM
//! bitstream would need to be decoded — see the module-level docs for
//! why the inner codec is out of scope.
//!
//! The one decodable case is `uncompressed_size == 0`: a well-formed
//! `LZH0` stream of an empty input file produces no decoded bytes, so we
//! report `StreamEnd` immediately after the header. This lets factory
//! round-trips against externally-produced empty fixtures succeed
//! without ever touching the codec.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::{HEADER_LEN, MAGIC, MAX_DICT_LOG2, MIN_DICT_LOG2};

/// Where in the parse pipeline the decoder currently is. Header parsing
/// is byte-by-byte across `raw_decode` calls so the decoder works under
/// any input chunking, then payload handling forks on the parsed
/// `uncompressed_size` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating the 13-byte header into `header_buf`.
    Header,
    /// Header parsed; `uncompressed_size == 0` so the stream is already
    /// complete (no payload needed). Caller can drain via `finish`.
    EmptyDone,
    /// Header parsed and the stream has a non-zero payload, but this
    /// build has no LZHAM bitstream decoder. The next call that asks
    /// the decoder to produce a byte returns `Error::Unsupported`.
    PayloadUnsupported,
    /// Reached either via `EmptyDone` after `finish`, or via an
    /// unrecoverable error. Once here, all subsequent calls return
    /// errors or the cached terminal status.
    Done,
}

/// Streaming `LZH0` container decoder.
///
/// Useful for: detecting an LZHAM stream by its magic, validating the
/// outer header, distinguishing a benign empty stream from a real
/// payload (the latter currently returns `Error::Unsupported`).
#[derive(Debug)]
pub struct Decoder {
    state: State,
    /// Header bytes accumulated so far (0..HEADER_LEN). We accumulate
    /// because the caller may chunk input arbitrarily — even a single
    /// byte per call.
    header_buf: Vec<u8>,
    /// Set true after we've returned a hard error from `raw_decode` or
    /// `raw_finish`. Mirrors the deflate/zlib poison-flag pattern: any
    /// further call without `reset` returns `Error::Corrupt`.
    poisoned: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            state: State::Header,
            header_buf: Vec::new(),
            poisoned: false,
        }
    }

    /// Push bytes into `header_buf` from `input`, stopping when the
    /// buffer is full. Returns how many bytes were taken.
    fn fill_header(&mut self, input: &[u8]) -> usize {
        let need = HEADER_LEN - self.header_buf.len();
        let take = need.min(input.len());
        self.header_buf.extend_from_slice(&input[..take]);
        take
    }

    /// Once `header_buf` holds the full 13 bytes, validate the magic
    /// and field ranges and transition to the appropriate post-header
    /// state. Returns an error for malformed headers; never panics on
    /// short buffers.
    fn finalise_header(&mut self) -> Result<(), Error> {
        debug_assert_eq!(self.header_buf.len(), HEADER_LEN);
        if self.header_buf[..4] != MAGIC {
            return Err(Error::BadHeader);
        }
        let dict_log2 = self.header_buf[4];
        if !(MIN_DICT_LOG2..=MAX_DICT_LOG2).contains(&dict_log2) {
            // The reference codec rejects out-of-range dict sizes at
            // init time with LZHAM_DECOMP_STATUS_INVALID_PARAMETER —
            // treat the same way at the framing layer.
            return Err(Error::BadHeader);
        }
        // Little-endian uint64 uncompressed size.
        let uncompressed_size = u64::from_le_bytes([
            self.header_buf[5],
            self.header_buf[6],
            self.header_buf[7],
            self.header_buf[8],
            self.header_buf[9],
            self.header_buf[10],
            self.header_buf[11],
            self.header_buf[12],
        ]);
        if uncompressed_size == 0 {
            // An empty source file produces an empty payload. We don't
            // need the inner codec for this case — declare success
            // straight away.
            self.state = State::EmptyDone;
        } else {
            self.state = State::PayloadUnsupported;
        }
        Ok(())
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        match self.state {
            State::Header => {
                let consumed = self.fill_header(input);
                // Once the 13-byte header has landed, validate it. The
                // EmptyDone path emits Done only on finish, and the
                // PayloadUnsupported path errors out a few lines below.
                if self.header_buf.len() == HEADER_LEN
                    && let Err(e) = self.finalise_header()
                {
                    self.poisoned = true;
                    return Err(e);
                }
                if matches!(self.state, State::PayloadUnsupported) {
                    // The inner codec is not implemented in this build.
                    // Refuse to silently drop bytes — surface the gap.
                    self.poisoned = true;
                    return Err(Error::Unsupported);
                }
                Ok(RawProgress {
                    consumed,
                    written: 0,
                    done: matches!(self.state, State::EmptyDone),
                })
            }
            State::EmptyDone => {
                // Already at end-of-stream; further input is no-op.
                Ok(RawProgress {
                    consumed: 0,
                    written: 0,
                    done: true,
                })
            }
            State::PayloadUnsupported => {
                self.poisoned = true;
                Err(Error::Unsupported)
            }
            State::Done => Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            }),
        }
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        match self.state {
            State::Header => {
                // Partial header at EOF. If we never received any bytes
                // at all the stream is just empty input — surface that
                // as UnexpectedEnd, consistent with how the bzip2/lzma
                // decoders treat "finish before stream parsed".
                self.poisoned = true;
                Err(Error::UnexpectedEnd)
            }
            State::EmptyDone => {
                self.state = State::Done;
                Ok(RawProgress {
                    consumed: 0,
                    written: 0,
                    done: true,
                })
            }
            State::PayloadUnsupported => {
                self.poisoned = true;
                Err(Error::Unsupported)
            }
            State::Done => Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            }),
        }
    }

    fn raw_reset(&mut self) {
        self.state = State::Header;
        self.header_buf.clear();
        self.poisoned = false;
    }
}
