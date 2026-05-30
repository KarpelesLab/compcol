//! StuffIt method-13 payload decoder.
//!
//! Method 13 carries no in-band container framing — the raw payload *is*
//! the (undocumented) LZ+Huffman bitstream, and the uncompressed length
//! lives in the surrounding SIT member header. This decoder therefore
//! accepts the length out of band (see [`Decoder::with_unpack_size`],
//! mirroring [`crate::rar2`]).
//!
//! Because the bitstream format is undocumented and unvalidatable from
//! this side (see the module docs in [`super`]), the payload decode path
//! returns [`Error::Unsupported`]. The one trivially-correct case is an
//! **empty member** (`unpack_size == 0`): it produces no output, so the
//! decoder reports end-of-stream immediately without touching the
//! (unimplemented) bitstream codec. This lets a caller that knows a member
//! is empty round-trip cleanly.
//!
//! The decoder is a resumable state machine and works under arbitrary
//! input chunking, including one byte at a time.

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `unpack_size == Some(0)`: empty member, nothing to decode. Caller
    /// drains via `finish`.
    EmptyDone,
    /// The member has payload (or an unspecified length); the method-13
    /// bitstream codec is not implemented in this build. Any call that
    /// would consume payload bytes returns `Error::Unsupported`.
    PayloadUnsupported,
    /// Terminal: reached via `EmptyDone` after `finish`, or after a hard
    /// error.
    Done,
}

/// Streaming StuffIt method-13 decoder.
///
/// Construct with [`Decoder::new`] (length unspecified) or
/// [`Decoder::with_unpack_size`] (caller-supplied uncompressed length).
/// The payload decode path is currently [`Error::Unsupported`]; only an
/// explicitly-empty member decodes (to zero bytes).
#[derive(Debug)]
pub struct Decoder {
    state: State,
    /// The state a fresh / freshly-reset decoder starts in, fixed at
    /// construction time. `reset` restores `state` to this.
    start_state: State,
    poisoned: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Build a decoder with no out-of-band length supplied. The payload is
    /// treated as non-empty and is `Unsupported`.
    pub const fn new() -> Self {
        Self {
            state: State::PayloadUnsupported,
            start_state: State::PayloadUnsupported,
            poisoned: false,
        }
    }

    /// Build a decoder told the member's uncompressed length out of band
    /// (the SIT container's convention — method 13 stores no in-band
    /// length). A length of `0` is decodable (empty output); any other
    /// length selects the `Unsupported` payload path.
    pub const fn with_unpack_size(unpack_size: u64) -> Self {
        let start_state = if unpack_size == 0 {
            State::EmptyDone
        } else {
            State::PayloadUnsupported
        };
        Self {
            state: start_state,
            start_state,
            poisoned: false,
        }
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        match self.state {
            State::EmptyDone => Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            }),
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
        // Restore the construction-time semantics, preserving config as
        // the trait contract requires.
        self.state = self.start_state;
        self.poisoned = false;
    }
}
