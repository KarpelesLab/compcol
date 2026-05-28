//! Run-length encoding.
//!
//! Wire format: a sequence of `[count: u8][byte: u8]` pairs, where `count`
//! is in `1..=255`. Runs longer than 255 are split across multiple pairs.
//! A `count` of `0` is reserved as a corruption marker.
//!
//! This algorithm is not chosen for compression ratio — it is the smallest
//! interesting state machine for validating the streaming trait shape.

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Zero-sized marker type implementing [`Algorithm`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Rle;

impl Algorithm for Rle {
    const NAME: &'static str = "rle";
    type Encoder = Encoder;
    type Decoder = Decoder;

    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── encoder ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum EncState {
    /// No run in progress; encoder is fresh or just flushed.
    Empty,
    /// Accumulating a run of `byte`; `count` is `1..=255`.
    Run { byte: u8, count: u8 },
    /// A `[count][value]` pair was started in the previous call but only the
    /// count made it into the caller's output. `value` is owed on the next
    /// available output byte.
    PartialPair { value: u8 },
}

#[derive(Debug, Clone, Copy)]
pub struct Encoder {
    state: EncState,
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            state: EncState::Empty,
        }
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
            // Always finish any owed value byte first.
            if let EncState::PartialPair { value } = self.state {
                if written == output.len() {
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
                output[written] = value;
                written += 1;
                self.state = EncState::Empty;
            }

            // Nothing more we can do without more input.
            if consumed == input.len() {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }

            let b = input[consumed];

            match self.state {
                EncState::Empty => {
                    self.state = EncState::Run { byte: b, count: 1 };
                    consumed += 1;
                }
                EncState::Run { byte, count } if byte == b && count < u8::MAX => {
                    self.state = EncState::Run {
                        byte,
                        count: count + 1,
                    };
                    consumed += 1;
                }
                EncState::Run { byte, count } => {
                    // Need to flush this pair before we can keep going.
                    if written == output.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    output[written] = count;
                    written += 1;
                    if written == output.len() {
                        // Only the count fit; remember to emit the value later.
                        self.state = EncState::PartialPair { value: byte };
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    output[written] = byte;
                    written += 1;
                    self.state = EncState::Empty;
                    // Loop continues — we still have not consumed `b`.
                }
                EncState::PartialPair { .. } => {
                    // Already handled at the top of the loop; unreachable here.
                    debug_assert!(false, "PartialPair should have been drained");
                }
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        // Drain a pending value byte first.
        if let EncState::PartialPair { value } = self.state {
            if written == output.len() {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            output[written] = value;
            written += 1;
            self.state = EncState::Empty;
        }

        // Emit the trailing run, if any.
        if let EncState::Run { byte, count } = self.state {
            if written == output.len() {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            output[written] = count;
            written += 1;
            if written == output.len() {
                self.state = EncState::PartialPair { value: byte };
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            output[written] = byte;
            written += 1;
            self.state = EncState::Empty;
        }

        Ok(Progress {
            consumed: 0,
            written,
            done: matches!(self.state, EncState::Empty),
        })
    }

    fn reset(&mut self) {
        self.state = EncState::Empty;
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum DecState {
    /// Waiting for the next pair's count byte.
    ExpectCount,
    /// Read a count; waiting for the value byte that pairs with it.
    ExpectValue { count: u8 },
    /// Emitting a fully-decoded run; `remaining` bytes of `value` still owed.
    EmittingRun { value: u8, remaining: u8 },
}

#[derive(Debug, Clone, Copy)]
pub struct Decoder {
    state: DecState,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            state: DecState::ExpectCount,
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.state {
                DecState::EmittingRun { value, remaining } => {
                    if written == output.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let space = output.len() - written;
                    let n = core::cmp::min(remaining as usize, space);
                    for slot in &mut output[written..written + n] {
                        *slot = value;
                    }
                    written += n;
                    let new_remaining = remaining - n as u8;
                    if new_remaining == 0 {
                        self.state = DecState::ExpectCount;
                    } else {
                        self.state = DecState::EmittingRun {
                            value,
                            remaining: new_remaining,
                        };
                        // Output buffer is full, so we cannot continue.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecState::ExpectCount => {
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let count = input[consumed];
                    consumed += 1;
                    if count == 0 {
                        return Err(Error::Corrupt);
                    }
                    self.state = DecState::ExpectValue { count };
                }
                DecState::ExpectValue { count } => {
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let value = input[consumed];
                    consumed += 1;
                    self.state = DecState::EmittingRun {
                        value,
                        remaining: count,
                    };
                }
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        if let DecState::EmittingRun { value, remaining } = self.state {
            let space = output.len() - written;
            let n = core::cmp::min(remaining as usize, space);
            for slot in &mut output[written..written + n] {
                *slot = value;
            }
            written += n;
            let new_remaining = remaining - n as u8;
            if new_remaining == 0 {
                self.state = DecState::ExpectCount;
            } else {
                self.state = DecState::EmittingRun {
                    value,
                    remaining: new_remaining,
                };
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
        }

        match self.state {
            DecState::ExpectCount => Ok(Progress {
                consumed: 0,
                written,
                done: true,
            }),
            DecState::ExpectValue { .. } => Err(Error::UnexpectedEnd),
            DecState::EmittingRun { .. } => Ok(Progress {
                consumed: 0,
                written,
                done: false,
            }),
        }
    }

    fn reset(&mut self) {
        self.state = DecState::ExpectCount;
    }
}
