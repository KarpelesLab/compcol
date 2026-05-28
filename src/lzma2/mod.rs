//! LZMA2 — chunked container around LZMA used as the inner format of `.xz`.
//!
//! Reference: <https://tukaani.org/xz/xz-file-format.txt> (section 5.3.1 plus
//! the `xz-embedded` / liblzma source for the chunk-level layout, which the
//! `.xz` spec defers to).
//!
//! An LZMA2 stream is a sequence of chunks, each introduced by a single
//! **control byte**:
//!
//! | control       | meaning                                                  |
//! |---------------|----------------------------------------------------------|
//! | `0x00`        | end-of-stream marker, no more chunks                     |
//! | `0x01`        | uncompressed chunk, dictionary reset                     |
//! | `0x02`        | uncompressed chunk, no reset                             |
//! | `0x80..=0xFF` | LZMA-compressed chunk (state/dict reset bits in 5..=7)   |
//!
//! Any other value is malformed.
//!
//! **Uncompressed chunk header** (3 bytes total, then raw data):
//!
//! ```text
//! +------+-------+-------+----------- ... -----------+
//! | ctrl | size1 | size0 |        raw bytes          |
//! +------+-------+-------+----------- ... -----------+
//! ```
//!
//! `size1`/`size0` form a 16-bit **big-endian** value equal to
//! `uncompressed_size - 1`, so a chunk carries between 1 and 65 536 bytes.
//!
//! **Compressed chunk header** (5 or 6 bytes, then compressed payload). The
//! lower five bits of the control byte plus two big-endian size bytes encode
//! `uncompressed_size - 1` (21 bits, up to 2 MiB); two further big-endian
//! bytes encode `compressed_size - 1` (16 bits, up to 64 KiB); a properties
//! byte follows if the control byte's reset flags require it.
//!
//! ## Status: stored-only encoder
//!
//! This iteration ships:
//!
//! * a **decoder** that handles uncompressed-only LZMA2 streams (control
//!   bytes `0x00`, `0x01`, `0x02`). A compressed-chunk control byte
//!   (`0x80..=0xFF`) returns [`Error::Unsupported`] cleanly. Invalid control
//!   bytes return [`Error::Corrupt`].
//! * an **encoder** that emits *only* type-`0x01` chunks (uncompressed,
//!   dictionary reset), capped at 64 KiB of uncompressed data per chunk,
//!   followed by a `0x00` end-of-stream marker on `finish`.
//!
//! Real LZMA-compressed chunks are deliberately out of scope here; a parallel
//! work item implements the LZMA range codec, and once it lands a follow-up
//! can wire it into this module without changing the public surface.

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Largest payload an encoder will pack into a single 0x01 chunk.
/// The spec allows up to 65 536 (2^16) bytes per uncompressed chunk; staying
/// at 65 536 maximises bytes per header byte triple.
const ENC_CHUNK_SIZE: usize = 65_536;

/// Zero-sized marker type implementing [`Algorithm`] for LZMA2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzma2;

impl Algorithm for Lzma2 {
    const NAME: &'static str = "lzma2";
    type Encoder = Encoder;
    type Decoder = Decoder;

    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DecPhase {
    /// Waiting for the next chunk's control byte.
    Control,
    /// Read the control byte for an uncompressed chunk; need 2 more bytes for
    /// the big-endian `(size - 1)` field.
    UncompSize { ctrl: u8, idx: u8, hi: u8 },
    /// Streaming out `remaining` raw bytes of an uncompressed chunk.
    UncompData { remaining: u32 },
    /// Hit the `0x00` end-of-stream marker; nothing more to read or emit.
    Done,
}

/// Streaming LZMA2 decoder. Handles uncompressed-only streams; refuses
/// compressed chunks with [`Error::Unsupported`].
pub struct Decoder {
    phase: DecPhase,
    poisoned: bool,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            phase: DecPhase::Control,
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
            let initial_consumed = consumed;
            let initial_written = written;

            match self.phase {
                DecPhase::Control => {
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let ctrl = input[consumed];
                    consumed += 1;
                    match ctrl {
                        0x00 => {
                            self.phase = DecPhase::Done;
                        }
                        0x01 | 0x02 => {
                            self.phase = DecPhase::UncompSize {
                                ctrl,
                                idx: 0,
                                hi: 0,
                            };
                        }
                        0x80..=0xFF => {
                            // Compressed LZMA chunk — out of scope in this
                            // iteration. Poison the decoder so callers can't
                            // keep poking it.
                            return Err(self.poison(Error::Unsupported));
                        }
                        _ => {
                            // 0x03..=0x7F are not assigned by the spec.
                            return Err(self.poison(Error::Corrupt));
                        }
                    }
                }
                DecPhase::UncompSize { ctrl, idx, hi } => {
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let b = input[consumed];
                    consumed += 1;
                    if idx == 0 {
                        self.phase = DecPhase::UncompSize {
                            ctrl,
                            idx: 1,
                            hi: b,
                        };
                    } else {
                        // size = ((hi << 8) | b) + 1, always in 1..=65_536.
                        let size = ((hi as u32) << 8) | (b as u32);
                        let size = size + 1;
                        self.phase = DecPhase::UncompData { remaining: size };
                    }
                }
                DecPhase::UncompData { remaining } => {
                    if remaining == 0 {
                        self.phase = DecPhase::Control;
                        continue;
                    }
                    if consumed == input.len() || written == output.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let in_left = input.len() - consumed;
                    let out_left = output.len() - written;
                    let n = core::cmp::min(remaining as usize, core::cmp::min(in_left, out_left));
                    output[written..written + n].copy_from_slice(&input[consumed..consumed + n]);
                    consumed += n;
                    written += n;
                    let new_remaining = remaining - n as u32;
                    self.phase = if new_remaining == 0 {
                        DecPhase::Control
                    } else {
                        DecPhase::UncompData {
                            remaining: new_remaining,
                        }
                    };
                }
                DecPhase::Done => {
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
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // Drain any pending data using an empty input slice.
        let empty: [u8; 0] = [];
        let p = self.decode(&empty, output)?;
        match self.phase {
            DecPhase::Done => Ok(Progress {
                consumed: 0,
                written: p.written,
                done: true,
            }),
            DecPhase::Control => {
                // No 0x00 marker was seen. The xz layer above us delimits the
                // stream by block size, so an "empty" finish here is legal
                // only if no chunks were started.
                Err(self.poison(Error::UnexpectedEnd))
            }
            _ => Err(self.poison(Error::UnexpectedEnd)),
        }
    }

    fn reset(&mut self) {
        self.phase = DecPhase::Control;
        self.poisoned = false;
    }
}

// ─── encoder ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EncPhase {
    /// No partial chunk in flight; ready to start a new one or finish.
    Idle,
    /// Mid-header: writing 3 chunk-header bytes for a chunk that will carry
    /// `payload` total bytes of data, `header_idx` bytes of header already
    /// emitted.
    HeaderOut {
        payload: u32,
        header_idx: u8,
        header: [u8; 3],
    },
    /// Mid-payload: `remaining` bytes of the current chunk still need to be
    /// emitted into output (after being consumed from input).
    PayloadOut { remaining: u32 },
    /// `finish` was called; we still owe the `0x00` end-of-stream marker.
    NeedEosMarker,
    /// Finished; nothing more to emit.
    Done,
}

/// Streaming LZMA2 encoder. Emits only type-`0x01` (uncompressed, dictionary
/// reset) chunks plus a `0x00` end-of-stream marker — see the module header
/// for context.
pub struct Encoder {
    phase: EncPhase,
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            phase: EncPhase::Idle,
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the 3-byte header for an uncompressed-type-0x01 chunk of `size`
/// bytes. `size` must satisfy `1 <= size <= 65_536`.
fn make_uncomp_header(size: u32) -> [u8; 3] {
    debug_assert!((1..=65_536).contains(&size));
    let v = size - 1; // fits in 16 bits.
    [0x01, ((v >> 8) & 0xFF) as u8, (v & 0xFF) as u8]
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Idle => {
                    if consumed == input.len() {
                        // No more input on this call; just return.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Decide how big the next chunk should be. We commit
                    // *now* to a chunk of `payload` bytes, which must then
                    // be drained from the same input slice we were handed
                    // — otherwise we'd be writing a chunk header for bytes
                    // we won't actually carry. Since `payload` is capped
                    // at the bytes remaining in this input, that always
                    // works.
                    let remaining_in = input.len() - consumed;
                    let payload = core::cmp::min(remaining_in, ENC_CHUNK_SIZE) as u32;
                    let header = make_uncomp_header(payload);
                    self.phase = EncPhase::HeaderOut {
                        payload,
                        header_idx: 0,
                        header,
                    };
                }
                EncPhase::HeaderOut {
                    payload,
                    mut header_idx,
                    header,
                } => {
                    while (header_idx as usize) < 3 && written < output.len() {
                        output[written] = header[header_idx as usize];
                        written += 1;
                        header_idx += 1;
                    }
                    if (header_idx as usize) == 3 {
                        self.phase = EncPhase::PayloadOut { remaining: payload };
                    } else {
                        self.phase = EncPhase::HeaderOut {
                            payload,
                            header_idx,
                            header,
                        };
                        // Output is full and we still owe header bytes —
                        // can't make further progress on this call.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::PayloadOut { remaining } => {
                    if remaining == 0 {
                        self.phase = EncPhase::Idle;
                        continue;
                    }
                    if written == output.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // We committed to `remaining` bytes of payload sourced
                    // from this input slice in the Idle branch above. If
                    // input is already drained we cannot honour that — that
                    // would only happen if the caller fed us through encode
                    // until input exhausted and then called encode again
                    // with a different (or empty) input, but inside this
                    // single call we always have the bytes we committed to.
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let in_left = input.len() - consumed;
                    let out_left = output.len() - written;
                    let n = core::cmp::min(remaining as usize, core::cmp::min(in_left, out_left));
                    output[written..written + n].copy_from_slice(&input[consumed..consumed + n]);
                    consumed += n;
                    written += n;
                    let new_remaining = remaining - n as u32;
                    self.phase = if new_remaining == 0 {
                        EncPhase::Idle
                    } else {
                        EncPhase::PayloadOut {
                            remaining: new_remaining,
                        }
                    };
                }
                EncPhase::NeedEosMarker | EncPhase::Done => {
                    // Encoding after finish() is a misuse; refuse cleanly.
                    return Err(Error::Corrupt);
                }
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Idle => {
                    self.phase = EncPhase::NeedEosMarker;
                }
                EncPhase::HeaderOut { .. } | EncPhase::PayloadOut { .. } => {
                    // The encode() above only ever returns mid-HeaderOut or
                    // mid-PayloadOut when its output buffer ran out. Calling
                    // finish() while a chunk is still in flight means the
                    // caller stopped delivering both bytes and output room
                    // before the chunk we committed to was fully written —
                    // a contract violation we surface as Corrupt rather
                    // than UnexpectedEnd, since the encoder has no input
                    // stream of its own that could be "ended" early.
                    return Err(Error::Corrupt);
                }
                EncPhase::NeedEosMarker => {
                    if written == output.len() {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    output[written] = 0x00;
                    written += 1;
                    self.phase = EncPhase::Done;
                }
                EncPhase::Done => {
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn reset(&mut self) {
        self.phase = EncPhase::Idle;
    }
}
