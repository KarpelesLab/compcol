//! RFC 1950 zlib container around RFC 1951 deflate.
//!
//! Wire format:
//! ```text
//! +---+---+--- ... ---+---+---+---+---+
//! |CMF|FLG|  deflate  |   ADLER-32    |
//! +---+---+--- ... ---+---+---+---+---+
//! ```
//! - `CMF`: bits 0-3 = CM (8 = deflate), bits 4-7 = CINFO (`log2(WINDOW)-8`).
//! - `FLG`: bits 0-4 = FCHECK (chosen so `CMF*256 + FLG` is a multiple of 31),
//!   bit 5 = FDICT (must be 0 here), bits 6-7 = FLEVEL.
//! - 4-byte big-endian Adler-32 of the **uncompressed** data.

use alloc::vec::Vec;

use crate::checksum::Adler32;
use crate::deflate;
use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Canonical "default compression" header, divisible by 31 with CINFO=7,
/// FDICT=0, FLEVEL=2.
const HEADER_CMF: u8 = 0x78;
const HEADER_FLG: u8 = 0x9C;

/// Zero-sized marker type implementing [`Algorithm`] for zlib.
#[derive(Debug, Clone, Copy, Default)]
pub struct Zlib;

impl Algorithm for Zlib {
    const NAME: &'static str = "zlib";
    type Encoder = Encoder;
    type Decoder = Decoder;

    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecPhase {
    /// Reading the 2-byte header.
    Header,
    /// Streaming the deflate payload.
    Deflate,
    /// Collecting the 4-byte Adler-32 trailer.
    Trailer,
    /// Header/trailer validated; nothing more to consume.
    Done,
}

pub struct Decoder {
    inner: deflate::Decoder,
    adler: Adler32,
    header: [u8; 2],
    header_idx: u8,
    /// First trailer bytes recovered from the deflate decoder's bit-reader
    /// after the deflate stream ended.
    trailer_carryover: Vec<u8>,
    trailer_carryover_idx: usize,
    trailer: [u8; 4],
    trailer_idx: u8,
    phase: DecPhase,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            inner: deflate::Decoder::new(),
            adler: Adler32::new(),
            header: [0u8; 2],
            header_idx: 0,
            trailer_carryover: Vec::new(),
            trailer_carryover_idx: 0,
            trailer: [0u8; 4],
            trailer_idx: 0,
            phase: DecPhase::Header,
            poisoned: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Validate the two header bytes we've collected.
    fn validate_header(&mut self) -> Result<(), Error> {
        let cmf = self.header[0];
        let flg = self.header[1];
        if cmf & 0x0F != 8 {
            return Err(self.poison(Error::Unsupported));
        }
        if flg & 0x20 != 0 {
            // FDICT set; we don't carry a preset dictionary.
            return Err(self.poison(Error::Unsupported));
        }
        let total = ((cmf as u32) << 8) | (flg as u32);
        if !total.is_multiple_of(31) {
            return Err(self.poison(Error::BadHeader));
        }
        Ok(())
    }

    /// Pull the next trailer byte from the carry-over buffer or, if empty,
    /// from `input`. Returns `Some(byte_came_from_input)` on success
    /// (where the bool says whether the input slice was advanced),
    /// or `None` if neither source has a byte ready.
    fn next_trailer_byte(&mut self, input: &[u8], consumed: &mut usize) -> Option<bool> {
        if self.trailer_carryover_idx < self.trailer_carryover.len() {
            let b = self.trailer_carryover[self.trailer_carryover_idx];
            self.trailer_carryover_idx += 1;
            self.trailer[self.trailer_idx as usize] = b;
            self.trailer_idx += 1;
            Some(false)
        } else if *consumed < input.len() {
            self.trailer[self.trailer_idx as usize] = input[*consumed];
            *consumed += 1;
            self.trailer_idx += 1;
            Some(true)
        } else {
            None
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
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let initial_consumed = consumed;
            let initial_written = written;

            match self.phase {
                DecPhase::Header => {
                    while self.header_idx < 2 && consumed < input.len() {
                        self.header[self.header_idx as usize] = input[consumed];
                        self.header_idx += 1;
                        consumed += 1;
                    }
                    if self.header_idx == 2 {
                        self.validate_header()?;
                        self.phase = DecPhase::Deflate;
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Deflate => {
                    let before_written = written;
                    let p = self
                        .inner
                        .decode(&input[consumed..], &mut output[written..])
                        .map_err(|e| self.poison(e))?;
                    consumed += p.consumed;
                    written += p.written;
                    self.adler.update(&output[before_written..written]);

                    if self.inner.is_complete() {
                        self.trailer_carryover = self.inner.drain_trailing_bytes();
                        self.trailer_carryover_idx = 0;
                        self.phase = DecPhase::Trailer;
                    } else if p.consumed == 0 && p.written == 0 {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Trailer => {
                    while self.trailer_idx < 4 {
                        if self.next_trailer_byte(input, &mut consumed).is_none() {
                            return Ok(Progress {
                                consumed,
                                written,
                                done: false,
                            });
                        }
                    }
                    let expected = u32::from_be_bytes(self.trailer);
                    if expected != self.adler.finalize() {
                        return Err(self.poison(Error::ChecksumMismatch));
                    }
                    self.phase = DecPhase::Done;
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
        // Try to advance with empty input — useful when the caller fed all
        // bytes via decode() but didn't realise the trailer hadn't been
        // validated yet.
        let empty: [u8; 0] = [];
        let p = self.decode(&empty, output)?;
        if matches!(self.phase, DecPhase::Done) {
            Ok(Progress {
                consumed: 0,
                written: p.written,
                done: true,
            })
        } else {
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.adler.reset();
        self.header_idx = 0;
        self.trailer_carryover.clear();
        self.trailer_carryover_idx = 0;
        self.trailer_idx = 0;
        self.phase = DecPhase::Header;
        self.poisoned = false;
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncPhase {
    Header,
    Deflate,
    Trailer,
    Done,
}

pub struct Encoder {
    inner: deflate::Encoder,
    adler: Adler32,
    header_idx: u8,
    trailer: [u8; 4],
    trailer_idx: u8,
    phase: EncPhase,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            inner: deflate::Encoder::new(),
            adler: Adler32::new(),
            header_idx: 0,
            trailer: [0u8; 4],
            trailer_idx: 0,
            phase: EncPhase::Header,
        }
    }

    /// Push the 2 header bytes one at a time as output room becomes available.
    /// Returns true if the header has been fully emitted.
    fn drain_header(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.header_idx < 2 && *written < output.len() {
            output[*written] = if self.header_idx == 0 {
                HEADER_CMF
            } else {
                HEADER_FLG
            };
            *written += 1;
            self.header_idx += 1;
        }
        self.header_idx == 2
    }

    fn drain_trailer(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        while self.trailer_idx < 4 && *written < output.len() {
            output[*written] = self.trailer[self.trailer_idx as usize];
            *written += 1;
            self.trailer_idx += 1;
        }
        self.trailer_idx == 4
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

        // Header.
        if matches!(self.phase, EncPhase::Header) {
            if !self.drain_header(output, &mut written) {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }
            self.phase = EncPhase::Deflate;
        }

        if !matches!(self.phase, EncPhase::Deflate) {
            return Err(Error::Corrupt);
        }

        // Pass-through to deflate, updating Adler-32 for each consumed byte.
        let before = consumed;
        let p = self
            .inner
            .encode(&input[consumed..], &mut output[written..])?;
        consumed += p.consumed;
        written += p.written;
        self.adler.update(&input[before..before + p.consumed]);

        Ok(Progress {
            consumed,
            written,
            done: false,
        })
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        // If finish is called before any encode, we still need to emit the header.
        if matches!(self.phase, EncPhase::Header) {
            if !self.drain_header(output, &mut written) {
                return Ok(Progress {
                    consumed: 0,
                    written,
                    done: false,
                });
            }
            self.phase = EncPhase::Deflate;
        }

        if matches!(self.phase, EncPhase::Deflate) {
            loop {
                let p = self.inner.finish(&mut output[written..])?;
                written += p.written;
                if p.done {
                    let adler = self.adler.finalize();
                    self.trailer = adler.to_be_bytes();
                    self.trailer_idx = 0;
                    self.phase = EncPhase::Trailer;
                    break;
                }
                if p.written == 0 {
                    // No output room and not done.
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
            }
        }

        if matches!(self.phase, EncPhase::Trailer) && self.drain_trailer(output, &mut written) {
            self.phase = EncPhase::Done;
            return Ok(Progress {
                consumed: 0,
                written,
                done: true,
            });
        }

        if matches!(self.phase, EncPhase::Done) {
            return Ok(Progress {
                consumed: 0,
                written,
                done: true,
            });
        }

        Ok(Progress {
            consumed: 0,
            written,
            done: false,
        })
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.adler.reset();
        self.header_idx = 0;
        self.trailer = [0u8; 4];
        self.trailer_idx = 0;
        self.phase = EncPhase::Header;
    }
}
