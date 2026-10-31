//! Streaming decoder for ZIP method 98 (PPMd variant I rev. 1).
//!
//! The entry data is a 2-byte little-endian header followed by the
//! range-coded body:
//!
//! ```text
//! bits 0..=3   model order - 1     (order 2..=16; 0 is invalid)
//! bits 4..=11  memory size MB - 1  (1..=256 MB)
//! bits 12..=15 restore method      (0 restart, 1 cut-off, 2 freeze)
//! ```
//!
//! Unlike the standalone `.ppmd` decoder this one streams: it keeps a
//! small input window and decodes a symbol whenever enough input is
//! buffered for any symbol to finish (see `MAX_BYTES_PER_SYMBOL`).

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::ppmd8::{
    MAX_BYTES_PER_SYMBOL, MAX_ORDER, Ppmd8, RESTORE_CUT_OFF, RESTORE_RESTART, RangeDec, RcState,
    Sym,
};

/// Input bytes kept buffered at most.
const WINDOW: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    RangeInit,
    Body,
    Done,
}

/// Streaming decoder for the data of a ZIP method 98 (PPMd) entry.
///
/// Feed it the entry's compressed bytes exactly as they appear after the
/// local file header. The 2-byte PPMd header is read from the stream; the
/// output length comes from the ZIP headers, since the format needs it to
/// know where to stop.
///
/// The model allocates the memory size named in the header (up to
/// 256 MiB) when the header arrives. If that allocation fails the decoder
/// returns [`Error::Unsupported`]. The freeze restore method (2) is also
/// [`Error::Unsupported`], as in 7-Zip.
///
/// ```
/// use compcol::ppmd::ZipDecoder;
/// use compcol::{Decoder as _, Status};
///
/// // An entry written by 7-Zip (order 6, 1 MB, restart).
/// let entry = [
///     0x05, 0x00, 0x67, 0xfb, 0x83, 0x54, 0xd7, 0x35, 0x97, 0x16, 0xdb, 0x81, 0x87, 0x9c, 0x00,
/// ];
/// let text = b"hello hello hello hello hello hello hello";
/// let mut dec = ZipDecoder::new(text.len() as u64);
/// let mut out = [0u8; 64];
/// // `decode` holds back the last few symbols until it knows no more
/// // input is coming; `finish` decodes them.
/// let (p, _) = dec.decode(&entry, &mut out)?;
/// let mut n = p.written;
/// let (p, status) = dec.finish(&mut out[n..])?;
/// n += p.written;
/// assert_eq!(&out[..n], text);
/// assert_eq!(status, Status::StreamEnd);
/// # Ok::<(), compcol::Error>(())
/// ```
pub struct ZipDecoder {
    /// `None`: stop at the end marker.
    target: Option<u64>,
    produced: u64,
    buf: Vec<u8>,
    pos: usize,
    phase: Phase,
    model: Option<Box<Ppmd8>>,
    rc: RcState,
    poisoned: Option<Error>,
}

impl ZipDecoder {
    /// Decoder for an entry whose uncompressed size is `uncompressed_len`
    /// (from the ZIP local or central header; a `u64` so ZIP64 sizes fit).
    ///
    /// Decoding stops after that many bytes; an end marker found earlier
    /// is [`Error::Corrupt`]. Nothing after the last byte is checked, so
    /// streams with or without a trailing end marker both decode. A
    /// zero length finishes at once without reading any input.
    pub fn new(uncompressed_len: u64) -> Self {
        Self::with_target(Some(uncompressed_len))
    }

    /// Decoder that runs until the stream's end marker, for when the
    /// uncompressed size is not known. 7-Zip always writes the marker.
    /// Running out of input before it is [`Error::UnexpectedEnd`], and
    /// the range coder must finish cleanly after it.
    pub fn until_end_marker() -> Self {
        Self::with_target(None)
    }

    fn with_target(target: Option<u64>) -> Self {
        Self {
            target,
            produced: 0,
            buf: Vec::new(),
            pos: 0,
            phase: Phase::Header,
            model: None,
            rc: RcState::default(),
            poisoned: None,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = Some(e);
        e
    }

    #[inline]
    fn avail(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Move up to `WINDOW` bytes of `input` into the buffer; returns how
    /// many were taken.
    fn refill(&mut self, input: &[u8]) -> usize {
        // Compact only once half the window is spent, so a caller with a
        // tiny output buffer doesn't pay for a 64 KiB move on every call.
        if self.pos > 0 && (self.pos >= WINDOW / 2 || self.pos == self.buf.len()) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let take = input.len().min(WINDOW.saturating_sub(self.buf.len()));
        self.buf.extend_from_slice(&input[..take]);
        take
    }

    fn start_model(&mut self, header: u16) -> Result<(), Error> {
        let order = (header & 0xF) as u32 + 1;
        let mem = ((header >> 4) & 0xFF) as u32 + 1;
        let restore = (header >> 12) as u32;
        if !(2..=MAX_ORDER).contains(&order) {
            return Err(Error::BadHeader);
        }
        match restore {
            RESTORE_RESTART | RESTORE_CUT_OFF => {}
            2 => return Err(Error::Unsupported),
            _ => return Err(Error::BadHeader),
        }
        let mem_bytes = mem << 20;
        let model = match self.model.take() {
            Some(m) if m.mem_size() == mem_bytes => m,
            _ => Box::new(Ppmd8::new(mem_bytes)?),
        };
        let model = self.model.insert(model);
        model.init(order, restore);
        Ok(())
    }

    /// Decode as far as the buffered input and `output` allow. With
    /// `last`, no more input will come.
    fn step(&mut self, output: &mut [u8], written: &mut usize, last: bool) -> Result<(), Error> {
        loop {
            match self.phase {
                Phase::Header => {
                    if self.target == Some(0) {
                        self.phase = Phase::Done;
                        continue;
                    }
                    if self.avail() < 2 {
                        return if last {
                            Err(Error::UnexpectedEnd)
                        } else {
                            Ok(())
                        };
                    }
                    let h = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
                    self.pos += 2;
                    self.start_model(h)?;
                    self.phase = Phase::RangeInit;
                }
                Phase::RangeInit => {
                    if self.avail() < 4 {
                        return if last {
                            Err(Error::UnexpectedEnd)
                        } else {
                            Ok(())
                        };
                    }
                    let p = self.pos;
                    let b = [
                        self.buf[p],
                        self.buf[p + 1],
                        self.buf[p + 2],
                        self.buf[p + 3],
                    ];
                    self.pos += 4;
                    self.rc = RcState::init(b)?;
                    self.phase = Phase::Body;
                }
                Phase::Body => return self.body(output, written, last),
                Phase::Done => return Ok(()),
            }
        }
    }

    fn body(&mut self, output: &mut [u8], written: &mut usize, last: bool) -> Result<(), Error> {
        let Some(model) = self.model.as_deref_mut() else {
            return Err(Error::Corrupt);
        };
        let mut rc = RangeDec::new(self.rc, &self.buf, self.pos);
        let mut result = Ok(());
        loop {
            if self.target == Some(self.produced) {
                self.phase = Phase::Done;
                break;
            }
            if *written == output.len() {
                break;
            }
            // A symbol never reads more than `MAX_BYTES_PER_SYMBOL` bytes,
            // so with that much buffered it can't run short mid-symbol.
            if !last && self.buf.len() - rc.pos < MAX_BYTES_PER_SYMBOL {
                break;
            }
            let sym = match model.decode_symbol(&mut rc) {
                Ok(s) => s,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            if rc.overran() {
                result = Err(if last {
                    Error::UnexpectedEnd
                } else {
                    Error::Corrupt
                });
                break;
            }
            match sym {
                Sym::Byte(b) => {
                    output[*written] = b;
                    *written += 1;
                    self.produced += 1;
                }
                Sym::End => {
                    // With a known size the marker must come after it;
                    // without one, the coder must end on a clean zero.
                    result = if self.target.is_some() || rc.st.code != 0 {
                        Err(Error::Corrupt)
                    } else {
                        self.phase = Phase::Done;
                        Ok(())
                    };
                    break;
                }
            }
        }
        self.rc = rc.st;
        self.pos = rc.pos.min(self.buf.len());
        result
    }
}

impl RawDecoder for ZipDecoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        let mut consumed = 0;
        let mut written = 0;
        loop {
            if self.phase != Phase::Done {
                consumed += self.refill(&input[consumed..]);
            }
            if let Err(e) = self.step(output, &mut written, false) {
                return Err(self.poison(e));
            }
            // Stop once finished, once the output is full, or once all
            // input is in and what's buffered can't produce more.
            if self.phase == Phase::Done || written == output.len() || consumed == input.len() {
                break;
            }
        }
        Ok(RawProgress {
            consumed,
            written,
            done: self.phase == Phase::Done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        let mut written = 0;
        if let Err(e) = self.step(output, &mut written, true) {
            return Err(self.poison(e));
        }
        Ok(RawProgress {
            consumed: 0,
            written,
            done: self.phase == Phase::Done,
        })
    }

    /// Back to the start of a new entry with the same size setting. The
    /// model's arena is kept and reused if the next header asks for the
    /// same memory size.
    fn raw_reset(&mut self) {
        self.produced = 0;
        self.buf.clear();
        self.pos = 0;
        self.phase = Phase::Header;
        self.rc = RcState::default();
        self.poisoned = None;
    }
}
