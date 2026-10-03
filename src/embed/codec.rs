//! The `minizlib`-backed deflate-family codecs, bridged onto the crate's
//! `RawEncoder` / `RawDecoder` traits.
//!
//! `minizlib` pushes input in and pulls nothing: its decoder decodes
//! everything a piece of input stands for into an `Output` of its own, and
//! its compressor compresses a whole chunk into one. The traits here hand the
//! caller a bounded output slice per call instead. So each direction owns an
//! `Output` that buffers — the decoder's doubles as the 32 KiB history
//! window — feeds `minizlib` only as much input as that buffer can take in
//! the worst case, and drains the buffer into the caller's slice, across
//! calls if need be.
//!
//! Everything here is written without indexing that could panic, so that a
//! bare-metal build links no panic machinery: `tools/footprint/check.sh`
//! verifies it.

use core::marker::PhantomData;

use minizlib::{Compressor, Container, Decompressor, Format, Output};

use super::{BLOCK, OUT, TABLE, WINDOW};
use crate::error::Error;
use crate::traits::{Flush, RawDecoder, RawEncoder, RawProgress};

// `OUT` takes a block's worst case, the longest container header (gzip's
// ten bytes) and the trailer `finish` adds to an empty buffer.
const _: () = assert!(OUT >= 10 + (3 + 9 * BLOCK + 7).div_ceil(8) + 1 + 10);

/// Input bytes fed to the decoder per call: as many as cannot overflow an
/// empty window. The decoder holds at most 32 bits between calls, every bit
/// produces at most 129 bytes (a 1-bit length code plus a 1-bit distance
/// code for a 258-byte match), so `(32 + 8 * FEED) * 129` must fit.
const FEED: usize = 27;
const _: () = assert!((32 + 8 * FEED) * 129 <= WINDOW);
const _: () = assert!(WINDOW.is_power_of_two());
const MASK: usize = WINDOW - 1;

fn map(error: minizlib::Error) -> Error {
    match error {
        minizlib::Error::UnexpectedEof => Error::UnexpectedEnd,
        minizlib::Error::InvalidHeader => Error::BadHeader,
        minizlib::Error::Unsupported => Error::Unsupported,
        minizlib::Error::InvalidBlock => Error::InvalidBlockType,
        minizlib::Error::InvalidCode => Error::InvalidHuffmanTree,
        minizlib::Error::InvalidDistance => Error::InvalidDistance,
        minizlib::Error::ChecksumMismatch => Error::ChecksumMismatch,
        // WindowTooSmall, OutputFull and Io: our outputs never report them.
        _ => Error::Corrupt,
    }
}

fn progress(consumed: usize, written: usize, done: bool) -> RawProgress {
    RawProgress {
        consumed,
        written,
        done,
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// The decoder's output: a ring of the last [`WINDOW`] bytes produced, which
/// back-references copy from, and which the caller is handed in order.
pub(crate) struct Window {
    buf: [u8; WINDOW],
    /// Bytes produced so far; the next one goes at `total & MASK`. Counts
    /// across streams: `reset` moves `base` up rather than everything down,
    /// which would be a `memclr8` to link for three words.
    total: u64,
    /// Bytes handed to the caller, or discarded, so far.
    delivered: u64,
    /// Bytes fed to the container's checksum so far.
    checked: u64,
    /// Where the current stream started.
    base: u64,
    /// The farthest back a reference may reach, if the caller asked for a
    /// check stricter than `WINDOW`; zero otherwise, so that a fresh window
    /// is all zeros and a `static` decoder lands in `.bss`.
    max_dist: usize,
}

impl Window {
    const fn new() -> Self {
        Window {
            buf: [0; WINDOW],
            total: 0,
            delivered: 0,
            checked: 0,
            base: 0,
            max_dist: 0,
        }
    }

    /// Bytes produced but not yet delivered.
    fn pending(&self) -> usize {
        (self.total - self.delivered) as usize
    }

    /// The pending bytes, as the one or two ring segments they occupy.
    fn segments(&self, from: u64, to: u64) -> (&[u8], &[u8]) {
        let len = (to - from) as usize;
        let start = (from as usize) & MASK;
        let first = len.min(WINDOW - start);
        let head = self.buf.get(start..start + first).unwrap_or(&[]);
        let tail = self.buf.get(..len - first).unwrap_or(&[]);
        (head, tail)
    }

    /// Copies pending bytes into `out`. Returns how many.
    fn drain(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.pending());
        let (head, tail) = self.segments(self.delivered, self.delivered + n as u64);
        // Not `copy_from_slice`: its length check, which cannot fail here,
        // would still link a panic.
        for (to, &from) in out.iter_mut().zip(head.iter().chain(tail)) {
            *to = from;
        }
        self.delivered += n as u64;
        n
    }

    /// Drops up to `n` pending bytes. Returns how many.
    fn discard(&mut self, n: usize) -> usize {
        let n = n.min(self.pending());
        self.delivered += n as u64;
        n
    }

    fn reset(&mut self) {
        self.delivered = self.total;
        self.checked = self.total;
        self.base = self.total;
    }
}

impl Output for Window {
    #[inline]
    fn put<C: minizlib::Checksum>(&mut self, byte: u8, _: &mut C) -> Result<(), minizlib::Error> {
        // Cannot happen: `FEED` bounds what one call produces. Kept as the
        // guard it is rather than as an overwrite of undelivered data.
        if self.pending() >= WINDOW {
            return Err(minizlib::Error::OutputFull);
        }
        if let Some(slot) = self.buf.get_mut((self.total as usize) & MASK) {
            *slot = byte;
        }
        self.total += 1;
        Ok(())
    }

    fn copy<C: minizlib::Checksum>(
        &mut self,
        dist: usize,
        len: usize,
        check: &mut C,
    ) -> Result<(), minizlib::Error> {
        let max_dist = match self.max_dist {
            0 => WINDOW,
            max_dist => max_dist,
        };
        if dist == 0 || dist > max_dist || dist as u64 > self.total - self.base {
            return Err(minizlib::Error::InvalidDistance);
        }
        for _ in 0..len {
            let at = (self.total as usize).wrapping_sub(dist) & MASK;
            let byte = self.buf.get(at).copied().unwrap_or(0);
            self.put(byte, check)?;
        }
        Ok(())
    }

    fn flush<C: minizlib::Checksum>(&mut self, check: &mut C) -> Result<(), minizlib::Error> {
        // The unchecked span is at most one call's production, which fits
        // the ring by the same bound that keeps pending data intact.
        let (head, tail) = self.segments(self.checked, self.total);
        check.update(head);
        check.update(tail);
        self.checked = self.total;
        Ok(())
    }

    fn written(&self) -> u64 {
        self.total
    }
}

/// A deflate-family decoder in format `F`, over `minizlib`'s push decoder.
pub(crate) struct Decoder<F> {
    inner: Decompressor<Window, F>,
    poisoned: bool,
}

impl<F: Container> Decoder<F> {
    pub(crate) const fn new() -> Self {
        Decoder {
            inner: Decompressor::new(Window::new()),
            poisoned: false,
        }
    }

    /// Rejects back-references farther than `window_size` bytes, clamped to
    /// `1..=WINDOW`.
    pub(crate) fn set_window_size(&mut self, window_size: usize) {
        self.inner.output_mut().max_dist = window_size.clamp(1, WINDOW);
    }

    fn poison(&mut self, error: Error) -> Error {
        self.poisoned = true;
        error
    }

    /// Delivers what the window holds through `sink`, which returns whether
    /// it has room for more, and feeds `input` in while it has.
    fn pump(
        &mut self,
        input: &[u8],
        mut sink: impl FnMut(&mut Window) -> bool,
    ) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0;
        loop {
            let room = sink(self.inner.output_mut());
            let empty = self.inner.output().pending() == 0;
            if self.inner.is_done() && empty {
                return Ok(progress(consumed, 0, true));
            }
            if !room || !empty {
                return Ok(progress(consumed, 0, false));
            }
            let Some(rest) = input.get(consumed..).filter(|rest| !rest.is_empty()) else {
                return Ok(progress(consumed, 0, false));
            };
            let piece = rest.get(..rest.len().min(FEED)).unwrap_or(rest);
            let took = self.inner.write(piece).map_err(map);
            let took = took.map_err(|e| self.poison(e))?;
            consumed += took;
            if took == 0 && !self.inner.is_done() {
                // Not reachable: the decoder consumes until the stream ends.
                return Err(self.poison(Error::Corrupt));
            }
        }
    }
}

impl<F: Container> RawDecoder for Decoder<F> {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0;
        let p = self.pump(input, |window| {
            if let Some(out) = output.get_mut(written..) {
                written += window.drain(out);
            }
            written < output.len()
        })?;
        Ok(progress(p.consumed, written, p.done))
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let p = self.raw_decode(&[], output)?;
        if p.done || self.inner.output().pending() > 0 {
            // Done, or done but for an output too small to take the rest:
            // the bridge has the caller come back with another buffer.
            return Ok(p);
        }
        Err(self.poison(Error::UnexpectedEnd))
    }

    fn raw_reset(&mut self) {
        // `finish` leaves the decoder ready for another stream whatever
        // state it was in; its verdict on this one is of no interest.
        let _ = self.inner.finish();
        self.inner.output_mut().reset();
        self.poisoned = false;
    }

    fn raw_skip(&mut self, input: &[u8], n: usize) -> Result<RawProgress, Error> {
        let mut skipped = 0;
        let p = self.pump(input, |window| {
            skipped += window.discard(n - skipped);
            skipped < n
        })?;
        Ok(progress(p.consumed, skipped, p.done))
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// The encoder's output: what the compressor made of the last block, until
/// the caller has taken it.
pub(crate) struct OutBuf {
    buf: [u8; OUT],
    len: usize,
    /// How much of `buf` the caller has taken.
    read: usize,
    total: u64,
}

impl OutBuf {
    const fn new() -> Self {
        OutBuf {
            buf: [0; OUT],
            len: 0,
            read: 0,
            total: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.read == self.len
    }

    /// Copies what the caller has not taken yet into `out`. Returns how many
    /// bytes.
    fn drain(&mut self, out: &mut [u8]) -> usize {
        let pending = self.buf.get(self.read..self.len).unwrap_or(&[]);
        let n = out.len().min(pending.len());
        for (to, &from) in out.iter_mut().zip(pending) {
            *to = from;
        }
        self.read += n;
        if self.read == self.len {
            self.read = 0;
            self.len = 0;
        }
        n
    }

    fn clear(&mut self) {
        self.read = 0;
        self.len = 0;
    }
}

impl Output for OutBuf {
    #[inline]
    fn put<C: minizlib::Checksum>(&mut self, byte: u8, _: &mut C) -> Result<(), minizlib::Error> {
        // Cannot happen: a block is only compressed into an empty buffer,
        // which `OUT` sizes for the worst case.
        let slot = self
            .buf
            .get_mut(self.len)
            .ok_or(minizlib::Error::OutputFull)?;
        *slot = byte;
        self.len += 1;
        self.total += 1;
        Ok(())
    }

    fn copy<C: minizlib::Checksum>(
        &mut self,
        _: usize,
        _: usize,
        _: &mut C,
    ) -> Result<(), minizlib::Error> {
        // Only a decoder copies.
        Err(minizlib::Error::Unsupported)
    }

    fn flush<C: minizlib::Checksum>(&mut self, _: &mut C) -> Result<(), minizlib::Error> {
        Ok(())
    }

    fn written(&self) -> u64 {
        self.total
    }
}

/// A deflate-family encoder in format `F`, over `minizlib`'s compressor.
pub(crate) struct Encoder<F> {
    inner: Compressor<'static, OutBuf, F, [u16; TABLE]>,
    /// Input gathered until there is a block's worth to compress.
    block: [u8; BLOCK],
    len: usize,
    /// Whether the trailer has been written.
    finished: bool,
    _format: PhantomData<F>,
}

impl<F: Format> Encoder<F> {
    pub(crate) const fn new() -> Self {
        Encoder {
            inner: Compressor::new(OutBuf::new(), [0; TABLE]),
            block: [0; BLOCK],
            len: 0,
            finished: false,
            _format: PhantomData,
        }
    }

    /// Compresses what the block buffer holds, into the (empty) output
    /// buffer.
    fn compress_block(&mut self) -> Result<(), Error> {
        let len = core::mem::take(&mut self.len);
        let block = self.block.get(..len).unwrap_or(&[]);
        self.inner.write(block).map_err(map)
    }
}

impl<F: Format> RawEncoder for Encoder<F> {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.finished {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0;
        let mut written = 0;
        loop {
            let out = self.inner.output_mut();
            written += out.drain(output.get_mut(written..).unwrap_or(&mut []));
            if !out.is_empty() {
                return Ok(progress(consumed, written, false));
            }
            if self.len == BLOCK {
                self.compress_block()?;
                continue;
            }
            let Some(rest) = input.get(consumed..).filter(|rest| !rest.is_empty()) else {
                return Ok(progress(consumed, written, false));
            };
            if self.len == 0 {
                // A block's worth at once is compressed from where it is.
                if let Some(block) = rest.get(..BLOCK) {
                    self.inner.write(block).map_err(map)?;
                    consumed += BLOCK;
                    continue;
                }
            }
            let room = self.block.get_mut(self.len..).unwrap_or(&mut []);
            let n = room.len().min(rest.len());
            for (to, &from) in room.iter_mut().zip(rest) {
                *to = from;
            }
            self.len += n;
            consumed += n;
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0;
        loop {
            let out = self.inner.output_mut();
            written += out.drain(output.get_mut(written..).unwrap_or(&mut []));
            if !out.is_empty() {
                return Ok(progress(0, written, false));
            }
            if self.len > 0 {
                self.compress_block()?;
            } else if !self.finished {
                self.inner.finish().map_err(map)?;
                self.finished = true;
            } else {
                return Ok(progress(0, written, true));
            }
        }
    }

    fn raw_reset(&mut self) {
        self.inner.output_mut().clear();
        if !self.finished {
            // Ends the stream in progress, so the compressor starts afresh;
            // what that writes is dropped with the rest.
            let _ = self.inner.finish();
            self.inner.output_mut().clear();
        }
        self.len = 0;
        self.finished = false;
    }

    fn raw_flush(&mut self, _: &mut [u8], _: Flush) -> Result<RawProgress, Error> {
        // The compressor keeps the tail of each block's end-of-block code in
        // its bit buffer and has no way to byte-align it mid-stream.
        Err(Error::Unsupported)
    }
}

/// Defines the public `Encoder` / `Decoder` of a deflate-family module in
/// `embed` mode, around [`Encoder`] / [`Decoder`] in the given `minizlib`
/// format. The module supplies `EncoderConfig` and `DecoderConfig`, and
/// `$window` maps the latter to the decoder's window-size setting.
macro_rules! codec {
    ($format:ty, $window:expr) => {
        /// Streaming encoder — the `embed` build, over `minizlib`.
        ///
        /// Owns everything it needs (block buffer, output buffer, hash table:
        /// see [`crate::embed`]); nothing is allocated. `const`-constructible.
        pub struct Encoder {
            inner: $crate::embed::codec::Encoder<$format>,
        }

        impl Encoder {
            /// Build an encoder. The configuration has no effect in `embed`
            /// mode; see [`EncoderConfig`].
            pub const fn new() -> Self {
                Encoder {
                    inner: $crate::embed::codec::Encoder::new(),
                }
            }

            /// Build an encoder with explicit configuration, which has no
            /// effect in `embed` mode: the ratio is fixed. Accepted so that
            /// code written for the standard build compiles unchanged.
            pub fn with_config(_: EncoderConfig) -> Self {
                Self::new()
            }
        }

        impl Default for Encoder {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::traits::RawEncoder for Encoder {
            fn raw_encode(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_encode(input, output)
            }
            fn raw_finish(
                &mut self,
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_finish(output)
            }
            fn raw_reset(&mut self) {
                self.inner.raw_reset()
            }
            fn raw_flush(
                &mut self,
                output: &mut [u8],
                mode: $crate::traits::Flush,
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_flush(output, mode)
            }
        }

        /// Streaming decoder — the `embed` build, over `minizlib`.
        ///
        /// Holds its 32 KiB history window inline (see [`crate::embed`] for
        /// where to put it); nothing is allocated. `const`-constructible.
        pub struct Decoder {
            inner: $crate::embed::codec::Decoder<$format>,
        }

        impl Decoder {
            /// Build a decoder with the default configuration.
            pub const fn new() -> Self {
                Decoder {
                    inner: $crate::embed::codec::Decoder::new(),
                }
            }

            /// Build a decoder with the given configuration.
            pub fn with_config(config: DecoderConfig) -> Self {
                let mut decoder = Self::new();
                let window: fn(&DecoderConfig) -> usize = $window;
                decoder.inner.set_window_size(window(&config));
                decoder
            }
        }

        impl Default for Decoder {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::traits::RawDecoder for Decoder {
            fn raw_decode(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_decode(input, output)
            }
            fn raw_finish(
                &mut self,
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_finish(output)
            }
            fn raw_reset(&mut self) {
                self.inner.raw_reset()
            }
            fn raw_skip(
                &mut self,
                input: &[u8],
                n: usize,
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_skip(input, n)
            }
        }
    };
}

pub(crate) use codec;
