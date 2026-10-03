//! Input sources and output sinks.

use super::{Checksum, Error};

/// A source of compressed bytes.
///
/// Implemented for `&[u8]` (buffer in), [`Reader`] (stream in through a
/// callback), [`Bytes`] (any byte iterator) and `&mut I`, so an input can be
/// lent to a decompression call and inspected afterwards.
///
/// The decoder never reads past the end of the compressed stream, except for
/// the single look-ahead byte needed to detect another gzip member.
pub trait Input {
    /// Returns the next byte, or [`Error::UnexpectedEof`] at end of input.
    fn byte(&mut self) -> Result<u8, Error>;
}

impl<I: Input + ?Sized> Input for &mut I {
    #[inline]
    fn byte(&mut self) -> Result<u8, Error> {
        (**self).byte()
    }
}

/// Buffer in. The slice is advanced past the consumed bytes, so passing
/// `&mut slice` leaves the unconsumed remainder in `slice`.
impl Input for &[u8] {
    #[inline]
    fn byte(&mut self) -> Result<u8, Error> {
        let (&byte, rest) = self.split_first().ok_or(Error::UnexpectedEof)?;
        *self = rest;
        Ok(byte)
    }
}

/// Stream in: pulls compressed data through a callback into a caller-supplied
/// scratch buffer of any non-zero size.
///
/// The callback fills the buffer it is given and returns the number of bytes
/// written, `Ok(0)` meaning end of input. It may fail with any [`Error`],
/// typically [`Error::Io`].
///
/// A `Reader` reads ahead: once decompression is done, [`Reader::buffered`]
/// holds whatever was fetched past the end of the compressed stream.
pub struct Reader<'b, F> {
    buf: &'b mut [u8],
    pos: usize,
    len: usize,
    read: F,
}

impl<'b, F: FnMut(&mut [u8]) -> Result<usize, Error>> Reader<'b, F> {
    /// Creates a reader using `buf` as scratch space.
    pub fn new(buf: &'b mut [u8], read: F) -> Self {
        Reader {
            buf,
            pos: 0,
            len: 0,
            read,
        }
    }

    /// Bytes fetched from the callback but not consumed yet.
    pub fn buffered(&self) -> &[u8] {
        self.buf.get(self.pos..self.len).unwrap_or(&[])
    }
}

impl<F: FnMut(&mut [u8]) -> Result<usize, Error>> Input for Reader<'_, F> {
    #[inline]
    fn byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.len {
            self.pos = 0;
            self.len = 0;
            self.len = (self.read)(self.buf)?;
            if self.len == 0 {
                return Err(Error::UnexpectedEof);
            }
        }
        // Fails only if the callback claimed more bytes than the buffer holds.
        let byte = *self.buf.get(self.pos).ok_or(Error::Io)?;
        self.pos += 1;
        Ok(byte)
    }
}

/// Stream in from any iterator over bytes.
pub struct Bytes<T>(pub T);

impl<T: Iterator<Item = u8>> Input for Bytes<T> {
    #[inline]
    fn byte(&mut self) -> Result<u8, Error> {
        self.0.next().ok_or(Error::UnexpectedEof)
    }
}

/// A sink for decompressed bytes that also serves as the deflate history
/// window.
///
/// Implemented by [`Buffer`] (buffer out), [`Stream`] (stream out through a
/// callback), [`Counter`] (discard and count) and `&mut O`.
pub trait Output {
    /// Whether the bytes reach `check`, i.e. whether data checksums can be
    /// verified with this output.
    const VERIFY: bool = true;

    /// Appends one byte.
    fn put<C: Checksum>(&mut self, byte: u8, check: &mut C) -> Result<(), Error>;

    /// Appends `len` bytes copied from `dist` bytes back in the output. The
    /// ranges overlap when `len > dist`, which repeats the last `dist` bytes.
    fn copy<C: Checksum>(&mut self, dist: usize, len: usize, check: &mut C) -> Result<(), Error>;

    /// Delivers everything produced so far to its destination and to `check`.
    fn flush<C: Checksum>(&mut self, check: &mut C) -> Result<(), Error>;

    /// Total number of bytes appended so far.
    fn written(&self) -> u64;
}

impl<O: Output + ?Sized> Output for &mut O {
    const VERIFY: bool = O::VERIFY;

    #[inline]
    fn put<C: Checksum>(&mut self, byte: u8, check: &mut C) -> Result<(), Error> {
        (**self).put(byte, check)
    }

    #[inline]
    fn copy<C: Checksum>(&mut self, dist: usize, len: usize, check: &mut C) -> Result<(), Error> {
        (**self).copy(dist, len, check)
    }

    #[inline]
    fn flush<C: Checksum>(&mut self, check: &mut C) -> Result<(), Error> {
        (**self).flush(check)
    }

    #[inline]
    fn written(&self) -> u64 {
        (**self).written()
    }
}

/// Buffer out: decompresses into a slice, which doubles as the history
/// window, so no other memory is needed.
///
/// Decompression fails with [`Error::OutputFull`] if the slice is too small.
pub struct Buffer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    checked: usize,
}

impl<'a> Buffer<'a> {
    /// Creates an output writing to the start of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Buffer {
            buf,
            pos: 0,
            checked: 0,
        }
    }

    /// The decompressed data written so far.
    pub fn filled(&self) -> &[u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }
}

impl Output for Buffer<'_> {
    #[inline]
    fn put<C: Checksum>(&mut self, byte: u8, _: &mut C) -> Result<(), Error> {
        *self.buf.get_mut(self.pos).ok_or(Error::OutputFull)? = byte;
        self.pos += 1;
        Ok(())
    }

    #[inline]
    fn copy<C: Checksum>(&mut self, dist: usize, len: usize, _: &mut C) -> Result<(), Error> {
        let start = self.pos.checked_sub(dist).ok_or(Error::InvalidDistance)?;
        // Should this wrap around, the range is invalid and gets refused.
        let end = self.pos.wrapping_add(len);
        let region = self.buf.get_mut(start..end).ok_or(Error::OutputFull)?;
        for i in dist..region.len() {
            region[i] = region[i - dist];
        }
        self.pos = end;
        Ok(())
    }

    fn flush<C: Checksum>(&mut self, check: &mut C) -> Result<(), Error> {
        if let Some(data) = self.buf.get(self.checked..self.pos) {
            check.update(data);
        }
        self.checked = self.pos;
        Ok(())
    }

    fn written(&self) -> u64 {
        self.pos as u64
    }
}

/// Stream out: decompresses through a caller-supplied history window, handing
/// the data to a callback each time the window fills up and once at the end.
///
/// The window must be at least as large as the one used by the compressor,
/// else decompression fails with [`Error::WindowTooSmall`]. 32768 bytes
/// handles every deflate stream; a larger window only means fewer, larger
/// callback invocations. The callback may fail with any [`Error`], typically
/// [`Error::Io`].
///
/// Nothing else bounds how much a stream decompresses to, and a few kilobytes
/// of deflate can expand to gigabytes, so a maximum length is required:
/// decompression fails with [`Error::OutputFull`] rather than produce more
/// than `max_len` bytes. Pass [`NO_LIMIT`](super::NO_LIMIT) if the callback can
/// really take whatever comes.
pub struct Stream<'w, F> {
    window: &'w mut [u8],
    pos: usize,
    sent: usize,
    total: u64,
    max_len: u64,
    sink: F,
}

impl<'w, F: FnMut(&[u8]) -> Result<(), Error>> Stream<'w, F> {
    /// Creates an output using `window` as its history window, accepting at
    /// most `max_len` bytes.
    pub fn new(window: &'w mut [u8], max_len: u64, sink: F) -> Self {
        Stream {
            window,
            pos: 0,
            sent: 0,
            total: 0,
            max_len,
            sink,
        }
    }

    fn send<C: Checksum>(&mut self, check: &mut C) -> Result<(), Error> {
        if let Some(data) = self.window.get(self.sent..self.pos)
            && !data.is_empty()
        {
            check.update(data);
            (self.sink)(data)?;
        }
        self.sent = self.pos;
        Ok(())
    }
}

impl<F: FnMut(&[u8]) -> Result<(), Error>> Output for Stream<'_, F> {
    #[inline]
    fn put<C: Checksum>(&mut self, byte: u8, check: &mut C) -> Result<(), Error> {
        if self.total >= self.max_len {
            return Err(Error::OutputFull);
        }
        *self.window.get_mut(self.pos).ok_or(Error::WindowTooSmall)? = byte;
        self.pos += 1;
        self.total += 1;
        if self.pos == self.window.len() {
            self.send(check)?;
            self.pos = 0;
            self.sent = 0;
        }
        Ok(())
    }

    fn copy<C: Checksum>(&mut self, dist: usize, len: usize, check: &mut C) -> Result<(), Error> {
        let size = self.window.len();
        if dist as u64 > self.total {
            return Err(Error::InvalidDistance);
        }
        if dist > size {
            return Err(Error::WindowTooSmall);
        }
        let mut src = if dist <= self.pos {
            self.pos - dist
        } else {
            size - (dist - self.pos)
        };
        for _ in 0..len {
            let byte = *self.window.get(src).ok_or(Error::WindowTooSmall)?;
            self.put(byte, check)?;
            src += 1;
            if src == size {
                src = 0;
            }
        }
        Ok(())
    }

    fn flush<C: Checksum>(&mut self, check: &mut C) -> Result<(), Error> {
        self.send(check)
    }

    fn written(&self) -> u64 {
        self.total
    }
}

/// Discards the data and only counts it. Needs no memory at all, since a
/// back-reference has a known length whatever it points at.
///
/// Data checksums cannot be verified this way; everything else still is.
///
/// Counting is fast, but a few kilobytes of deflate can still stand for
/// gigabytes of data, so a maximum length is required: decoding fails with
/// [`Error::OutputFull`] as soon as the count exceeds `max_len`. Pass
/// [`NO_LIMIT`](super::NO_LIMIT) to count no matter what.
pub struct Counter {
    count: u64,
    max_len: u64,
}

impl Counter {
    /// Creates a counter starting at zero and giving up past `max_len`.
    pub fn new(max_len: u64) -> Self {
        Counter { count: 0, max_len }
    }
}

impl Output for Counter {
    const VERIFY: bool = false;

    #[inline]
    fn put<C: Checksum>(&mut self, _: u8, check: &mut C) -> Result<(), Error> {
        self.copy(0, 1, check)
    }

    #[inline]
    fn copy<C: Checksum>(&mut self, dist: usize, len: usize, _: &mut C) -> Result<(), Error> {
        if dist as u64 > self.count {
            return Err(Error::InvalidDistance);
        }
        // `count` never exceeds `max_len`, so this cannot overflow.
        if len as u64 > self.max_len - self.count {
            return Err(Error::OutputFull);
        }
        self.count += len as u64;
        Ok(())
    }

    fn flush<C: Checksum>(&mut self, _: &mut C) -> Result<(), Error> {
        Ok(())
    }

    fn written(&self) -> u64 {
        self.count
    }
}
