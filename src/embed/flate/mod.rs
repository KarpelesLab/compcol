//! The `embed` deflate family at the lowest level: the memory is the caller's,
//! the input and output are whatever the caller plugs in. `embed` build only.
//!
//! Where [`deflate::Decoder`](crate::deflate::Decoder) and friends own their window
//! and fit the crate-wide [`Encoder`](crate::Encoder) /
//! [`Decoder`](crate::Decoder) traits, this decodes straight into the
//! caller's buffer or window and pulls its input through a callback or an
//! iterator, with about 1.5 KiB of stack and no state; compresses with a
//! table of the caller's, a chunk at a time, into any output; and reports
//! errors with its own [`Error`], which tells input and output failures and
//! too small a window apart. This is the API of the retired `minizlib`
//! crate, which now re-exports it.
//!
//! Checksums are always verified, all three deflate block types decoded, and
//! concatenated gzip members decoded as one stream: one byte past the end of
//! each member is consumed from the input, if there is one, to tell whether
//! another follows.
//!
//! Pick a format, an input and an output, and go:
//!
//! | format                 | decompress        | length only            | compress         |
//! |------------------------|-------------------|------------------------|------------------|
//! | gzip (RFC 1952)        | [`gunzip`][g]     | [`gunzip_len`][gl]     | [`gzip`][cg]     |
//! | zlib (RFC 1950)        | [`unzlib`][z]     | [`unzlib_len`][zl]     | [`zlib`][cz]     |
//! | raw deflate (RFC 1951) | [`inflate`][i]    | [`inflate_len`][il]    | [`deflate`][cd]  |
//! | gzip or zlib, detected | [`decompress`][d] | [`decompress_len`][dl] |                  |
//!
//! [g]: fn.gunzip.html
//! [gl]: fn.gunzip_len.html
//! [z]: fn.unzlib.html
//! [zl]: fn.unzlib_len.html
//! [i]: fn.inflate.html
//! [il]: fn.inflate_len.html
//! [d]: fn.decompress.html
//! [dl]: fn.decompress_len.html
//! [cg]: fn.gzip.html
//! [cz]: fn.zlib.html
//! [cd]: fn.deflate.html
//! [c]: struct.Compressor.html
//! [bc]: struct.BufferedCompressor.html
//! [dc]: struct.Decompressor.html
//!
//! | input to decompress  | how                           |
//! |----------------------|-------------------------------|
//! | buffer in            | `&[u8]`, or `&mut &[u8]`      |
//! | stream in (callback) | [`Reader`]                    |
//! | stream in (iterator) | [`Bytes`]                     |
//! | stream in (pushed)   | [`Decompressor`][dc], a piece at a time |
//! | anything else        | implement [`Input`]           |
//!
//! | input to compress    | how                           |
//! |----------------------|-------------------------------|
//! | buffer in            | `&[u8]`                       |
//! | stream in            | [`Compressor`][c], a chunk at a time |
//! | stream in (pushed)   | [`BufferedCompressor`][bc], a piece at a time |
//!
//! | output                | how                 | memory needed               |
//! |-----------------------|---------------------|-----------------------------|
//! | buffer out            | [`Buffer`]          | the output buffer itself    |
//! | stream out (callback) | [`Stream`]          | a window, usually 32 KiB    |
//! | none, just the length | [`Counter`]         | none                        |
//!
//! On top of that, decompressing uses about 1.5 KiB of stack, or 1.1 KiB in a
//! [`Decompressor`][dc], which has to keep it between pieces. Compressing
//! uses next to none, and a table of yours to find matches with: any size
//! will do, 8 KiB is a good deal.
//!
//! The pushed inputs are for when the input is not yours to ask for, and
//! comes in pieces of whatever size, over a socket or a UART say: everything
//! else pulls its input as it needs it, and does not return until done.
//!
//! Every path is bounded: a [`Buffer`] by its size, a [`Stream`], a
//! [`Counter`] and the length functions by a mandatory maximum length, beyond
//! which they fail with [`Error::OutputFull`] instead of letting a
//! decompression bomb run. [`NO_LIMIT`] opts out.
//!
//! # Examples
//!
//! Buffer to buffer:
//!
//! ```
//! # #[cfg(feature = "gzip")] {
//! use compcol::embed::flate::{gunzip, Buffer};
//!
//! let gz = [
//!     0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
//!     0x57, 0xc8, 0x40, 0x27, 0x01, 0xe3, 0x51, 0x3d, 0x8d, 0x17, 0x00, 0x00, 0x00,
//! ];
//! let mut out = [0; 64];
//! let len = gunzip(&gz[..], Buffer::new(&mut out))? as usize;
//! assert_eq!(&out[..len], b"hello hello hello hello");
//! # }
//! # Ok::<(), compcol::embed::flate::Error>(())
//! ```
//!
//! Stream to stream, sizing things up first:
//!
//! ```
//! # #[cfg(feature = "gzip")] {
//! use compcol::embed::flate::{gunzip, gunzip_len, Error, Reader, Stream};
//!
//! # let gz = [
//! #     0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
//! #     0x57, 0xc8, 0x40, 0x27, 0x01, 0xe3, 0x51, 0x3d, 0x8d, 0x17, 0x00, 0x00, 0x00,
//! # ];
//! assert_eq!(gunzip_len(&gz[..], 1 << 20)?, 23);
//!
//! let mut source = gz.chunks(5); // stands for a UART, a flash driver, a socket...
//! let mut scratch = [0; 16];
//! let input = Reader::new(&mut scratch, |buf| {
//!     let chunk = source.next().unwrap_or(&[]);
//!     buf[..chunk.len()].copy_from_slice(chunk);
//!     Ok(chunk.len())
//! });
//!
//! let mut window = [0; 32768];
//! let mut total = 0;
//! let output = Stream::new(&mut window, 1 << 20, |data| {
//!     total += data.len();
//!     Ok(())
//! });
//!
//! gunzip(input, output)?;
//! assert_eq!(total, 23);
//! # }
//! # Ok::<(), compcol::embed::flate::Error>(())
//! ```
//!
//! Pushed in, as the compressed data comes:
//!
//! ```
//! # #[cfg(feature = "gzip")] {
//! use compcol::embed::flate::{Buffer, Decompressor, Gzip};
//!
//! # let gz = [
//! #     0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
//! #     0x57, 0xc8, 0x40, 0x27, 0x01, 0xe3, 0x51, 0x3d, 0x8d, 0x17, 0x00, 0x00, 0x00,
//! # ];
//! let mut out = [0; 64];
//! let mut decompressor = Decompressor::<_, Gzip>::new(Buffer::new(&mut out));
//! for piece in gz.chunks(3) { // whatever the socket hands over
//!     decompressor.write(piece)?;
//! }
//! let len = decompressor.finish()? as usize;
//! assert_eq!(&out[..len], b"hello hello hello hello");
//! # }
//! # Ok::<(), compcol::embed::flate::Error>(())
//! ```
//!
//! Compressing, in one go, then a chunk at a time, then pushed in:
//!
//! ```
//! # #[cfg(feature = "gzip")] {
//! use compcol::embed::flate::{gunzip, gzip, Buffer, BufferedCompressor, Compressor, Gzip};
//!
//! let data = b"hello hello hello hello";
//! let mut table = [0; 256];
//! let mut gz = [0; 64];
//! let whole = gzip(data, &mut table, Buffer::new(&mut gz))? as usize;
//! assert!(whole < data.len() + 18);
//!
//! let mut out = [0; 64];
//! let mut compressor = Compressor::<_, Gzip>::new(Buffer::new(&mut out), &mut table);
//! for chunk in data.chunks(10) {
//!     compressor.write(chunk)?;
//! }
//! let len = compressor.finish()? as usize;
//!
//! let mut back = [0; 64];
//! let back_len = gunzip(&out[..len], Buffer::new(&mut back))? as usize;
//! assert_eq!(&back[..back_len], data);
//!
//! // Pieces of any size compress as well as chunks the size of the buffer:
//! // here, as the whole.
//! let mut buffer = [0; 32];
//! let mut compressor =
//!     BufferedCompressor::<_, Gzip>::new(Buffer::new(&mut out), &mut table, &mut buffer);
//! for piece in data.chunks(1) {
//!     compressor.write(piece)?;
//! }
//! assert_eq!(compressor.finish()? as usize, whole);
//! # }
//! # Ok::<(), compcol::embed::flate::Error>(())
//! ```
//!

mod checksum;
#[cfg(any(feature = "gzip", feature = "zlib"))]
mod container;
mod deflate;
mod format;
mod inflate;
mod io;
mod push;

pub use checksum::Checksum;
pub use deflate::{BufferedCompressor, Compressor};
#[cfg(all(feature = "gzip", feature = "zlib"))]
pub use format::Detect;
#[cfg(feature = "gzip")]
pub use format::Gzip;
#[cfg(feature = "zlib")]
pub use format::Zlib;
pub use format::{Container, Format, Raw};
pub use io::{Buffer, Bytes, Counter, Input, Output, Reader, Stream};
pub use push::Decompressor;

use core::fmt;

/// The maximum length to pass for no maximum at all: the `-1` of a C API.
///
/// Think twice. Deflate can expand a thousandfold, so without a limit whoever
/// supplies the compressed data decides how long decoding runs and how much
/// comes out of it.
pub const NO_LIMIT: u64 = u64::MAX;

/// Why decompression failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the compressed stream did.
    UnexpectedEof,
    /// The gzip or zlib header is malformed.
    InvalidHeader,
    /// The stream uses something that cannot be decoded: a compression method
    /// other than deflate, or a preset dictionary.
    Unsupported,
    /// A deflate block header is malformed.
    InvalidBlock,
    /// A Huffman code is malformed, or a symbol cannot be decoded.
    InvalidCode,
    /// A back-reference points before the start of the output.
    InvalidDistance,
    /// A back-reference points further back than the [`Stream`] window holds.
    WindowTooSmall,
    /// The decompressed data is longer than the output allows: it does not fit
    /// in the [`Buffer`], or exceeds the maximum length given to a [`Stream`],
    /// a [`Counter`] or a `*_len` function.
    OutputFull,
    /// The decompressed data does not match its checksum or recorded length.
    ChecksumMismatch,
    /// An input or output callback failed.
    Io,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::UnexpectedEof => "unexpected end of input",
            Error::InvalidHeader => "invalid header",
            Error::Unsupported => "unsupported stream",
            Error::InvalidBlock => "invalid deflate block",
            Error::InvalidCode => "invalid Huffman code",
            Error::InvalidDistance => "invalid back-reference distance",
            Error::WindowTooSmall => "window too small",
            Error::OutputFull => "output too long",
            Error::ChecksumMismatch => "checksum mismatch",
            Error::Io => "input/output failure",
        })
    }
}

impl core::error::Error for Error {}

/// Decompresses a raw deflate stream. Returns the number of bytes produced.
pub fn inflate<I: Input, O: Output>(mut input: I, mut output: O) -> Result<u64, Error> {
    let start = output.written();
    inflate::Inflate::new(&mut input, &mut output, ()).run(|state| state.inflate())?;
    Ok(output.written() - start)
}

/// Decompresses a gzip stream. Returns the number of bytes produced.
///
/// All the members of the stream are decompressed one after the other.
#[cfg(feature = "gzip")]
pub fn gunzip<I: Input, O: Output>(mut input: I, mut output: O) -> Result<u64, Error> {
    let start = output.written();
    let first = input.byte()?;
    container::gzip(first, &mut input, &mut output)?;
    Ok(output.written() - start)
}

/// Decompresses a zlib stream. Returns the number of bytes produced.
#[cfg(feature = "zlib")]
pub fn unzlib<I: Input, O: Output>(mut input: I, mut output: O) -> Result<u64, Error> {
    let start = output.written();
    let first = input.byte()?;
    container::zlib(first, &mut input, &mut output)?;
    Ok(output.written() - start)
}

/// Decompresses a gzip or zlib stream, whichever it turns out to be. Returns
/// the number of bytes produced.
#[cfg(all(feature = "gzip", feature = "zlib"))]
pub fn decompress<I: Input, O: Output>(mut input: I, mut output: O) -> Result<u64, Error> {
    let start = output.written();
    // A zlib stream cannot start with 0x1f: the low nibble of its first byte
    // is the compression method, 8.
    match input.byte()? {
        0x1f => container::gzip(0x1f, &mut input, &mut output)?,
        first => container::zlib(first, &mut input, &mut output)?,
    }
    Ok(output.written() - start)
}

/// Returns the length a raw deflate stream decompresses to.
///
/// The stream is decoded in full, but nothing is stored, so this needs no
/// memory and is a good deal faster than decompressing. Decoding gives up with
/// [`Error::OutputFull`] once the length exceeds `max_len`; see [`NO_LIMIT`].
pub fn inflate_len<I: Input>(input: I, max_len: u64) -> Result<u64, Error> {
    inflate(input, Counter::new(max_len))
}

/// Returns the length a gzip stream decompresses to.
///
/// The stream is decoded in full, but nothing is stored, so this needs no
/// memory and is a good deal faster than decompressing. Decoding gives up with
/// [`Error::OutputFull`] once the length exceeds `max_len`; see [`NO_LIMIT`]. The data checksum is
/// not verified; the length recorded in the stream is.
///
/// See [`gzip_size_hint`] for a shortcut.
#[cfg(feature = "gzip")]
pub fn gunzip_len<I: Input>(input: I, max_len: u64) -> Result<u64, Error> {
    gunzip(input, Counter::new(max_len))
}

/// Returns the length a zlib stream decompresses to.
///
/// The stream is decoded in full, but nothing is stored, so this needs no
/// memory and is a good deal faster than decompressing. Decoding gives up with
/// [`Error::OutputFull`] once the length exceeds `max_len`; see [`NO_LIMIT`]. The data checksum is
/// not verified.
#[cfg(feature = "zlib")]
pub fn unzlib_len<I: Input>(input: I, max_len: u64) -> Result<u64, Error> {
    unzlib(input, Counter::new(max_len))
}

/// Returns the length a gzip or zlib stream decompresses to.
///
/// The stream is decoded in full, but nothing is stored, so this needs no
/// memory and is a good deal faster than decompressing. Decoding gives up with
/// [`Error::OutputFull`] once the length exceeds `max_len`; see [`NO_LIMIT`]. The data checksum is
/// not verified.
#[cfg(all(feature = "gzip", feature = "zlib"))]
pub fn decompress_len<I: Input>(input: I, max_len: u64) -> Result<u64, Error> {
    decompress(input, Counter::new(max_len))
}

/// Reads the decompressed length recorded in the last four bytes of a gzip
/// file, without decoding anything.
///
/// This is only a hint: it is the length of the last member alone, modulo
/// 2<sup>32</sup>, it is wrong if anything follows the gzip stream in `gz`,
/// and nothing vouches for it. [`gunzip_len`] gives the real answer.
#[cfg(feature = "gzip")]
pub fn gzip_size_hint(gz: &[u8]) -> Option<u32> {
    // The smallest gzip file has a 10 byte header and a 2 byte deflate stream.
    if gz.len() < 20 {
        return None;
    }
    Some(u32::from_le_bytes(*gz.last_chunk()?))
}

/// Compresses `data` into a gzip stream, finding matches with `table`: see
/// [`Compressor`]. Returns the length of the stream.
#[cfg(feature = "gzip")]
pub fn gzip<O: Output>(data: &[u8], table: &mut [u16], output: O) -> Result<u64, Error> {
    compress::<O, Gzip>(data, table, output)
}

/// Compresses `data` into a zlib stream, finding matches with `table`: see
/// [`Compressor`]. Returns the length of the stream.
#[cfg(feature = "zlib")]
pub fn zlib<O: Output>(data: &[u8], table: &mut [u16], output: O) -> Result<u64, Error> {
    compress::<O, Zlib>(data, table, output)
}

/// Compresses `data` into a raw deflate stream, finding matches with `table`:
/// see [`Compressor`]. Returns the length of the stream.
pub fn deflate<O: Output>(data: &[u8], table: &mut [u16], output: O) -> Result<u64, Error> {
    compress::<O, Raw>(data, table, output)
}

fn compress<O: Output, F: Format>(data: &[u8], table: &mut [u16], output: O) -> Result<u64, Error> {
    let mut compressor = Compressor::<O, F>::new(output, table);
    compressor.write(data)?;
    compressor.finish()
}
