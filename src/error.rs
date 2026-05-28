use core::fmt;

/// Errors that any algorithm in this crate may return.
///
/// A single crate-wide enum (instead of per-algorithm associated types) keeps
/// the [`Encoder`](crate::Encoder) / [`Decoder`](crate::Decoder) traits object
/// safe and lets the [`factory`](crate::factory) module hand back
/// `Box<dyn Encoder>` cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The encoded stream is malformed.
    Corrupt,
    /// `finish` was called while the codec was mid-symbol and needs more input.
    UnexpectedEnd,
    /// The output buffer is too small for the codec to make any progress on
    /// this call. Drain the buffer (or supply a larger one) and call again.
    /// Only returned by algorithms that have a minimum atomic output size.
    OutputTooSmall,
    /// Container header (zlib CMF/FLG, gzip magic/method) is malformed.
    BadHeader,
    /// A deflate block declared `BTYPE = 11` (reserved).
    InvalidBlockType,
    /// Code lengths in a deflate dynamic-Huffman header don't form a valid
    /// canonical prefix code.
    InvalidHuffmanTree,
    /// A deflate back-reference distance is zero, exceeds 32768, or points
    /// past the start of the decoded data.
    InvalidDistance,
    /// Adler-32 or CRC-32 trailer didn't match the recomputed value.
    ChecksumMismatch,
    /// Gzip `ISIZE` (decoded length mod 2^32) didn't match the count of
    /// bytes actually produced.
    TrailerMismatch,
    /// The stream uses an option or compression method this build does not
    /// implement (e.g. zlib `CM != 8`, zlib `FDICT = 1`, gzip reserved flags).
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Corrupt => f.write_str("encoded stream is corrupt"),
            Error::UnexpectedEnd => f.write_str("unexpected end of input"),
            Error::OutputTooSmall => f.write_str("output buffer too small to make progress"),
            Error::BadHeader => f.write_str("container header is malformed"),
            Error::InvalidBlockType => f.write_str("invalid deflate block type"),
            Error::InvalidHuffmanTree => f.write_str("invalid Huffman code lengths"),
            Error::InvalidDistance => f.write_str("invalid LZ77 back-reference distance"),
            Error::ChecksumMismatch => f.write_str("checksum mismatch"),
            Error::TrailerMismatch => f.write_str("decoded length doesn't match trailer"),
            Error::Unsupported => f.write_str("unsupported compression option"),
        }
    }
}

// std-only interop. The `std` feature pulls `alloc` and gives us
// `std::error::Error` plus a free conversion into `std::io::Error` so
// the streaming adapters in `crate::io` can use `?` on either error
// type without explicit `.map_err(...)`.
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e)
    }
}
