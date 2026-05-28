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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Corrupt => f.write_str("encoded stream is corrupt"),
            Error::UnexpectedEnd => f.write_str("unexpected end of input"),
            Error::OutputTooSmall => f.write_str("output buffer too small to make progress"),
        }
    }
}
