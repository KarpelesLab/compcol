//! Streaming codec traits.
//!
//! `compcol` v0.3 introduced the explicit [`Status`] return signal so callers
//! never have to infer "why did the codec return?" from byte counts. The
//! per-algorithm implementations live in private `Raw*` traits with the
//! older byte-counts-only shape; a blanket impl bridges to the public
//! [`Encoder`] / [`Decoder`] traits below.

use crate::error::Error;

/// Bytes consumed from `input` and written to `output` by one codec call.
///
/// Pair this with a [`Status`] (returned alongside) to know what the codec
/// is waiting for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    /// Bytes read from the caller's `input` slice.
    pub consumed: usize,
    /// Bytes written to the caller's `output` slice.
    pub written: usize,
}

/// Why a codec call returned — the explicit "what should I do next?" signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// All of `input` was consumed; the codec can't make further progress
    /// without more input bytes (or, for an encoder, a [`Encoder::finish`]
    /// call to signal end-of-stream).
    InputEmpty,
    /// `output` is full (or insufficient for the codec's next atomic step).
    /// Drain it and call again with a fresh buffer.
    OutputFull,
    /// The codec has emitted everything it will ever emit. For [`Encoder::finish`]
    /// this means the encoded stream has been fully flushed; for
    /// [`Decoder::decode`] this means the trailer was consumed and the stream
    /// is complete. Further calls with the same state are no-ops returning
    /// `(Progress { 0, 0 }, StreamEnd)`. To reuse the codec, call `reset`.
    StreamEnd,
}

// ─── implementation traits (private internals) ───────────────────────────

/// Outcome of one internal codec step. The `done` flag is only meaningful
/// from `finish_raw` and `decode_raw` (for decoders that detect end-of-stream
/// inline); for encoders' `encode_raw` it must always be `false`.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawProgress {
    pub consumed: usize,
    pub written: usize,
    pub done: bool,
}

/// Implementation trait for compressors. End-users go through [`Encoder`]
/// (which is auto-implemented for every `RawEncoder` via a blanket impl).
#[doc(hidden)]
pub trait RawEncoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error>;
    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error>;
    fn raw_reset(&mut self);
}

/// Implementation trait for decompressors. End-users go through [`Decoder`].
#[doc(hidden)]
pub trait RawDecoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error>;
    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error>;
    fn raw_reset(&mut self);

    /// Optional accelerated skip. Default impl drains through a scratch
    /// buffer via `raw_decode`. Override when the format allows fast-
    /// forwarding (e.g. seeking past deflate stored blocks).
    fn raw_skip(&mut self, input: &[u8], n: usize) -> Result<RawProgress, Error> {
        let mut scratch = [0u8; 1024];
        let mut consumed = 0usize;
        let mut written = 0usize;
        while written < n {
            let want = (n - written).min(scratch.len());
            let p = self.raw_decode(&input[consumed..], &mut scratch[..want])?;
            consumed += p.consumed;
            written += p.written;
            if p.consumed == 0 && p.written == 0 {
                break;
            }
        }
        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }
}

// ─── public traits ───────────────────────────────────────────────────────

/// A streaming compressor.
///
/// The caller owns both buffers; the encoder owns whatever per-call state is
/// needed to bridge them. This shape works in `no_std` without allocation and
/// lets the caller chunk arbitrarily large inputs.
///
/// ## Loop pattern
///
/// ```no_run
/// # use compcol::{Encoder, Status};
/// # fn use_it<E: Encoder>(mut enc: E, input: &[u8], out: &mut Vec<u8>) -> Result<(), compcol::Error> {
/// let mut buf = vec![0u8; 64 * 1024];
/// let mut consumed = 0;
/// loop {
///     let (p, status) = enc.encode(&input[consumed..], &mut buf)?;
///     out.extend_from_slice(&buf[..p.written]);
///     consumed += p.consumed;
///     match status {
///         Status::OutputFull => continue,           // drain buf, call again
///         Status::InputEmpty => break,              // give it more input — none left
///         Status::StreamEnd => break,               // (encode doesn't normally return this)
///     }
/// }
/// loop {
///     let (p, status) = enc.finish(&mut buf)?;
///     out.extend_from_slice(&buf[..p.written]);
///     if matches!(status, Status::StreamEnd) { break; }
/// }
/// # Ok(()) }
/// ```
///
/// ## Post-error state
///
/// After any `Err(_)` return, the encoder is **poisoned**: subsequent
/// `encode`/`finish` calls without an intervening [`reset`](Encoder::reset)
/// are unspecified and may return further errors.
pub trait Encoder {
    /// Push input bytes and pull output bytes.
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error>;

    /// Signal end of input and drain remaining output.
    ///
    /// Call repeatedly with a fresh `output` buffer until the returned
    /// `Status` is [`Status::StreamEnd`]. After that point the encoder must
    /// be [`reset`](Encoder::reset) before further use.
    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error>;

    /// Return the encoder to a freshly-constructed state. **Configuration
    /// (compression level, dictionary, etc. passed at construction time) is
    /// preserved** so the same encoder can be reused for a new stream
    /// without reconfiguring. Internal buffers are reused.
    ///
    /// Calling `reset` is also the documented way to recover from an
    /// [`Err`] return.
    fn reset(&mut self);
}

/// A streaming decompressor.
///
/// Symmetric to [`Encoder`] plus an optional [`discard_output`](Decoder::discard_output).
///
/// ## Post-error state
///
/// After any `Err(_)` return, the decoder is **poisoned**: subsequent calls
/// without an intervening [`reset`](Decoder::reset) are unspecified and may
/// return further errors. Some decoders (deflate, zlib, gzip, …) explicitly
/// track a poison flag and return [`Error::Corrupt`] until reset.
pub trait Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error>;
    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error>;

    /// See [`Encoder::reset`] — configuration is preserved.
    fn reset(&mut self);

    /// Advance the decompressed stream by up to `n` decompressed bytes
    /// **without writing them to the caller**.
    ///
    /// The signature still takes `input` because the decoder still needs
    /// compressed bytes to advance its state; the `n` parameter just tells
    /// the decoder to discard those decompressed bytes rather than emit
    /// them. Best-effort: stops at input exhaustion or after exactly `n`
    /// bytes have been discarded, whichever comes first.
    ///
    /// Useful when listing files in a `.tar.gz` without materialising
    /// their contents.
    ///
    /// The default implementation just runs [`decode`](Decoder::decode) into
    /// a small scratch buffer and discards the result; algorithms that can
    /// short-circuit (e.g. through stored / uncompressed blocks) are
    /// encouraged to override.
    fn discard_output(&mut self, input: &[u8], n: usize) -> Result<(Progress, Status), Error>;
}

// ─── bridge: RawEncoder/RawDecoder → Encoder/Decoder ────────────────────

impl<T: RawEncoder> Encoder for T {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let p = self.raw_encode(input, output)?;
        let status = if p.consumed >= input.len() {
            Status::InputEmpty
        } else {
            // Some bytes left in input but we returned — either output is
            // full or the codec is mid-state. The caller's correct action
            // is "drain output, give us the same input slice again," which
            // is OutputFull's contract.
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: p.consumed,
                written: p.written,
            },
            status,
        ))
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let p = self.raw_finish(output)?;
        let status = if p.done {
            Status::StreamEnd
        } else {
            // Not done; only finish() can produce more output. The caller's
            // correct action is "drain output, call finish again," which
            // is OutputFull's contract.
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: 0,
                written: p.written,
            },
            status,
        ))
    }

    fn reset(&mut self) {
        self.raw_reset()
    }
}

impl<T: RawDecoder> Decoder for T {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let p = self.raw_decode(input, output)?;
        let status = if p.done {
            Status::StreamEnd
        } else if p.consumed >= input.len() {
            Status::InputEmpty
        } else {
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: p.consumed,
                written: p.written,
            },
            status,
        ))
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let p = self.raw_finish(output)?;
        let status = if p.done {
            Status::StreamEnd
        } else {
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: 0,
                written: p.written,
            },
            status,
        ))
    }

    fn reset(&mut self) {
        self.raw_reset()
    }

    fn discard_output(&mut self, input: &[u8], n: usize) -> Result<(Progress, Status), Error> {
        let p = self.raw_skip(input, n)?;
        let status = if p.done {
            Status::StreamEnd
        } else if p.written >= n {
            // Asked-for amount discarded; caller can move on.
            Status::OutputFull
        } else if p.consumed >= input.len() {
            Status::InputEmpty
        } else {
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: p.consumed,
                written: p.written,
            },
            status,
        ))
    }
}

// ─── Algorithm ───────────────────────────────────────────────────────────

/// A compression algorithm: a name plus encoder/decoder factories plus
/// per-algorithm configuration types.
///
/// Implementors are typically zero-sized marker types (e.g. `struct Rle;`).
/// The associated `Encoder` / `Decoder` types are the concrete state machines.
/// The associated `EncoderConfig` / `DecoderConfig` types carry tunables
/// (compression level, dictionary, window size, …); algorithms with no
/// tunables use `()`.
pub trait Algorithm {
    /// Stable, lowercase name used by the runtime factory (`"rle"`, `"gzip"`).
    const NAME: &'static str;

    type Encoder: Encoder;
    type Decoder: Decoder;
    type EncoderConfig: Clone + Default;
    type DecoderConfig: Clone + Default;

    /// Build an encoder with the default configuration.
    fn encoder() -> Self::Encoder {
        Self::encoder_with(Self::EncoderConfig::default())
    }

    /// Build an encoder with the supplied configuration.
    fn encoder_with(config: Self::EncoderConfig) -> Self::Encoder;

    /// Build a decoder with the default configuration.
    fn decoder() -> Self::Decoder {
        Self::decoder_with(Self::DecoderConfig::default())
    }

    /// Build a decoder with the supplied configuration.
    fn decoder_with(config: Self::DecoderConfig) -> Self::Decoder;
}
