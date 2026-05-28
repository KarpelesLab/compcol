use crate::error::Error;

/// Result of a single streaming step.
///
/// `consumed` and `written` report how much of the caller's `input` and
/// `output` buffers the codec actually used. A step that returns
/// `Progress { consumed: 0, written: 0, done: false }` is a stall — usually
/// because `output` is empty while the codec has bytes to flush, or `input`
/// is empty while the codec needs more bytes to decide what to emit. Either
/// drain the output, supply more input, or call [`Encoder::finish`] /
/// [`Decoder::finish`] to signal end of stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    /// Bytes read from the caller's `input` slice.
    pub consumed: usize,
    /// Bytes written to the caller's `output` slice.
    pub written: usize,
    /// Set by `finish` once the codec has nothing left to flush.
    /// Always `false` from `encode` / `decode`.
    pub done: bool,
}

/// A streaming compressor.
///
/// The caller owns both buffers; the encoder owns whatever per-call state is
/// needed to bridge them. This shape works in `no_std` without allocation and
/// lets the caller chunk arbitrarily large inputs.
pub trait Encoder {
    /// Push input bytes and pull output bytes.
    ///
    /// Returns how many input bytes were consumed and how many output bytes
    /// were written. The encoder may consume zero bytes when its internal
    /// state forbids progress until the caller drains `output`.
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error>;

    /// Signal end of input and drain remaining output.
    ///
    /// Call repeatedly, supplying a fresh `output` buffer each time, until the
    /// returned `Progress::done` is `true`. After that point the encoder must
    /// be [`reset`](Encoder::reset) before further use.
    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error>;

    /// Return the encoder to a freshly-constructed state, reusing any internal
    /// buffers.
    fn reset(&mut self);
}

/// A streaming decompressor. Symmetric to [`Encoder`].
pub trait Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error>;
    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error>;
    fn reset(&mut self);
}

/// A compression algorithm: a name plus encoder/decoder factories.
///
/// Implementors are typically zero-sized marker types (e.g. `struct Rle;`).
/// The associated `Encoder` / `Decoder` types are the concrete state machines.
pub trait Algorithm {
    /// Stable, lowercase name used by the runtime factory (`"rle"`, `"lz77"`).
    const NAME: &'static str;

    type Encoder: Encoder;
    type Decoder: Decoder;

    fn encoder() -> Self::Encoder;
    fn decoder() -> Self::Decoder;
}
