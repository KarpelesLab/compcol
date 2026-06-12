//! Delta filter — byte-wise delta coding with a configurable distance.
//!
//! This is a *filter*, not a compressor: it makes data more compressible
//! for a downstream entropy coder (it does not shrink the data on its
//! own — output length always equals input length). It is the same
//! filter shipped in the xz / LZMA SDK toolchain.
//!
//! ## Transform
//!
//! With a distance `dist ∈ 1..=256`, the encoder replaces each byte with
//! the (wrapping) difference from the byte `dist` positions earlier in the
//! original stream:
//!
//! ```text
//! out[i] = in[i].wrapping_sub(history[i - dist])
//! ```
//!
//! where `history[j]` is the *original* (pre-transform) byte at position
//! `j`, and bytes before position 0 are treated as 0. The decoder is the
//! exact inverse, reconstructing the original byte before storing it in
//! the history:
//!
//! ```text
//! out[i] = in[i].wrapping_add(history[i - dist])
//! ```
//!
//! The arithmetic is intentionally modular (`wrapping_add` /
//! `wrapping_sub` over `u8`): the format defines the delta in modular
//! bytes so that encode∘decode is the identity for *every* input. This is
//! why we use wrapping ops rather than checked ones — overflow is the
//! defined behaviour, not an error.
//!
//! ## State
//!
//! Both directions keep a `dist`-byte ring buffer of the most recent
//! *original* bytes. The filter is stateful across the whole stream, so
//! it works unchanged whether the caller feeds one byte or a megabyte per
//! call.
//!
//! References:
//! * xz `delta` filter (public-domain, LZMA SDK lineage). Implemented
//!   clean-room from the documented transform above.

#![cfg_attr(docsrs, doc(cfg(feature = "delta")))]

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Minimum valid delta distance.
pub const MIN_DISTANCE: usize = 1;
/// Maximum valid delta distance (matches the xz delta filter's 1..=256).
pub const MAX_DISTANCE: usize = 256;

/// Zero-sized marker type implementing [`Algorithm`] for the delta filter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Delta;

/// Encoder configuration: the delta distance in bytes.
///
/// `dist` must be in `1..=256`; other values are rejected by the encoder
/// on first use ([`Error::Unsupported`]). [`Default`] is `1` (consecutive
/// byte differencing).
#[derive(Debug, Clone, Copy)]
pub struct EncoderConfig {
    /// Delta distance in bytes, `1..=256`.
    pub dist: usize,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { dist: 1 }
    }
}

/// Decoder configuration: the delta distance in bytes. Must match the
/// distance the stream was encoded with. See [`EncoderConfig`].
#[derive(Debug, Clone, Copy)]
pub struct DecoderConfig {
    /// Delta distance in bytes, `1..=256`.
    pub dist: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self { dist: 1 }
    }
}

impl Algorithm for Delta {
    const NAME: &'static str = "delta";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = EncoderConfig;
    type DecoderConfig = DecoderConfig;
    fn encoder_with(cfg: EncoderConfig) -> Encoder {
        Encoder::new(cfg.dist)
    }
    fn decoder_with(cfg: DecoderConfig) -> Decoder {
        Decoder::new(cfg.dist)
    }
}

/// Shared `dist`-byte history ring of the most recent *original* bytes.
///
/// `pos` is the write cursor; the byte `dist` positions back is the one at
/// `pos` (the slot we are about to overwrite). The ring starts all-zero,
/// which models "bytes before the stream are 0".
#[derive(Debug, Clone)]
struct History {
    /// Ring of original bytes; only the first `dist` slots are used.
    buf: [u8; MAX_DISTANCE],
    dist: usize,
    pos: usize,
    /// `true` once the distance has been validated (lazily on first use so
    /// construction stays infallible and `const`).
    valid: bool,
}

impl History {
    const fn new(dist: usize) -> Self {
        Self {
            buf: [0u8; MAX_DISTANCE],
            dist,
            pos: 0,
            valid: false,
        }
    }

    /// Validate the configured distance exactly once.
    fn check(&mut self) -> Result<(), Error> {
        if self.valid {
            return Ok(());
        }
        if (MIN_DISTANCE..=MAX_DISTANCE).contains(&self.dist) {
            self.valid = true;
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }

    fn reset(&mut self) {
        self.buf = [0u8; MAX_DISTANCE];
        self.pos = 0;
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming delta-filter encoder.
#[derive(Debug, Clone)]
pub struct Encoder {
    hist: History,
}

impl Encoder {
    /// Construct an encoder with the given `dist` (`1..=256`). The
    /// distance is validated lazily on the first `encode`/`finish` call.
    pub const fn new(dist: usize) -> Self {
        Self {
            hist: History::new(dist),
        }
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        self.hist.check()?;
        let n = input.len().min(output.len());
        let h = &mut self.hist;
        let dist = h.dist;

        // Phase 1: the first `dist` outputs subtract bytes from the ring
        // history (previous calls / the all-zero seed).
        let seed = dist.min(n);
        for i in 0..seed {
            let orig = input[i];
            let prev = h.buf[h.pos];
            output[i] = orig.wrapping_sub(prev);
            h.buf[h.pos] = orig;
            h.pos += 1;
            if h.pos == dist {
                h.pos = 0;
            }
        }
        // Phase 2: for `i >= dist` the predecessor is `input[i - dist]` (the
        // input *is* the original stream), so read it directly and drop the
        // ring modulo branch and history accesses from the hot loop.
        for i in dist..n {
            output[i] = input[i].wrapping_sub(input[i - dist]);
        }
        // Phase 3: refresh the ring from the last `dist` *original* (input)
        // bytes, matching the byte-by-byte cursor/layout (see the decoder for
        // the derivation).
        if n >= dist {
            let pos_final = (h.pos + (n % dist)) % dist;
            for k in 0..dist {
                h.buf[(pos_final + k) % dist] = input[n - dist + k];
            }
            h.pos = pos_final;
        }
        Ok(RawProgress {
            consumed: n,
            written: n,
            done: false,
        })
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        // 1:1 transform with no trailer: once all input is consumed the
        // stream is complete and there is nothing buffered to flush.
        self.hist.check()?;
        Ok(RawProgress {
            consumed: 0,
            written: 0,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.hist.reset();
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming delta-filter decoder (inverse of [`Encoder`]).
#[derive(Debug, Clone)]
pub struct Decoder {
    hist: History,
}

impl Decoder {
    /// Construct a decoder with the given `dist` (`1..=256`), which must
    /// match the encoder's distance.
    pub const fn new(dist: usize) -> Self {
        Self {
            hist: History::new(dist),
        }
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        self.hist.check()?;
        let n = input.len().min(output.len());
        let h = &mut self.hist;
        let dist = h.dist;

        // Phase 1: the first `dist` outputs depend on the ring history (bytes
        // from previous calls / the all-zero seed). Reconstruct them through
        // the ring exactly as before.
        let seed = dist.min(n);
        for i in 0..seed {
            let prev = h.buf[h.pos];
            let orig = input[i].wrapping_add(prev);
            output[i] = orig;
            h.buf[h.pos] = orig;
            h.pos += 1;
            if h.pos == dist {
                h.pos = 0;
            }
        }
        // Phase 2: once `i >= dist`, `output[i - dist]` is the original byte we
        // need — read it straight from the output buffer. This drops both the
        // ring modulo branch and the history load/store from the hot loop and
        // exposes a simple `out[i] = in[i] + out[i-dist]` recurrence.
        for i in dist..n {
            output[i] = input[i].wrapping_add(output[i - dist]);
        }
        // Phase 3: refresh the ring from the last `dist` reconstructed bytes so
        // the next call continues seamlessly. (When `n < dist` the ring was
        // already fully advanced byte-by-byte in phase 1 and is correct.)
        //
        // After processing `n` bytes the byte-by-byte algorithm leaves
        // `pos = (p0 + n) % dist` and `buf[(pos + k) % dist] = output[n-dist+k]`
        // for k in 0..dist (each slot holds its most recent write). Reproduce
        // exactly that state. With `seed == dist` here, `h.pos` is back at `p0`,
        // so the final cursor is `(p0 + n) % dist == (h.pos + (n % dist)) %
        // dist`.
        if n >= dist {
            let pos_final = (h.pos + (n % dist)) % dist;
            for k in 0..dist {
                h.buf[(pos_final + k) % dist] = output[n - dist + k];
            }
            h.pos = pos_final;
        }
        Ok(RawProgress {
            consumed: n,
            written: n,
            done: false,
        })
    }

    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        self.hist.check()?;
        Ok(RawProgress {
            consumed: 0,
            written: 0,
            done: true,
        })
    }

    fn raw_reset(&mut self) {
        self.hist.reset();
    }
}
