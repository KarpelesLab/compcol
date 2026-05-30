//! One-shot `Vec<u8>` compress / decompress helpers.
//!
//! These wrap the streaming [`Encoder`]/[`Decoder`] API for the common
//! case where the caller already has the whole payload in memory and
//! just wants a `Vec<u8>` back. Use [`crate::io`] (when the `std`
//! feature is enabled) for file- or socket-backed streaming.
//!
//! All four functions are generic over an [`Algorithm`]. The
//! no-config forms ([`compress_to_vec`], [`decompress_to_vec`]) use
//! the algorithm's default config; the `_with` forms accept an
//! explicit config (e.g. `gzip::EncoderConfig { level: 9 }`).
//!
//! ```ignore
//! // Default-config compress:
//! let compressed = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(&data)?;
//! let plain      = compcol::vec::decompress_to_vec::<compcol::gzip::Gzip>(&compressed)?;
//!
//! // Explicit config:
//! let config = compcol::gzip::EncoderConfig { level: 9 };
//! let small  = compcol::vec::compress_to_vec_with::<compcol::gzip::Gzip>(&data, config)?;
//! ```

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::limit::LimitedDecoder;
use crate::{Algorithm, Decoder, Encoder, Error, Status};

/// Per-call scratch buffer size for the codec → output Vec staging path.
/// 64 KiB matches what `src/bin/compcol.rs` uses for its CLI streaming
/// loop and is large enough that a single algorithm tick rarely
/// returns `OutputFull` more than once on realistic inputs.
const SCRATCH: usize = 64 * 1024;

/// Compress `input` with `A`'s default encoder config and return the
/// encoded bytes.
pub fn compress_to_vec<A: Algorithm>(input: &[u8]) -> Result<Vec<u8>, Error> {
    compress_to_vec_with::<A>(input, A::EncoderConfig::default())
}

/// Compress `input` with the supplied `A::EncoderConfig` and return
/// the encoded bytes.
pub fn compress_to_vec_with<A: Algorithm>(
    input: &[u8],
    config: A::EncoderConfig,
) -> Result<Vec<u8>, Error> {
    let mut enc = A::encoder_with(config);
    // Compressed output is usually smaller than the input — start with
    // the input length as a capacity hint and let the Vec grow on
    // incompressible payloads.
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut scratch: Vec<u8> = vec![0u8; SCRATCH];

    let mut consumed = 0usize;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        match status {
            Status::InputEmpty => break,
            Status::OutputFull => continue,
            Status::StreamEnd => break,
        }
    }
    loop {
        let (p, status) = enc.finish(&mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            // Codec asked for more output room but our scratch is plenty
            // large and the Vec can grow — this is a stall the caller
            // can't fix. Treat as corruption rather than loop forever.
            return Err(Error::Corrupt);
        }
    }
    Ok(out)
}

/// Decompress `input` with `A`'s default decoder config and return the
/// decoded bytes.
///
/// # Warning: unbounded output
///
/// This grows the output `Vec` with **no upper bound**. A small malicious
/// input can expand to many gigabytes (a "decompression bomb"), exhausting
/// memory. Do **not** call this on untrusted input. Use
/// [`decompress_to_vec_capped`] (or [`decompress_to_vec_capped_with`]) to
/// cap the decoded size and get [`Error::OutputLimitExceeded`] when the
/// cap is hit.
pub fn decompress_to_vec<A: Algorithm>(input: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_to_vec_with::<A>(input, A::DecoderConfig::default())
}

/// Decompress `input` with the supplied `A::DecoderConfig`.
///
/// # Warning: unbounded output
///
/// Like [`decompress_to_vec`], this grows the output with **no upper
/// bound** and must **not** be used on untrusted input. Use
/// [`decompress_to_vec_capped_with`] for a bounded variant.
pub fn decompress_to_vec_with<A: Algorithm>(
    input: &[u8],
    config: A::DecoderConfig,
) -> Result<Vec<u8>, Error> {
    let mut dec = A::decoder_with(config);
    // Decompressed output is usually larger than the compressed input;
    // a 2× capacity hint avoids a few early grows without overcommitting.
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(2));
    let mut scratch: Vec<u8> = vec![0u8; SCRATCH];

    let mut consumed = 0usize;
    while consumed < input.len() {
        let (p, status) = dec.decode(&input[consumed..], &mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => return Ok(out),
            Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }
    loop {
        let (p, status) = dec.finish(&mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            return Err(Error::Corrupt);
        }
    }
    Ok(out)
}

/// Decompress `input` with `A`'s default decoder config, refusing to
/// produce more than `max_output` bytes of plaintext.
///
/// Unlike [`decompress_to_vec`], this is safe to call on untrusted input:
/// the decoder is wrapped in a [`LimitedDecoder`] so a decompression bomb
/// aborts with [`Error::OutputLimitExceeded`] once the decoded size would
/// exceed `max_output`, instead of growing the output `Vec` without bound.
pub fn decompress_to_vec_capped<A: Algorithm>(
    input: &[u8],
    max_output: u64,
) -> Result<Vec<u8>, Error> {
    decompress_to_vec_capped_with::<A>(input, A::DecoderConfig::default(), max_output)
}

/// Decompress `input` with the supplied `A::DecoderConfig`, refusing to
/// produce more than `max_output` bytes of plaintext.
///
/// The bounded counterpart of [`decompress_to_vec_with`]; see
/// [`decompress_to_vec_capped`] for the rationale. Returns
/// [`Error::OutputLimitExceeded`] if the decoded output would exceed
/// `max_output`.
pub fn decompress_to_vec_capped_with<A: Algorithm>(
    input: &[u8],
    config: A::DecoderConfig,
    max_output: u64,
) -> Result<Vec<u8>, Error> {
    let mut dec = LimitedDecoder::new(A::decoder_with(config), max_output);
    // Capacity hint: usual 2× compressed size, but never preallocate more
    // than the cap — otherwise the hint itself becomes an allocation
    // vector for a tiny bomb that declares a huge size.
    let hint = (input.len() as u64)
        .saturating_mul(2)
        .min(max_output)
        .min(usize::MAX as u64) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(hint);
    let mut scratch: Vec<u8> = vec![0u8; SCRATCH];

    let mut consumed = 0usize;
    while consumed < input.len() {
        let (p, status) = dec.decode(&input[consumed..], &mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => return Ok(out),
            Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }
    loop {
        let (p, status) = dec.finish(&mut scratch)?;
        out.extend_from_slice(&scratch[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            return Err(Error::Corrupt);
        }
    }
    Ok(out)
}
