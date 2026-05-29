//! Decompression-bomb defenses.
//!
//! A small compressed input can expand to many gigabytes — sub-kilobyte
//! zstd/lzma/brotli streams can hit terabytes — which is a hazard for
//! callers that decompress untrusted input (network endpoints, archive
//! readers, anti-virus scanners). This module provides a single wrapper
//! type, [`LimitedDecoder`], that takes any [`Decoder`] and aborts with
//! [`Error::OutputLimitExceeded`] if decoded output would exceed a
//! caller-supplied byte budget.
//!
//! The wrapper is `no_std`-clean and doesn't need any feature flags —
//! it adds two `u64` fields and a thin pass-through to the inner
//! decoder. The budget includes every byte the inner decoder writes
//! into the caller's slice; bytes the inner consumes from input or
//! buffers internally don't count.
//!
//! ```ignore
//! use compcol::{Algorithm, gzip::Gzip};
//! use compcol::limit::LimitedDecoder;
//!
//! // Refuse anything larger than 16 MiB of decoded output.
//! let mut dec = LimitedDecoder::new(Gzip::decoder(), 16 * 1024 * 1024);
//!
//! // The wrapper composes with `compcol::io::DecoderReader`:
//! # #[cfg(feature = "std")]
//! # fn use_with_io(dec: LimitedDecoder<<Gzip as Algorithm>::Decoder>) {
//! let r = compcol::io::DecoderReader::new(std::io::empty(), dec);
//! # let _ = r;
//! # }
//! ```
//!
//! For runtime-selected algorithms, wrap the boxed decoder the factory
//! returns:
//!
//! ```ignore
//! # #[cfg(feature = "factory")]
//! # {
//! let inner = compcol::factory::decoder_by_name("zstd").unwrap();
//! let mut dec = LimitedDecoder::new(inner, 64 * 1024 * 1024);
//! # }
//! ```

use crate::{Decoder, Error, Progress, Status};

/// Wraps any [`Decoder`] and aborts decoding once the cumulative output
/// would exceed `max_output_bytes`. The inner decoder is left poisoned
/// after a limit overflow — call [`reset`](Decoder::reset) if you want
/// to reuse it.
pub struct LimitedDecoder<D: Decoder> {
    inner: D,
    limit: u64,
    written: u64,
}

impl<D: Decoder> LimitedDecoder<D> {
    /// Wrap `inner` with a `max_output_bytes` budget on decoded output.
    ///
    /// A budget of `u64::MAX` is effectively unlimited (the inner
    /// decoder runs unbounded); use `Decoder` directly in that case
    /// rather than paying for the comparison.
    pub fn new(inner: D, max_output_bytes: u64) -> Self {
        Self {
            inner,
            limit: max_output_bytes,
            written: 0,
        }
    }

    /// Bytes the inner decoder has emitted so far against the budget.
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    /// Remaining budget. Returns 0 once the limit is reached.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.written)
    }

    /// Borrow the inner decoder.
    pub fn get_ref(&self) -> &D {
        &self.inner
    }

    /// Mutably borrow the inner decoder.
    pub fn get_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Recover the inner decoder, discarding the budget tracking.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: Decoder> Decoder for LimitedDecoder<D> {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let remaining = self.remaining();
        if remaining == 0 {
            // Budget exhausted. A decoder whose plaintext is already fully
            // emitted may still need one or more calls to consume the
            // stream's trailer (block CRC / footer / EOS marker) and reach
            // StreamEnd. Those calls emit zero output. Capping the output
            // slice to 0 would force codecs like bzip2 — whose blanket
            // `decode` derives status purely from byte counts — to report
            // OutputFull, which we'd then mis-translate as a bomb.
            //
            // Probe the inner with a 1-byte private scratch buffer: if it
            // doesn't write, we forward the status (lets the trailer-
            // consuming step finish). If it tries to write, we abort —
            // the probe byte stays in our local scratch and never reaches
            // the caller's slice, so no over-budget bytes leak out.
            let mut probe = [0u8; 1];
            let (p, status) = self.inner.decode(input, &mut probe)?;
            if p.written > 0 {
                return Err(Error::OutputLimitExceeded);
            }
            return Ok((
                Progress {
                    consumed: p.consumed,
                    written: 0,
                },
                status,
            ));
        }
        let cap = core::cmp::min(remaining as usize, output.len());
        let (p, status) = self.inner.decode(input, &mut output[..cap])?;
        self.written = self.written.saturating_add(p.written as u64);
        Ok((p, status))
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let remaining = self.remaining();
        if remaining == 0 {
            // Same trailer-consume probe as decode(). Mirrors the rationale
            // above for codecs whose finish path emits zero output.
            let mut probe = [0u8; 1];
            let (p, status) = self.inner.finish(&mut probe)?;
            if p.written > 0 {
                return Err(Error::OutputLimitExceeded);
            }
            return Ok((
                Progress {
                    consumed: 0,
                    written: 0,
                },
                status,
            ));
        }
        let cap = core::cmp::min(remaining as usize, output.len());
        let (p, status) = self.inner.finish(&mut output[..cap])?;
        self.written = self.written.saturating_add(p.written as u64);
        Ok((p, status))
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.written = 0;
    }

    fn discard_output(&mut self, input: &[u8], n: usize) -> Result<(Progress, Status), Error> {
        // discard_output emits no bytes to a caller slice, so it doesn't
        // consume budget. We forward to the inner directly.
        self.inner.discard_output(input, n)
    }
}
