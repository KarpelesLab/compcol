//! StuffIt method-13 ("LZ+Huffman") payload decoder.
//!
//! Method 13 is LZSS over a 64 KiB window with the literal/length symbols and
//! offset bit-lengths entropy-coded by per-stream canonical Huffman codes (or
//! one of five predefined code-length sets). The bitstream is read
//! **least-significant-bit first** throughout. See [`super`] for the format
//! overview and the wire details.
//!
//! The raw method-13 payload carries no in-band container framing — the
//! uncompressed length lives in the surrounding SIT member header. Like
//! [`crate::lha`], this decoder accepts that length out of band via
//! [`super::DecoderConfig::with_len`]; with no length supplied it decodes
//! until the explicit end-of-stream symbol `0x140`. Either way the decoder
//! buffers the whole compressed payload (a single LSB-first bitstream whose
//! end is only known once the caller says so) and starts decoding when the
//! stream ends. The *output* is not buffered: tokens are decoded a stretch at
//! a time as the caller asks for bytes, and only the 64 KiB match window plus
//! a small read-ahead is kept, whatever the size of the fork.
//!
//! DoS hygiene: output is bounded (by `expected_len` when supplied, else by a
//! sane cap so a malformed stream cannot expand without limit before hitting
//! EOS); all canonical codes are Kraft-validated; back-references are
//! bounds-checked against the 64 KiB window and the start of output;
//! arithmetic is checked; and no input can drive a panic. Illegal control
//! byte, truncation, or an invalid code map to
//! [`Error::Corrupt`]/[`Error::UnexpectedEnd`]/[`Error::InvalidHuffmanTree`]/[`Error::InvalidDistance`].
//! Because output is handed out as it is decoded, an error that lies part
//! way into the stream is reported after the bytes before it.

extern crate alloc;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitReader;
use super::huffman::Huffman;
use super::tables;
use super::window::{self, WINDOW_SIZE};

/// Cap on decoded output when no expected length is supplied, so a malformed
/// stream that never reaches end-of-stream cannot expand without bound. 256
/// MiB comfortably exceeds any classic-StuffIt member.
const DEFAULT_OUTPUT_CAP: usize = 256 * 1024 * 1024;

/// Number of literal/length symbols (`0x000..=0x140`).
const LITLEN_SYMBOLS: usize = tables::LITLEN_SYMBOLS;
/// End-of-stream literal/length symbol.
const EOS_SYMBOL: u32 = 0x140;

/// Decoded bytes kept ready ahead of the caller: [`Stream::fill`] decodes
/// whole tokens until at least this many are pending (or the stream ends).
/// The longest token is a 32 832-byte match, so pending output stays under
/// `FILL` + that.
const FILL: usize = 32 * 1024;

/// A method-13 token stream being decoded: the three codes, the position in
/// the buffered payload, and the tail of the output.
///
/// The payload itself is owned by the caller and passed to [`fill`] each
/// time, so that the stream can live beside it in the [`Decoder`].
///
/// [`fill`]: Stream::fill
struct Stream {
    code_a: Huffman,
    code_b: Huffman,
    offset_code: Huffman,
    /// Bit position of the next token in the payload.
    bit_pos: usize,
    /// Next literal/length symbol uses code A (after a literal, or at the
    /// start) rather than code B (after a match).
    use_a: bool,
    /// Out-of-band uncompressed length, if known.
    expected_len: Option<usize>,
    /// Most bytes the stream may decode to: `expected_len`, or the open-ended
    /// cap.
    cap: usize,
    /// The caller's output limit, as a total the stream may not pass.
    limit: usize,
    /// The tail of the decoded output. `out[..cursor]` has been handed to
    /// the caller and is kept as match history (at least the last 64 KiB of
    /// it, once that much exists); `out[cursor..]` is still to hand out.
    out: Vec<u8>,
    cursor: usize,
    /// Decoded bytes already dropped from the front of `out`.
    trimmed: usize,
    /// The end-of-stream symbol was read, or `expected_len` was reached.
    ended: bool,
}

impl core::fmt::Debug for Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stream")
            .field("bit_pos", &self.bit_pos)
            .field("produced", &self.produced())
            .field("pending", &self.pending())
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// Read the control byte and build the three codes.
    ///
    /// `expected_len` is the out-of-band uncompressed length; when `Some(n)`,
    /// decoding stops at exactly `n` bytes (and `n` bounds output). When
    /// `None`, decoding runs until the `0x140` end-of-stream symbol, bounded
    /// by `open_cap`: a stream that would produce more is rejected with
    /// [`Error::Corrupt`].
    ///
    /// `limit` is the caller's output limit
    /// ([`Decoder::set_output_limit`](crate::Decoder::set_output_limit),
    /// `u64::MAX` for none): a stream that would decode to more fails with
    /// [`Error::OutputLimitExceeded`] at the token that crosses it.
    fn new(
        input: &[u8],
        expected_len: Option<usize>,
        open_cap: usize,
        limit: u64,
    ) -> Result<Self, Error> {
        if input.is_empty() {
            // No payload at all: the control byte and stream are missing.
            return Err(Error::UnexpectedEnd);
        }

        let mut reader = BitReader::new(input);

        // ── control byte ──────────────────────────────────────────────────
        let control = reader.read_bits(8)? as u8;
        let high = control >> 4;

        let (code_a, code_b, offset_code) = if high == 0 {
            // Dynamic: code-length lists are transmitted, decoded with the
            // fixed meta-code.
            let alias = control & 0x08 != 0;
            let offset_syms = (control & 0x07) as usize + 10;

            let meta = Huffman::from_codes(&tables::META_CODE_VALUES, &tables::META_CODE_LENGTHS)?;

            let a_lengths = read_code_lengths(&mut reader, &meta, LITLEN_SYMBOLS)?;
            let code_a = Huffman::from_lengths(&a_lengths)?;

            let code_b = if alias {
                Huffman::from_lengths(&a_lengths)?
            } else {
                let b_lengths = read_code_lengths(&mut reader, &meta, LITLEN_SYMBOLS)?;
                Huffman::from_lengths(&b_lengths)?
            };

            let off_lengths = read_code_lengths(&mut reader, &meta, offset_syms)?;
            let offset_code = Huffman::from_lengths(&off_lengths)?;

            (code_a, code_b, offset_code)
        } else if (1..=5).contains(&high) {
            // Predefined: select one of five fixed length sets.
            let idx = (high - 1) as usize;
            let code_a = Huffman::from_lengths(tables::PREDEFINED_FIRST[idx])?;
            let code_b = Huffman::from_lengths(tables::PREDEFINED_SECOND[idx])?;
            let offset_code = Huffman::from_lengths(tables::PREDEFINED_OFFSET[idx])?;
            (code_a, code_b, offset_code)
        } else {
            // high nibble >= 6 is illegal.
            return Err(Error::Corrupt);
        };

        Ok(Self {
            code_a,
            code_b,
            offset_code,
            bit_pos: reader.bit_pos(),
            use_a: true,
            expected_len,
            cap: expected_len.unwrap_or(open_cap),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            out: Vec::new(),
            cursor: 0,
            trimmed: 0,
            ended: false,
        })
    }

    /// Bytes decoded so far, handed out or not.
    fn produced(&self) -> usize {
        self.trimmed + self.out.len()
    }

    /// Decoded bytes not yet handed out.
    fn pending(&self) -> usize {
        self.out.len() - self.cursor
    }

    /// Every byte has been decoded and handed out.
    fn finished(&self) -> bool {
        self.ended && self.pending() == 0
    }

    /// Decode whole tokens from `input` (the same payload every time) until
    /// at least [`FILL`] bytes are pending or the stream has ended.
    fn fill(&mut self, input: &[u8]) -> Result<(), Error> {
        // Drop history no match can reach any more. At least a full window
        // stays, so `window::emit_match`'s "before the start of output"
        // check keeps meaning exactly that.
        if self.cursor >= 2 * WINDOW_SIZE {
            let drop = self.cursor - WINDOW_SIZE;
            self.out.drain(..drop);
            self.cursor -= drop;
            self.trimmed += drop;
        }

        let mut reader = BitReader::at(input, self.bit_pos);
        while !self.ended && self.pending() < FILL {
            self.token(&mut reader)?;
        }
        self.bit_pos = reader.bit_pos();
        Ok(())
    }

    /// Decode one token: a literal, a match, or the end of the stream.
    fn token(&mut self, reader: &mut BitReader<'_>) -> Result<(), Error> {
        let produced = self.produced();
        if self.expected_len.is_some() && produced >= self.cap {
            // Reached the requested length. A well-formed stream emits the
            // EOS symbol here, but the header length is the authority.
            self.ended = true;
            return Ok(());
        }
        // With no expected length the cap is only a bomb guard, not a place
        // to stop: decoding carries on so that the end-of-stream symbol is
        // still accepted at exactly `cap` bytes, while any further output
        // is rejected below instead of returning a truncated prefix.
        let litlen = if self.use_a {
            self.code_a.decode(reader)?
        } else {
            self.code_b.decode(reader)?
        };

        if litlen <= 0xFF {
            if produced >= self.cap {
                // Open-ended cap reached (see above); same error as a match
                // that would cross it.
                return Err(Error::Corrupt);
            }
            if produced >= self.limit {
                return Err(Error::OutputLimitExceeded);
            }
            window::emit_literal(&mut self.out, litlen as u8);
            self.use_a = true;
            return Ok(());
        }
        if litlen == EOS_SYMBOL {
            if let Some(n) = self.expected_len
                && produced != n
            {
                // The stream ended before producing the bytes the header
                // promised.
                return Err(Error::Corrupt);
            }
            self.ended = true;
            return Ok(());
        }

        // Match: determine length.
        let length: usize = if litlen <= 0x13D {
            (litlen as usize - 0x100) + 3
        } else if litlen == 0x13E {
            reader.read_bits(10)? as usize + 65
        } else if litlen == 0x13F {
            reader.read_bits(15)? as usize + 65
        } else {
            // Symbol beyond 0x140: impossible for a 321-symbol alphabet.
            return Err(Error::Corrupt);
        };

        // Decode offset.
        let b = self.offset_code.decode(reader)?;
        let distance: usize = if b == 0 {
            1
        } else if b == 1 {
            2
        } else {
            let extra = reader.read_bits(b - 1)? as usize;
            // (1 << (b-1)) + extra + 1; b <= 17 in practice, well within usize.
            (1usize << (b - 1))
                .checked_add(extra)
                .and_then(|v| v.checked_add(1))
                .ok_or(Error::Corrupt)?
        };

        // Bound the copy so a crafted huge length can't blow past the cap.
        let end = produced.checked_add(length).ok_or(Error::Corrupt)?;
        if end > self.cap {
            // For an explicit expected_len this is a corrupt stream; for the
            // open-ended cap it is a bomb guard.
            return Err(Error::Corrupt);
        }
        // Likewise the caller's limit, checked before the copy is made.
        if end > self.limit {
            return Err(Error::OutputLimitExceeded);
        }
        window::emit_match(&mut self.out, distance, length)?;
        self.use_a = false;
        Ok(())
    }

    /// Hand out pending bytes; returns how many were copied.
    fn drain(&mut self, output: &mut [u8]) -> usize {
        let n = self.pending().min(output.len());
        output[..n].copy_from_slice(&self.out[self.cursor..self.cursor + n]);
        self.cursor += n;
        n
    }
}

/// Decode a complete method-13 payload into a fresh `Vec`, with the default
/// open-ended cap. See [`Stream::new`] for the parameters.
#[cfg(test)]
fn decode_payload(input: &[u8], expected_len: Option<usize>, limit: u64) -> Result<Vec<u8>, Error> {
    decode_payload_capped(input, expected_len, DEFAULT_OUTPUT_CAP, limit)
}

/// [`decode_payload`] with the open-ended output cap as a parameter
/// (`open_cap` only applies when `expected_len` is `None`).
#[cfg(test)]
fn decode_payload_capped(
    input: &[u8],
    expected_len: Option<usize>,
    open_cap: usize,
    limit: u64,
) -> Result<Vec<u8>, Error> {
    if let Some(0) = expected_len {
        return Ok(Vec::new());
    }
    let mut stream = Stream::new(input, expected_len, open_cap, limit)?;
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        stream.fill(input)?;
        let n = stream.drain(&mut buf);
        all.extend_from_slice(&buf[..n]);
        if stream.finished() {
            return Ok(all);
        }
    }
}

/// Decode one transmitted code-length list of `count` entries using the
/// fixed meta-code and the stateful run-length-of-lengths scheme (spec §5.1).
fn read_code_lengths(
    reader: &mut BitReader<'_>,
    meta: &Huffman,
    count: usize,
) -> Result<Vec<u8>, Error> {
    let mut lengths: Vec<u8> = Vec::with_capacity(count);
    // Signed accumulator; -1 marks an absent symbol (length 0).
    let mut acc: i32 = 0;

    while lengths.len() < count {
        let v = meta.decode(reader)?;
        // Number of *extra* copies of `acc` to emit before the per-symbol
        // append (opcodes 34/35/36); the per-symbol append always happens.
        let mut extra: usize = 0;
        match v {
            0..=30 => acc = v as i32 + 1,
            31 => acc = -1,
            32 => acc = acc.checked_add(1).ok_or(Error::Corrupt)?,
            33 => acc = acc.checked_sub(1).ok_or(Error::Corrupt)?,
            34 => {
                if reader.read_bit()? == 1 {
                    extra = 1;
                }
            }
            35 => extra = reader.read_bits(3)? as usize + 2,
            36 => extra = reader.read_bits(6)? as usize + 10,
            _ => return Err(Error::InvalidHuffmanTree),
        }

        let len_byte: u8 = if acc >= 1 { acc as u8 } else { 0 };
        // Emit `extra` run copies plus the one per-symbol append.
        for _ in 0..=extra {
            if lengths.len() == count {
                break;
            }
            lengths.push(len_byte);
        }
    }

    Ok(lengths)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Still accumulating the compressed payload across streaming calls.
    Buffering,
    /// The payload is complete; `stream` is decoding it to the caller.
    Decoding,
    /// Terminal.
    Done,
}

/// Streaming StuffIt method-13 decoder.
///
/// Construct via the [`Algorithm`](crate::traits::Algorithm) factory with a
/// [`super::DecoderConfig`] (optionally [`with_len`](super::DecoderConfig::with_len)).
/// `decode` buffers the raw method-13 payload; once `finish` says the payload
/// is complete, the decoded bytes are produced across `finish`/`decode`
/// calls, as many as each call's output buffer takes.
///
/// Memory: the compressed payload is held whole, but the decoded fork is
/// not. Only the 64 KiB match window and a read-ahead of under 64 KiB are
/// kept (about 230 KiB at most), so a tiny payload that decodes to hundreds
/// of megabytes costs no more than a small one.
///
/// With an output limit set
/// ([`set_output_limit`](crate::Decoder::set_output_limit), which
/// [`LimitedDecoder`](crate::limit::LimitedDecoder) does for you), a stream
/// that decodes to more than the limit fails with
/// [`Error::OutputLimitExceeded`] at the token that would cross it. Without
/// one, a stream with no supplied length may decode to at most 256 MiB.
#[derive(Debug)]
pub struct Decoder {
    expected_len: Option<usize>,
    input: Vec<u8>,
    /// The token stream, once the payload is complete.
    stream: Option<Stream>,
    state: State,
    poisoned: bool,
    /// Caller's output limit (`u64::MAX` = none). Configuration: kept
    /// across `reset`.
    limit: u64,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Build a decoder with no out-of-band length: decoding runs until the
    /// in-band end-of-stream symbol `0x140`.
    pub const fn new() -> Self {
        Self {
            expected_len: None,
            input: Vec::new(),
            stream: None,
            state: State::Buffering,
            poisoned: false,
            limit: u64::MAX,
        }
    }

    /// Build a decoder told the member's uncompressed length out of band (the
    /// SIT container's convention). Decoding stops at exactly `len` bytes.
    pub const fn with_len(len: usize) -> Self {
        Self {
            expected_len: Some(len),
            input: Vec::new(),
            stream: None,
            state: State::Buffering,
            poisoned: false,
            limit: u64::MAX,
        }
    }

    /// The payload is complete: read its header and get ready to decode.
    fn start(&mut self) -> Result<(), Error> {
        if self.expected_len == Some(0) {
            // An empty member needs no payload at all.
            self.state = State::Done;
            return Ok(());
        }
        self.stream = Some(Stream::new(
            &self.input,
            self.expected_len,
            DEFAULT_OUTPUT_CAP,
            self.limit,
        )?);
        self.state = State::Decoding;
        Ok(())
    }

    /// Decode into `output` until it is full or the stream is finished.
    fn pump(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let mut written = 0usize;
        if let Some(stream) = self.stream.as_mut() {
            loop {
                // Decode ahead first, so the end of the stream is known by
                // the time its last bytes are handed out.
                stream.fill(&self.input)?;
                written += stream.drain(&mut output[written..]);
                if stream.finished() {
                    break;
                }
                if written == output.len() {
                    return Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    });
                }
            }
        }
        // Finished: the payload and the window are no longer needed.
        self.stream = None;
        self.input.clear();
        self.state = State::Done;
        Ok(RawProgress {
            consumed: 0,
            written,
            done: true,
        })
    }

    /// [`pump`](Self::pump), poisoning the decoder on error.
    fn pump_or_poison(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let r = self.pump(output);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        match self.state {
            State::Buffering => {
                // An empty member with a known zero length needs no input.
                self.input.extend_from_slice(input);
                Ok(RawProgress {
                    consumed: input.len(),
                    written: 0,
                    done: false,
                })
            }
            State::Decoding => self.pump_or_poison(output),
            State::Done => Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            }),
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if self.state == State::Buffering
            && let Err(e) = self.start()
        {
            self.poisoned = true;
            return Err(e);
        }
        if self.state == State::Done {
            return Ok(RawProgress {
                consumed: 0,
                written: 0,
                done: true,
            });
        }
        self.pump_or_poison(output)
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.stream = None;
        self.state = State::Buffering;
        self.poisoned = false;
    }

    fn raw_set_output_limit(&mut self, max_output_bytes: u64) {
        self.limit = max_output_bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit::LimitedDecoder;
    use crate::traits::Decoder as _;

    /// MSB-canonical codes for a length list, as `from_lengths` assigns
    /// them: `(code, bit length)` per symbol.
    fn canonical(lengths: &[u8]) -> Vec<(u32, u32)> {
        let mut order: Vec<usize> = (0..lengths.len()).filter(|&s| lengths[s] != 0).collect();
        order.sort_by_key(|&s| (lengths[s], s));
        let mut codes = alloc::vec![(0u32, 0u32); lengths.len()];
        let (mut code, mut prev) = (0u64, lengths[order[0]] as u32);
        for s in order {
            let l = lengths[s] as u32;
            code <<= l - prev;
            prev = l;
            codes[s] = (code as u32, l);
            code += 1;
        }
        codes
    }

    /// Minimal method-13 writer for the predefined code set 1: literals,
    /// longest-form matches at distance 1, and the end-of-stream symbol.
    struct Writer {
        bytes: Vec<u8>,
        bits: usize,
        code_a: Vec<(u32, u32)>,
        code_b: Vec<(u32, u32)>,
        offsets: Vec<(u32, u32)>,
        /// Next literal/length symbol uses code A (else code B).
        use_a: bool,
    }

    /// Bytes one [`Writer::runs`] match decodes to: symbol `0x13F` with all
    /// 15 extra bits set.
    const RUN_LEN: usize = 0x7FFF + 65;

    impl Writer {
        fn new() -> Self {
            let mut w = Self {
                bytes: Vec::new(),
                bits: 0,
                code_a: canonical(tables::PREDEFINED_FIRST[0]),
                code_b: canonical(tables::PREDEFINED_SECOND[0]),
                offsets: canonical(tables::PREDEFINED_OFFSET[0]),
                use_a: true,
            };
            // Control byte: high nibble 1 = predefined set 1.
            for i in 0..8 {
                w.bit((0x10u32 >> i) & 1);
            }
            w
        }

        fn bit(&mut self, b: u32) {
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            *self.bytes.last_mut().unwrap() |= (b as u8) << (self.bits % 8);
            self.bits += 1;
        }

        /// Emit a code: MSB-canonical, first bit first.
        fn code(&mut self, (code, len): (u32, u32)) {
            assert!(len != 0, "symbol absent from the predefined code");
            for i in (0..len).rev() {
                self.bit((code >> i) & 1);
            }
        }

        /// Emit a literal/length symbol with whichever code is current.
        fn symbol(&mut self, sym: u32) {
            let c = if self.use_a {
                self.code_a[sym as usize]
            } else {
                self.code_b[sym as usize]
            };
            self.code(c);
        }

        fn literals(mut self, data: &[u8]) -> Self {
            for &b in data {
                self.symbol(b as u32);
                self.use_a = true;
            }
            self
        }

        /// `count` matches of [`RUN_LEN`] bytes at distance 1.
        fn runs(mut self, count: usize) -> Self {
            for _ in 0..count {
                self.symbol(0x13F);
                for _ in 0..15 {
                    self.bit(1);
                }
                let c = self.offsets[0];
                self.code(c);
                self.use_a = false;
            }
            self
        }

        /// `n` bits of `v`, least significant first.
        fn field(&mut self, v: u32, n: u32) {
            for i in 0..n {
                self.bit((v >> i) & 1);
            }
        }

        /// A match of `length` bytes (3 or more) from `distance` back
        /// (1..=1024, the reach of set 1's offset code).
        fn copy(&mut self, distance: usize, length: usize) {
            match length {
                3..=64 => self.symbol(0x100 + (length as u32 - 3)),
                65..=1088 => {
                    self.symbol(0x13E);
                    self.field(length as u32 - 65, 10);
                }
                _ => {
                    self.symbol(0x13F);
                    self.field(length as u32 - 65, 15);
                }
            }
            // distance = (1 << (b - 1)) + extra + 1 for b >= 2.
            let (b, extra) = match distance {
                1 => (0, 0),
                2 => (1, 0),
                d => {
                    let v = d as u32 - 1;
                    let high = 31 - v.leading_zeros();
                    (high + 1, v - (1 << high))
                }
            };
            let c = self.offsets[b as usize];
            self.code(c);
            if b >= 2 {
                self.field(extra, b - 1);
            }
            self.use_a = false;
        }

        fn finish(mut self, eos: bool) -> Vec<u8> {
            if eos {
                self.symbol(EOS_SYMBOL);
            }
            self.bytes
        }
    }

    /// Feed `stream` whole, then drain through `finish`.
    fn drive<D: crate::traits::Decoder>(dec: &mut D, stream: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut buf = alloc::vec![0u8; 64 * 1024];
        let mut pos = 0;
        while pos < stream.len() {
            let (p, _) = dec.decode(&stream[pos..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            pos += p.consumed;
        }
        loop {
            let (p, status) = dec.finish(&mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            if status == crate::Status::StreamEnd {
                return Ok(out);
            }
        }
    }

    /// Feed `stream`, then drain through `finish` with `chunk`-byte buffers,
    /// returning the output and the largest internal output buffer seen.
    fn drain_chunked(dec: &mut Decoder, stream: &[u8], chunk: usize) -> (Vec<u8>, usize) {
        let mut buf = alloc::vec![0u8; chunk];
        let (p, _) = dec.decode(stream, &mut buf).unwrap();
        assert_eq!((p.consumed, p.written), (stream.len(), 0));
        let mut out = Vec::new();
        let mut held = 0usize;
        loop {
            let (p, status) = dec.finish(&mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            held = held.max(dec.stream.as_ref().map_or(0, |s| s.out.capacity()));
            if status == crate::Status::StreamEnd {
                return (out, held);
            }
            assert!(p.written > 0, "finish made no progress");
        }
    }

    /// The fork is handed out as it is decoded: however much a stream
    /// expands, the decoder keeps only the window and a read-ahead.
    #[test]
    fn output_is_streamed_not_buffered() {
        let runs = 260;
        let stream = Writer::new().literals(b"x").runs(runs).finish(true);
        let total = 1 + runs * RUN_LEN;
        assert!(total > 8 << 20);

        let mut dec = Decoder::new();
        let (out, held) = drain_chunked(&mut dec, &stream, 4096);
        assert_eq!(out.len(), total);
        assert!(out.iter().all(|&b| b == b'x'));
        // 2 windows of history + FILL + one maximal match, with room for
        // the Vec's growth policy; nowhere near the 8 MiB of output.
        assert!(held <= 512 * 1024, "decoder held {held} bytes");
        // Finished: the payload and window are released.
        assert!(dec.stream.is_none());
    }

    /// Literals and matches at every distance the writer reaches, over
    /// enough output to trim the history several times, against a plain
    /// model, at several output chunk sizes.
    #[test]
    fn streamed_output_matches_a_reference_model() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut w = Writer::new();
        let mut want: Vec<u8> = Vec::new();
        // Output length after each token.
        let mut ends: Vec<usize> = Vec::new();
        while want.len() < 600 * 1024 {
            let r = next();
            if want.is_empty() || r % 4 == 0 {
                let b = (r >> 8) as u8;
                w = w.literals(&[b]);
                want.push(b);
            } else {
                let distance = 1 + (r >> 8) as usize % want.len().min(1024);
                let length = match (r >> 32) % 8 {
                    0 => 65 + (r >> 40) as usize % 1024,
                    1 => 1089 + (r >> 40) as usize % 20_000,
                    _ => 3 + (r >> 40) as usize % 62,
                };
                w.copy(distance, length);
                for _ in 0..length {
                    want.push(want[want.len() - distance]);
                }
            }
            ends.push(want.len());
        }
        let stream = w.finish(true);

        for chunk in [1usize, 7, 4096, 100_000, 1 << 20] {
            let (out, held) = drain_chunked(&mut Decoder::new(), &stream, chunk);
            assert!(out == want, "chunk {chunk}: output differs");
            assert!(held <= 512 * 1024, "chunk {chunk}: held {held} bytes");

            let (out, _) = drain_chunked(&mut Decoder::with_len(want.len()), &stream, chunk);
            assert!(out == want, "chunk {chunk}: output differs (known length)");
        }
        // A known length that falls on a token boundary is where decoding
        // stops, without reading on to the end-of-stream symbol.
        for target in [1usize, 70_000, 200_001] {
            let n = *ends.iter().find(|&&e| e >= target).unwrap();
            let (out, _) = drain_chunked(&mut Decoder::with_len(n), &stream, 4096);
            assert!(out == want[..n], "length {n}: output differs");
        }
    }

    /// An error part way in is reported once the bytes before it have
    /// been decoded, and poisons the decoder.
    #[test]
    fn truncated_stream_fails_after_its_prefix() {
        let mut stream = Writer::new().literals(b"x").runs(8).finish(true);
        stream.truncate(stream.len() - 2);
        let mut dec = Decoder::new();
        let mut buf = alloc::vec![0u8; 4096];
        dec.decode(&stream, &mut buf).unwrap();
        let mut got = 0usize;
        let err = loop {
            match dec.finish(&mut buf) {
                Ok((p, status)) => {
                    assert_ne!(status, crate::Status::StreamEnd);
                    assert!(p.written > 0);
                    got += p.written;
                }
                Err(e) => break e,
            }
        };
        assert_eq!(err, Error::UnexpectedEnd);
        assert!(got < 1 + 8 * RUN_LEN);
        assert_eq!(dec.finish(&mut buf), Err(Error::Corrupt));
    }

    #[test]
    fn writer_round_trips() {
        let stream = Writer::new().literals(b"stuffit!").finish(true);
        assert_eq!(
            decode_payload(&stream, None, u64::MAX).unwrap(),
            b"stuffit!"
        );
        assert_eq!(
            decode_payload(&stream, Some(8), u64::MAX).unwrap(),
            b"stuffit!"
        );
    }

    #[test]
    fn writer_runs_round_trip() {
        let stream = Writer::new()
            .literals(b"x")
            .runs(2)
            .literals(b"y")
            .finish(true);
        let out = decode_payload(&stream, None, u64::MAX).unwrap();
        assert_eq!(out.len(), 2 + 2 * RUN_LEN);
        assert!(out[..out.len() - 1].iter().all(|&b| b == b'x'));
        assert_eq!(out[out.len() - 1], b'y');
    }

    #[test]
    fn open_ended_output_exactly_at_cap_is_accepted() {
        let stream = Writer::new().literals(b"stuffit!").finish(true);
        assert_eq!(
            decode_payload_capped(&stream, None, 8, u64::MAX).unwrap(),
            b"stuffit!"
        );
    }

    /// With no out-of-band length, a stream that keeps producing output at
    /// the internal cap must fail rather than return a silently truncated
    /// prefix as if it were the whole member.
    #[test]
    fn open_ended_literal_past_cap_is_an_error() {
        let stream = Writer::new().literals(b"stuffit!!").finish(true);
        assert_eq!(
            decode_payload_capped(&stream, None, 8, u64::MAX),
            Err(Error::Corrupt)
        );
        // A known length is still the authority on where to stop.
        assert_eq!(
            decode_payload_capped(&stream, Some(8), 8, u64::MAX).unwrap(),
            b"stuffit!"
        );
    }

    /// The audit's bomb, scaled down: a few dozen bytes that decode to
    /// 1.3 MB. With an output limit the decoder must refuse instead of
    /// building the fork.
    #[test]
    fn output_limit_refuses_a_bomb() {
        let stream = Writer::new().literals(b"x").runs(40).finish(true);
        assert!(stream.len() < 256);
        let total = 1 + 40 * RUN_LEN;

        let mut dec = Decoder::new();
        assert_eq!(drive(&mut dec, &stream).unwrap().len(), total);

        let mut dec = Decoder::new();
        dec.set_output_limit(1024);
        assert_eq!(drive(&mut dec, &stream), Err(Error::OutputLimitExceeded));

        // The limit is configuration: it survives a reset.
        dec.reset();
        assert_eq!(drive(&mut dec, &stream), Err(Error::OutputLimitExceeded));
    }

    /// The limit is a bound, not an off-by-one: exactly `limit` bytes
    /// decode, one more does not, whether the last token is a match or a
    /// literal.
    #[test]
    fn output_exactly_at_the_limit_decodes() {
        for stream in [
            Writer::new().literals(b"x").runs(2).finish(true),
            Writer::new()
                .literals(b"x")
                .runs(2)
                .literals(b"yz")
                .finish(true),
        ] {
            let plain = decode_payload(&stream, None, u64::MAX).unwrap();
            let n = plain.len() as u64;

            let mut dec = Decoder::new();
            dec.set_output_limit(n);
            assert_eq!(drive(&mut dec, &stream).unwrap(), plain);
            dec.set_output_limit(n - 1);
            dec.reset();
            assert_eq!(drive(&mut dec, &stream), Err(Error::OutputLimitExceeded));

            // Same with the length known out of band.
            let mut dec = Decoder::with_len(plain.len());
            dec.set_output_limit(n);
            assert_eq!(drive(&mut dec, &stream).unwrap(), plain);
            let mut dec = Decoder::with_len(plain.len());
            dec.set_output_limit(n - 1);
            assert_eq!(drive(&mut dec, &stream), Err(Error::OutputLimitExceeded));
        }
    }

    /// `LimitedDecoder` passes its budget down, so the bomb is refused
    /// rather than decoded and then found to be too long.
    #[test]
    fn limited_decoder_refuses_a_bomb() {
        let stream = Writer::new().literals(b"x").runs(40).finish(true);
        let mut dec = LimitedDecoder::new(Decoder::new(), 1024);
        assert_eq!(drive(&mut dec, &stream), Err(Error::OutputLimitExceeded));
        assert_eq!(
            crate::vec::decompress_to_vec_capped::<crate::sit13::Sit13>(&stream, 1024),
            Err(Error::OutputLimitExceeded)
        );

        // At exactly the budget a stream still decodes.
        let small = Writer::new().literals(b"stuffit!").finish(true);
        let mut dec = LimitedDecoder::new(Decoder::new(), 8);
        assert_eq!(drive(&mut dec, &small).unwrap(), b"stuffit!");
        assert_eq!(
            crate::vec::decompress_to_vec_capped::<crate::sit13::Sit13>(&small, 8).unwrap(),
            b"stuffit!"
        );
    }
}
