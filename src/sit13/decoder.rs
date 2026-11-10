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
//! buffers the whole compressed payload (a single LSB-first bitstream that is
//! not cheaply resumable mid-symbol) and decodes it in one pass once the
//! stream ends, then drains the decoded bytes to the caller across calls.
//!
//! DoS hygiene: output is bounded (by `expected_len` when supplied, else by a
//! sane cap so a malformed stream cannot expand without limit before hitting
//! EOS); all canonical codes are Kraft-validated; back-references are
//! bounds-checked against the 64 KiB window and the start of output;
//! arithmetic is checked; and no input can drive a panic. Illegal control
//! byte, truncation, or an invalid code map to
//! [`Error::Corrupt`]/[`Error::UnexpectedEnd`]/[`Error::InvalidHuffmanTree`]/[`Error::InvalidDistance`].

extern crate alloc;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitReader;
use super::huffman::Huffman;
use super::tables;
use super::window;

/// Cap on decoded output when no expected length is supplied, so a malformed
/// stream that never reaches end-of-stream cannot expand without bound. 256
/// MiB comfortably exceeds any classic-StuffIt member while bounding memory.
const DEFAULT_OUTPUT_CAP: usize = 256 * 1024 * 1024;

/// Number of literal/length symbols (`0x000..=0x140`).
const LITLEN_SYMBOLS: usize = tables::LITLEN_SYMBOLS;
/// End-of-stream literal/length symbol.
const EOS_SYMBOL: u32 = 0x140;

/// Decode a complete method-13 payload into a fresh `Vec`.
///
/// `expected_len` is the out-of-band uncompressed length; when `Some(n)`,
/// decoding stops at exactly `n` bytes (and `n` bounds output). When `None`,
/// decoding runs until the `0x140` end-of-stream symbol, bounded by
/// [`DEFAULT_OUTPUT_CAP`]: a stream that would produce more is rejected with
/// [`Error::Corrupt`].
pub(crate) fn decode_payload(input: &[u8], expected_len: Option<usize>) -> Result<Vec<u8>, Error> {
    decode_payload_capped(input, expected_len, DEFAULT_OUTPUT_CAP)
}

/// [`decode_payload`] with the open-ended output cap as a parameter
/// (`open_cap` only applies when `expected_len` is `None`).
fn decode_payload_capped(
    input: &[u8],
    expected_len: Option<usize>,
    open_cap: usize,
) -> Result<Vec<u8>, Error> {
    if let Some(0) = expected_len {
        return Ok(Vec::new());
    }
    if input.is_empty() {
        // A non-zero (or unknown) expected length but no payload at all: the
        // control byte and stream are missing.
        return Err(Error::UnexpectedEnd);
    }

    let cap = expected_len.unwrap_or(open_cap);
    let mut out: Vec<u8> = Vec::new();
    if let Some(n) = expected_len {
        // Pre-reserve modestly; do not trust a huge n to pre-allocate.
        out.reserve(n.min(1 << 20));
    }

    let mut reader = BitReader::new(input);

    // ── control byte ──────────────────────────────────────────────────────
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

    // ── token loop ──────────────────────────────────────────────────────
    // `use_a` selects code A (after a literal / at start) or code B (after a
    // match).
    let mut use_a = true;
    loop {
        if expected_len.is_some() && out.len() >= cap {
            // Reached the requested length. A well-formed stream emits the
            // EOS symbol here, but the header length is the authority.
            break;
        }
        // With no expected length the cap is only a bomb guard, not a place
        // to stop: decoding carries on so that the end-of-stream symbol is
        // still accepted at exactly `cap` bytes, while any further output
        // is rejected below instead of returning a truncated prefix.
        let litlen = if use_a {
            code_a.decode(&mut reader)?
        } else {
            code_b.decode(&mut reader)?
        };

        if litlen <= 0xFF {
            if out.len() >= cap {
                // Open-ended cap reached (see above); same error as a match
                // that would cross it.
                return Err(Error::Corrupt);
            }
            window::emit_literal(&mut out, litlen as u8);
            use_a = true;
            continue;
        }
        if litlen == EOS_SYMBOL {
            break;
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
        let b = offset_code.decode(&mut reader)?;
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
        if out
            .len()
            .checked_add(length)
            .map(|t| t > cap)
            .unwrap_or(true)
        {
            // For an explicit expected_len this is a corrupt stream; for the
            // open-ended cap it is a bomb guard.
            return Err(Error::Corrupt);
        }
        window::emit_match(&mut out, distance, length)?;
        use_a = false;
    }

    if let Some(n) = expected_len
        && out.len() != n
    {
        // Stream ended (EOS or input exhaustion handled above) but produced
        // the wrong number of bytes.
        return Err(Error::Corrupt);
    }

    Ok(out)
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
    /// Decoded; draining `output` to the caller.
    Draining,
    /// Terminal.
    Done,
}

/// Streaming StuffIt method-13 decoder.
///
/// Construct via the [`Algorithm`](crate::traits::Algorithm) factory with a
/// [`super::DecoderConfig`] (optionally [`with_len`](super::DecoderConfig::with_len)).
/// Buffers the raw method-13 payload, decodes it in one pass once the stream
/// ends, then drains the decoded bytes across `decode`/`finish` calls.
#[derive(Debug)]
pub struct Decoder {
    expected_len: Option<usize>,
    input: Vec<u8>,
    output: Vec<u8>,
    out_cursor: usize,
    state: State,
    poisoned: bool,
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
            output: Vec::new(),
            out_cursor: 0,
            state: State::Buffering,
            poisoned: false,
        }
    }

    /// Build a decoder told the member's uncompressed length out of band (the
    /// SIT container's convention). Decoding stops at exactly `len` bytes.
    pub const fn with_len(len: usize) -> Self {
        Self {
            expected_len: Some(len),
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            state: State::Buffering,
            poisoned: false,
        }
    }

    fn decode_now(&mut self) -> Result<(), Error> {
        if self.state != State::Buffering {
            return Ok(());
        }
        if self.expected_len == Some(0) {
            self.output = Vec::new();
        } else {
            self.output = decode_payload(&self.input, self.expected_len)?;
        }
        self.state = State::Draining;
        Ok(())
    }

    fn drain(&mut self, output: &mut [u8]) -> RawProgress {
        let remaining = self.output.len() - self.out_cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + take]);
        self.out_cursor += take;
        let done = self.out_cursor >= self.output.len();
        if done {
            self.state = State::Done;
        }
        RawProgress {
            consumed: 0,
            written: take,
            done,
        }
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
            State::Draining => Ok(self.drain(output)),
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
            && let Err(e) = self.decode_now()
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
        Ok(self.drain(output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.state = State::Buffering;
        self.poisoned = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal method-13 writer for the predefined code set 1: literals and
    /// the end-of-stream symbol only, so every symbol uses code A.
    struct Writer {
        bytes: Vec<u8>,
        bits: usize,
        codes: Vec<(u32, u32)>,
    }

    impl Writer {
        fn new() -> Self {
            // MSB-canonical codes for the length list, as `from_lengths`
            // assigns them.
            let lengths = tables::PREDEFINED_FIRST[0];
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
            let mut w = Self {
                bytes: Vec::new(),
                bits: 0,
                codes,
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

        /// Emit a literal/length symbol: MSB-canonical code, first bit first.
        fn symbol(&mut self, sym: u32) {
            let (code, len) = self.codes[sym as usize];
            for i in (0..len).rev() {
                self.bit((code >> i) & 1);
            }
        }

        fn literals(mut self, data: &[u8]) -> Self {
            for &b in data {
                self.symbol(b as u32);
            }
            self
        }

        fn finish(mut self, eos: bool) -> Vec<u8> {
            if eos {
                self.symbol(EOS_SYMBOL);
            }
            self.bytes
        }
    }

    #[test]
    fn writer_round_trips() {
        let stream = Writer::new().literals(b"stuffit!").finish(true);
        assert_eq!(decode_payload(&stream, None).unwrap(), b"stuffit!");
        assert_eq!(decode_payload(&stream, Some(8)).unwrap(), b"stuffit!");
    }

    #[test]
    fn open_ended_output_exactly_at_cap_is_accepted() {
        let stream = Writer::new().literals(b"stuffit!").finish(true);
        assert_eq!(
            decode_payload_capped(&stream, None, 8).unwrap(),
            b"stuffit!"
        );
    }

    /// With no out-of-band length, a stream that keeps producing output at
    /// the internal cap must fail rather than return a silently truncated
    /// prefix as if it were the whole member.
    #[test]
    fn open_ended_literal_past_cap_is_an_error() {
        let stream = Writer::new().literals(b"stuffit!!").finish(true);
        assert_eq!(decode_payload_capped(&stream, None, 8), Err(Error::Corrupt));
        // A known length is still the authority on where to stop.
        assert_eq!(
            decode_payload_capped(&stream, Some(8), 8).unwrap(),
            b"stuffit!"
        );
    }
}
