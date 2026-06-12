//! bzip2 streaming decoder.
//!
//! Strategy: we buffer the compressed input into an internal `Vec<u8>`
//! and decode one block at a time. The "do we have enough input to
//! decode the next block?" decision is made by parsing speculatively —
//! if a `BitReader` ever returns `Error::UnexpectedEnd` mid-block, we
//! return `more input please` to the caller without poisoning the
//! decoder. (The reference bzip2 source uses a longjmp-driven retry
//! loop for the same effect; we use a snapshot/restore pattern instead.)
//!
//! Once a block is decoded we hold the reconstructed raw bytes (after
//! inverse-RLE-2 → inverse-MTF → inverse-BWT → inverse-RLE-1) in
//! `decoded` and drain them into the caller's output buffer.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitReader;
use super::bwt::bwt_inverse;
use super::crc::Crc32;
use super::huffman::{DecodeTable, MAX_CODE_LEN};
use super::mtf::mtf_inverse_reduced;
use super::rle::rle1_inverse;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const STREAM_END_MAGIC: u64 = 0x1772_4538_5090;

/// Coarse decoder phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading 4-byte stream header `BZh<level>`.
    Header,
    /// Between blocks: poised to read either the block magic or the
    /// stream-end magic.
    BlockOrEnd,
    /// Block magic seen; payload decode in progress. We don't keep
    /// fine state here — the block is decoded eagerly once enough
    /// input is buffered.
    DrainDecoded,
    /// End-of-stream magic seen; reading combined CRC.
    StreamCrc,
    /// Stream successfully terminated; drain any remaining decoded
    /// bytes and return `done=true`.
    Done,
}

pub struct Decoder {
    /// Buffered compressed bytes — bzip2's bit stream is variable-rate
    /// and our parser needs random access, so we accumulate.
    in_buf: Vec<u8>,
    /// Position (in **whole bytes**) up to which we have committed —
    /// i.e. fully decoded into `decoded`. Anything before this index
    /// is no longer needed.
    in_committed_bytes: usize,
    /// Position (in **bits** from the start of in_buf) of the parser.
    bit_pos: usize,

    /// Decoded raw bytes waiting to be delivered to the caller.
    decoded: Vec<u8>,
    decoded_idx: usize,

    /// Running combined CRC across already-decoded blocks. Matched
    /// against the stream footer at the end.
    combined_crc: u32,

    /// Header level digit (1..=9). Captured for diagnostics; not
    /// otherwise used (we trust whatever the encoder produced).
    level: u8,

    phase: Phase,
    poisoned: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            in_buf: Vec::new(),
            in_committed_bytes: 0,
            bit_pos: 0,
            decoded: Vec::new(),
            decoded_idx: 0,
            combined_crc: 0,
            level: 0,
            phase: Phase::Header,
            poisoned: false,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Try to make progress: parse whatever the buffered input
    /// supports, populating `self.decoded`. Returns `Ok(true)` if we
    /// made any state-machine progress, `Ok(false)` if we genuinely
    /// need more input or the output buffer is full.
    fn step(&mut self) -> Result<bool, Error> {
        match self.phase {
            Phase::Header => self.try_header(),
            Phase::BlockOrEnd => self.try_block_or_end(),
            Phase::DrainDecoded => Ok(false), // caller drains, then we advance from BlockOrEnd
            Phase::StreamCrc => self.try_stream_crc(),
            Phase::Done => Ok(false),
        }
    }

    fn try_header(&mut self) -> Result<bool, Error> {
        // Need at least 4 bytes for "BZh<level>".
        let buffered = self.in_buf.len() - self.in_committed_bytes;
        if buffered < 4 {
            return Ok(false);
        }
        let off = self.in_committed_bytes;
        if &self.in_buf[off..off + 3] != b"BZh" {
            return Err(self.poison(Error::BadHeader));
        }
        let lvl = self.in_buf[off + 3];
        if !(b'1'..=b'9').contains(&lvl) {
            return Err(self.poison(Error::BadHeader));
        }
        self.level = lvl - b'0';
        self.in_committed_bytes += 4;
        self.bit_pos = self.in_committed_bytes * 8;
        self.phase = Phase::BlockOrEnd;
        Ok(true)
    }

    fn try_block_or_end(&mut self) -> Result<bool, Error> {
        // We need at least 6 bytes to read the 48-bit magic (worst
        // case the magic starts at a non-aligned bit position, so we
        // may actually need 7 bytes).
        let available_bits = self.in_buf.len() * 8 - self.bit_pos;
        if available_bits < 48 {
            return Ok(false);
        }

        // Snapshot bit position; if a speculative read fails, we
        // rewind.
        let snapshot = self.bit_pos;
        let mut br = BitReader::new_at(&self.in_buf, self.bit_pos);
        let magic = br.read_bits_48()?;
        if magic == BLOCK_MAGIC {
            // Block payload begins right after the magic. We need to
            // decode the rest of the block now; if anything in the
            // block tries to read past the buffered input we rewind
            // and ask for more.
            self.bit_pos = br.position();
            // Try to decode the block; if it fails with UnexpectedEnd
            // we rewind to before the magic.
            match self.decode_block_payload() {
                Ok(()) => {
                    self.phase = Phase::DrainDecoded;
                    Ok(true)
                }
                Err(Error::UnexpectedEnd) => {
                    // Roll back to before the magic.
                    self.bit_pos = snapshot;
                    Ok(false)
                }
                Err(e) => Err(self.poison(e)),
            }
        } else if magic == STREAM_END_MAGIC {
            self.bit_pos = br.position();
            self.phase = Phase::StreamCrc;
            Ok(true)
        } else {
            Err(self.poison(Error::BadHeader))
        }
    }

    fn try_stream_crc(&mut self) -> Result<bool, Error> {
        let available_bits = self.in_buf.len() * 8 - self.bit_pos;
        if available_bits < 32 {
            return Ok(false);
        }
        let mut br = BitReader::new_at(&self.in_buf, self.bit_pos);
        let expected = br.read_bits(32)?;
        if expected != self.combined_crc {
            return Err(self.poison(Error::ChecksumMismatch));
        }
        // Advance to the next byte boundary; bzip2 pads the trailer
        // with zero bits up to a byte boundary.
        let mut p = br.position();
        let rem = p & 7;
        if rem != 0 {
            p += 8 - rem;
        }
        self.bit_pos = p;
        self.in_committed_bytes = self.bit_pos / 8;
        self.phase = Phase::Done;
        Ok(true)
    }

    /// Decode a single block's payload, having already consumed the
    /// 48-bit block magic. Appends the reconstituted raw bytes to
    /// `self.decoded` and updates the running combined CRC.
    ///
    /// Returns `Err(Error::UnexpectedEnd)` to signal "more input
    /// needed, please rewind"; other errors are real failures.
    fn decode_block_payload(&mut self) -> Result<(), Error> {
        let mut br = BitReader::new_at(&self.in_buf, self.bit_pos);

        let stored_crc = br.read_bits(32)?;
        let randomized = br.read_bit()?;
        if randomized != 0 {
            return Err(Error::Unsupported);
        }
        let origin = br.read_bits(24)?;

        // Symbol map.
        let stripe_top = br.read_bits(16)?;
        let mut alphabet: Vec<u8> = Vec::with_capacity(64);
        for stripe in 0..16 {
            let stripe_used = stripe_top & (1 << (15 - stripe)) != 0;
            if !stripe_used {
                continue;
            }
            let mask = br.read_bits(16)?;
            for byte in 0..16 {
                if mask & (1 << (15 - byte)) != 0 {
                    alphabet.push(((stripe << 4) | byte) as u8);
                }
            }
        }
        if alphabet.is_empty() {
            return Err(Error::Corrupt);
        }
        let num_used = alphabet.len();
        let alpha_size = num_used + 2; // includes RUNA/RUNB merged + EOB

        let num_tables = br.read_bits(3)? as usize;
        if !(2..=6).contains(&num_tables) {
            return Err(Error::Corrupt);
        }
        let num_selectors = br.read_bits(15)? as usize;
        if num_selectors == 0 || num_selectors > 18002 {
            return Err(Error::Corrupt);
        }

        // Read MTF-coded selectors: each is a unary count of 1-bits
        // followed by a 0 stop-bit; that count is the MTF position
        // (0..num_tables).
        let mut mtf_list: Vec<u8> = (0..num_tables as u8).collect();
        let mut selectors: Vec<u8> = Vec::with_capacity(num_selectors);
        for _ in 0..num_selectors {
            let mut pos = 0;
            loop {
                if pos >= num_tables {
                    return Err(Error::Corrupt);
                }
                let bit = br.read_bit()?;
                if bit == 0 {
                    break;
                }
                pos += 1;
            }
            let v = mtf_list.remove(pos);
            selectors.push(v);
            mtf_list.insert(0, v);
        }

        // Per-table code-length tables.
        let mut tables: Vec<DecodeTable> = Vec::with_capacity(num_tables);
        for _ in 0..num_tables {
            let mut cur = br.read_bits(5)? as i32;
            if !(1..=(MAX_CODE_LEN as i32)).contains(&cur) {
                return Err(Error::Corrupt);
            }
            let mut lens = vec![0u8; alpha_size];
            for symbol_len in lens.iter_mut().take(alpha_size) {
                loop {
                    let b = br.read_bit()?;
                    if b == 0 {
                        break;
                    }
                    // Read another bit: 0 = +1, 1 = -1.
                    let dir = br.read_bit()?;
                    if dir == 0 {
                        cur += 1;
                    } else {
                        cur -= 1;
                    }
                    if !(1..=(MAX_CODE_LEN as i32)).contains(&cur) {
                        return Err(Error::Corrupt);
                    }
                }
                *symbol_len = cur as u8;
            }
            tables.push(DecodeTable::from_lengths(&lens)?);
        }

        // Now decode symbols 50 at a time, switching tables per group
        // per selector. Stop when EOB (= alpha_size - 1) is seen.
        //
        // Anti-bomb bound: a single bzip2 block decodes to at most the
        // declared block size = level * 100_000 bytes (level 1..=9). The
        // RLE-2 stream we are reconstructing here (`mtf_indices`) is the
        // pre-BWT/pre-MTF symbol stream and must not exceed that. We keep
        // a tiny constant of slack (1024) aligned with the original
        // per-run headroom, but the bound stays within a couple KB of the
        // real block size — NOT a multiple of it. Without a *cumulative*
        // cap a malicious stream can flush a fresh ~8 MB zero-run after
        // every one of ~900_100 non-zero symbols and inflate this
        // intermediate buffer to hundreds of GB before any output is
        // produced (so LimitedDecoder, which only sees output bytes, can't
        // stop it). Mirrors arsenic's `block.len() + count > block_size`.
        let max_block_bytes: u64 = self.level as u64 * 100_000 + 1024;
        let eob = (alpha_size - 1) as u16;
        let mut mtf_indices: Vec<u8> = Vec::new();
        // RLE-2 accumulator: each time we see RUNA/RUNB we extend the
        // current zero-run; on a non-zero symbol we materialise the
        // run as that many zero MTF indices and then push the
        // resolved MTF byte.
        let mut group_idx = 0usize;
        let mut symbols_in_group = 0usize;
        let mut zero_run: u32 = 0;
        let mut zero_weight: u32 = 1;
        loop {
            if symbols_in_group == 0 {
                if group_idx >= num_selectors {
                    return Err(Error::Corrupt);
                }
                symbols_in_group = 50;
            }
            let sel = selectors[group_idx] as usize;
            if sel >= num_tables {
                return Err(Error::Corrupt);
            }
            let tbl = &tables[sel];
            let s = tbl.decode_symbol(&mut br)?;
            symbols_in_group -= 1;
            if symbols_in_group == 0 {
                group_idx += 1;
            }

            if s == eob {
                break;
            }

            if s <= 1 {
                let contrib = if s == 0 { 1 } else { 2 };
                zero_run = zero_run.saturating_add(contrib * zero_weight);
                zero_weight = zero_weight.saturating_mul(2);
                // Anti-bomb (cumulative): the already-materialised indices
                // plus the in-flight zero-run must not exceed the declared
                // block size. This catches both a single oversized run and
                // the death-by-a-thousand-runs attack where each non-zero
                // symbol flushes and resets a fresh run.
                if mtf_indices.len() as u64 + zero_run as u64 > max_block_bytes {
                    return Err(Error::Corrupt);
                }
            } else {
                if zero_run > 0 {
                    mtf_indices.extend(core::iter::repeat_n(0u8, zero_run as usize));
                    zero_run = 0;
                    zero_weight = 1;
                }
                // s >= 2 → MTF index (s - 1) in 1..=num_used-1.
                let idx = (s - 1) as usize;
                if idx >= num_used {
                    return Err(Error::Corrupt);
                }
                // Anti-bomb (cumulative): bound the literal pushes too.
                if mtf_indices.len() as u64 + 1 > max_block_bytes {
                    return Err(Error::Corrupt);
                }
                mtf_indices.push(idx as u8);
            }
        }
        if zero_run > 0 {
            // Anti-bomb (cumulative): final flush must also stay in bounds.
            if mtf_indices.len() as u64 + zero_run as u64 > max_block_bytes {
                return Err(Error::Corrupt);
            }
            mtf_indices.extend(core::iter::repeat_n(0u8, zero_run as usize));
        }

        // mtf_indices is the L-column-after-MTF stream; invert MTF, then
        // invert BWT, then invert RLE-1.
        let l_column = mtf_inverse_reduced(&mtf_indices, &alphabet);
        if origin as usize >= l_column.len() {
            return Err(Error::Corrupt);
        }
        let bwt = bwt_inverse(&l_column, origin);
        let raw = rle1_inverse(&bwt);

        // Validate the per-block CRC.
        let mut crc = Crc32::new();
        crc.update(&raw);
        if crc.value() != stored_crc {
            return Err(Error::ChecksumMismatch);
        }

        // Update combined CRC: rotate-left then XOR.
        self.combined_crc = self.combined_crc.rotate_left(1) ^ stored_crc;

        // Stash the decoded bytes for the caller.
        self.decoded.extend_from_slice(&raw);

        // Commit the input position.
        self.bit_pos = br.position();
        self.in_committed_bytes = self.bit_pos / 8;

        Ok(())
    }

    fn drain(&mut self, output: &mut [u8], written: &mut usize) {
        let avail = self.decoded.len() - self.decoded_idx;
        let space = output.len() - *written;
        let n = avail.min(space);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.decoded[self.decoded_idx..self.decoded_idx + n]);
            self.decoded_idx += n;
            *written += n;
        }
        if self.decoded_idx == self.decoded.len() {
            self.decoded.clear();
            self.decoded_idx = 0;
            if matches!(self.phase, Phase::DrainDecoded) {
                // After fully draining a decoded block, return to the
                // BlockOrEnd state so the next iteration parses either
                // another block or the end-of-stream magic.
                self.phase = Phase::BlockOrEnd;
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        // First: drain any already-decoded bytes.
        self.drain(output, &mut written);

        // Then: absorb input, step the parser, and drain again, until
        // we either fill the output, finish, or exhaust the input.
        loop {
            // If we've decoded the end-of-stream successfully and
            // drained everything, signal `done`.
            if matches!(self.phase, Phase::Done) && self.decoded_idx == self.decoded.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: true,
                });
            }

            // Pull input into the buffer. We may need to buffer an
            // entire block at once because the speculative-decode loop
            // wants random access; rather than try to predict the
            // block length, we keep ingesting until either step()
            // succeeds or the caller's input is drained.
            if consumed < input.len() {
                // Grab the rest of the caller's slice in one shot.
                // The bzip2 spec caps each block at 900 KB compressed,
                // so the buffer can't grow without bound across one
                // stream.
                self.in_buf.extend_from_slice(&input[consumed..]);
                consumed = input.len();
            }

            // Try to step.
            let progressed = self.step()?;

            // Drain anything the step produced.
            self.drain(output, &mut written);

            // Bookkeep `in_buf` — chop off committed bytes if it has
            // grown big to keep memory bounded.
            if self.in_committed_bytes > 1 << 20 {
                // Drop the committed prefix.
                let off = self.in_committed_bytes;
                self.in_buf.drain(..off);
                self.bit_pos -= off * 8;
                self.in_committed_bytes = 0;
            }

            if matches!(self.phase, Phase::Done) {
                // Stream finished; mark `done` next iteration (which
                // catches the drained-empty case).
                continue;
            }

            // If the output is full and we still have decoded bytes
            // queued, return to let the caller drain.
            if written == output.len() && self.decoded_idx < self.decoded.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            // No progress and no more input → ask for more.
            if !progressed {
                // For the streaming case where the caller already gave
                // us bytes but we still couldn't proceed, we need them
                // to come back with more.
                if consumed >= input.len() {
                    return Ok(RawProgress {
                        consumed,
                        written,
                        done: false,
                    });
                }
                // Otherwise we still have more input to absorb; loop.
            }

            // If we made progress but the output buffer is now full,
            // bail out so the caller can drain.
            if written == output.len() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let empty: [u8; 0] = [];
        let p = self.raw_decode(&empty, output)?;
        if matches!(self.phase, Phase::Done) && self.decoded_idx == self.decoded.len() {
            Ok(RawProgress {
                consumed: 0,
                written: p.written,
                done: true,
            })
        } else {
            // We're not done and we have no input to advance with —
            // truncated stream.
            Err(self.poison(Error::UnexpectedEnd))
        }
    }

    fn raw_reset(&mut self) {
        self.in_buf.clear();
        self.in_committed_bytes = 0;
        self.bit_pos = 0;
        self.decoded.clear();
        self.decoded_idx = 0;
        self.combined_crc = 0;
        self.level = 0;
        self.phase = Phase::Header;
        self.poisoned = false;
    }
}
