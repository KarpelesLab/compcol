//! Streaming Zstandard encoder.
//!
//! Emits a single Zstd frame whose body is one or more blocks. Block_Type is
//! chosen per block:
//!
//! - `Raw_Block` (Block_Type=0) is used for very short inputs, the trailing
//!   "Last_Block" sentinel when no payload is left, or whenever a
//!   Compressed_Block would not actually save bytes.
//! - `Compressed_Block` (Block_Type=2) is the typical path: literals are
//!   emitted as `Raw_Literals_Block` (no Huffman compression) and sequences
//!   use the **Predefined_Mode** FSE tables for LL, OF, and ML (so the
//!   decoder gets the table distributions for free). The sequence bitstream
//!   is written in reverse — last sequence first — via
//!   [`RevBitWriter`](crate::zstd::encoder_bitwriter::RevBitWriter).
//!
//! Match finding is a hash-chain LZ77 ([`crate::zstd::matcher`]).
//!
//! Offsets are emitted as `offset_value = distance + 3` so we never hit the
//! repeat-offset aliases (offset_value ∈ 1..=3) — keeping the encoder simple
//! at a small compression cost (~ 1-2 extra bits per sequence).
//!
//! Frame layout we emit:
//! - 4 bytes magic (`0x28 0xB5 0x2F 0xFD`)
//! - 1 byte Frame_Header_Descriptor = `0x00`
//! - 1 byte Window_Descriptor = `0x70` (Exponent=14, Mantissa=0 → 16 KiB,
//!   matching our max block size)
//! - One or more blocks; the last carries `Last_Block = 1`.

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Encoder as EncoderTrait, Progress};
use crate::zstd::encoder_bitwriter::RevBitWriter;
use crate::zstd::encoder_fse::{
    DEFAULT_LL_ACCURACY_LOG, DEFAULT_LL_COUNTS, DEFAULT_ML_ACCURACY_LOG, DEFAULT_ML_COUNTS,
    DEFAULT_OF_ACCURACY_LOG, DEFAULT_OF_COUNTS, FseEncoder,
};
use crate::zstd::encoder_seq::{encode_sequence_count, ll_code, ml_code, of_code};
use crate::zstd::matcher::{MIN_MATCH, MatchFinder};

const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const FHD: u8 = 0x00;
/// Window_Descriptor = 0x70: Exponent=14, Mantissa=0 → 16 KiB window.
const WD: u8 = 0x70;

/// Block size threshold. We emit one block per [`BLOCK_SIZE`] bytes (or
/// whatever's left at `finish` time). 16 KiB matches the window we advertise.
const BLOCK_SIZE: usize = 16 * 1024;

/// Streaming Zstandard encoder.
pub struct Encoder {
    state: State,
    /// Input buffer pending block emission.
    pending: Vec<u8>,
    /// Output bytes ready to drain into the caller's buffer.
    out_buf: Vec<u8>,
    /// Cursor into `out_buf`.
    out_idx: usize,
    /// Reusable matcher.
    matcher: MatchFinder,
    /// FSE encoders for the three sequence streams. Built once and reused.
    ll_enc: FseEncoder,
    ml_enc: FseEncoder,
    of_enc: FseEncoder,
    /// Have we written the frame header yet?
    header_written: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Accepting new input and accumulating into `pending`.
    Accepting,
    /// `out_buf[out_idx..]` is being drained into the caller's output.
    Draining { last: bool },
    /// All output drained; the codec is fully finished.
    Done,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            state: State::Accepting,
            pending: Vec::with_capacity(BLOCK_SIZE),
            out_buf: Vec::new(),
            out_idx: 0,
            matcher: MatchFinder::new(BLOCK_SIZE),
            ll_enc: FseEncoder::from_normalized(&DEFAULT_LL_COUNTS, DEFAULT_LL_ACCURACY_LOG),
            ml_enc: FseEncoder::from_normalized(&DEFAULT_ML_COUNTS, DEFAULT_ML_ACCURACY_LOG),
            of_enc: FseEncoder::from_normalized(&DEFAULT_OF_COUNTS, DEFAULT_OF_ACCURACY_LOG),
            header_written: false,
        }
    }

    /// Append frame magic + FHD + WD to `out_buf`.
    fn write_frame_header(&mut self) {
        self.out_buf.extend_from_slice(&MAGIC);
        self.out_buf.push(FHD);
        self.out_buf.push(WD);
    }

    /// Append a 3-byte block header for the given body size, type, and
    /// last-block flag.
    fn push_block_header(out: &mut Vec<u8>, body_size: u32, block_type: u32, last: bool) {
        debug_assert!(body_size < (1u32 << 21));
        debug_assert!(block_type < 4);
        let bh: u32 = (if last { 1 } else { 0 }) | (block_type << 1) | (body_size << 3);
        out.push((bh & 0xFF) as u8);
        out.push(((bh >> 8) & 0xFF) as u8);
        out.push(((bh >> 16) & 0xFF) as u8);
    }

    /// Append a Raw_Block (header + payload) for `body`.
    fn append_raw_block(out: &mut Vec<u8>, body: &[u8], last: bool) {
        Self::push_block_header(out, body.len() as u32, 0, last);
        out.extend_from_slice(body);
    }

    /// Try to encode `pending` as a Compressed_Block. Returns the block body
    /// (without the 3-byte block header) if successful and smaller than a
    /// Raw_Block; otherwise `None`.
    fn try_compress_block(&mut self) -> Option<Vec<u8>> {
        if self.pending.len() < 16 {
            // Too small to bother — the framing overhead eats any savings.
            return None;
        }
        let buffer = self.pending.as_slice();
        self.matcher.resize_for(buffer.len());

        // Run LZ77.
        let mut sequences: Vec<Seq> = Vec::new();
        let mut literals: Vec<u8> = Vec::with_capacity(buffer.len());
        let mut lit_start: usize = 0;
        let mut pos: usize = 0;

        while pos + MIN_MATCH < buffer.len() {
            self.matcher.insert(buffer, pos);
            // Try to find a match.
            let m = self.matcher.find_match(buffer, pos, buffer.len());
            if let Some(m) = m {
                let literal_run = pos - lit_start;
                let distance = m.distance;
                let match_len = m.length;
                // Push literals from lit_start..pos.
                literals.extend_from_slice(&buffer[lit_start..pos]);
                sequences.push(Seq {
                    literal_length: literal_run as u32,
                    match_length: match_len as u32,
                    distance: distance as u32,
                });
                // Insert hash entries for the bytes we're skipping over (so
                // future matches inside this match are findable). Skip the
                // first one (already inserted above).
                for skip_pos in (pos + 1)..(pos + match_len) {
                    self.matcher.insert(buffer, skip_pos);
                }
                pos += match_len;
                lit_start = pos;
            } else {
                pos += 1;
            }
        }

        if sequences.is_empty() {
            return None;
        }

        // Trailing literals: from lit_start to end of buffer.
        let trailing_literals = &buffer[lit_start..];

        // Build literals section: Raw_Literals_Block.
        let regen_size = literals.len() + trailing_literals.len();
        let lit_section = build_raw_literals_section(&literals, trailing_literals);

        // Build sequences section.
        let seq_section = self.build_sequences_section(&sequences);

        let total = lit_section.len() + seq_section.len();
        let raw_size = buffer.len();
        if total >= raw_size {
            return None; // Not worth compressing.
        }
        let _ = regen_size;

        let mut body = Vec::with_capacity(total);
        body.extend_from_slice(&lit_section);
        body.extend_from_slice(&seq_section);
        Some(body)
    }

    /// Build the sequence section bytes: header (count + symbol-modes byte)
    /// followed by the FSE-encoded sequence bitstream.
    fn build_sequences_section(&self, sequences: &[Seq]) -> Vec<u8> {
        let n = sequences.len() as u32;
        let mut out = encode_sequence_count(n);
        // Symbol_Compression_Modes byte: bits [7:6]=LL_Mode, [5:4]=OF_Mode,
        // [3:2]=ML_Mode, [1:0]=Reserved.
        // 0b00 = Predefined_Mode. We use predefined for all three.
        let modes: u8 = 0b00_00_00_00;
        out.push(modes);

        // Pre-compute (code, extra_bits, extra_val) for each sequence.
        let mut ll_codes: Vec<u8> = Vec::with_capacity(sequences.len());
        let mut ml_codes: Vec<u8> = Vec::with_capacity(sequences.len());
        let mut of_codes: Vec<u8> = Vec::with_capacity(sequences.len());
        let mut ll_extras: Vec<(u32, u32)> = Vec::with_capacity(sequences.len());
        let mut ml_extras: Vec<(u32, u32)> = Vec::with_capacity(sequences.len());
        let mut of_extras: Vec<(u32, u32)> = Vec::with_capacity(sequences.len());

        for s in sequences {
            // We don't use repeat offsets — encode offset_value = distance + 3.
            let offset_value = s.distance + 3;
            let (oc, oe_bits, oe_val) = of_code(offset_value);
            of_codes.push(oc);
            of_extras.push((oe_bits, oe_val));

            let (lc, le_bits, le_val) = ll_code(s.literal_length);
            ll_codes.push(lc);
            ll_extras.push((le_bits, le_val));

            let (mc, me_bits, me_val) = ml_code(s.match_length);
            ml_codes.push(mc);
            ml_extras.push((me_bits, me_val));
        }

        // FSE-encode the symbol streams.
        let mut writer = RevBitWriter::new();
        let n_seq = sequences.len();

        // Reverse encoding pattern. Init states from the LAST sequence.
        let mut ll_state = self.ll_enc.init_state(ll_codes[n_seq - 1] as usize);
        let mut of_state = self.of_enc.init_state(of_codes[n_seq - 1] as usize);
        let mut ml_state = self.ml_enc.init_state(ml_codes[n_seq - 1] as usize);

        // For each sequence (processed in reverse), write to the bitstream
        // in the EXACT REVERSE of the decoder's read order.
        //
        // Decoder per-sequence read order (recall §3.1.1.3.2.1):
        //   1. OF_extra_bits (number = of_code value)
        //   2. ML_extra_bits
        //   3. LL_extra_bits
        //   4. (only if not last sequence): LL_advance, ML_advance, OF_advance.
        //
        // The reverse-bitstream writer is "first-written = last-read". So if
        // we walk sequences i = n-1 → 0:
        //   For i = n-1 (DECODER's last sequence): write extras only, in
        //     reverse read order: write LL_extra first, then ML_extra, then
        //     OF_extra.
        //   For i < n-1: write the FSE advance bits for THIS sequence's
        //     transition (out_OF, then out_ML, then out_LL — reverse of the
        //     decoder's LL, ML, OF advance read order), THEN write the
        //     extras (LL, ML, OF reversed).
        //
        // FSE advance bits are emitted by `encode_symbol(state, sym)`.
        // The bits returned correspond to the decoder's read at that
        // advance step.
        //
        // To produce the correct interleaving, we structure the loop:
        //   for i in (0..n_seq).rev() {
        //       if i == n_seq - 1 {
        //           // No advance for the last decoder-side sequence.
        //       } else {
        //           // Advance: encode the transition FROM sequence i+1's
        //           // state INTO sequence i's state for each of OF, ML, LL.
        //           // Decoder reads advance order LL, ML, OF — so we write
        //           // OF first (most recently read), then ML, then LL.
        //           of_state = self.of_enc.encode_symbol(of_state, of_codes[i] as usize, &mut writer);
        //           ml_state = self.ml_enc.encode_symbol(ml_state, ml_codes[i] as usize, &mut writer);
        //           ll_state = self.ll_enc.encode_symbol(ll_state, ll_codes[i] as usize, &mut writer);
        //       }
        //       // Extras: decoder reads OF, ML, LL — write LL, ML, OF.
        //       writer.write_bits(ll_extras[i].1 as u64, ll_extras[i].0);
        //       writer.write_bits(ml_extras[i].1 as u64, ml_extras[i].0);
        //       writer.write_bits(of_extras[i].1 as u64, of_extras[i].0);
        //   }
        //
        // Hmm wait — encode_symbol(state, sym) consumes the CURRENT state
        // (which corresponds to the decoder's PRE-advance state) and
        // produces NEW state (decoder's POST-advance state). The bits
        // written are the bits the decoder reads to perform the advance.
        //
        // The decoder advances at the END of sequence i (using sequence i's
        // current state to compute next_state for sequence i+1). So the
        // bits FOR THIS ADVANCE are read at the END of sequence i's
        // processing. From sequence i+1's POV, the state was set up by
        // this advance.
        //
        // We're processing sequences in reverse (i from n-1 to 0). When
        // i = n-2, we're handling the SECOND-TO-LAST sequence (decoder-
        // side). The advance bits at this point are the ones the decoder
        // reads at the END of i=n-2 to set up i=n-1's state. So we encode
        // the transition FROM sequence n-2's state INTO n-1's state.
        //
        // In our reverse loop, "current state" represents sequence n-1's
        // initial state (set up via init_state). After encode_symbol with
        // ll_codes[n-2], the state will represent sequence n-2's initial
        // state. The BITS written reflect the (current → new) transition
        // i.e. n-2 → n-1 advance (since current = n-1 before).
        //
        // So `encode_symbol(state_for_seq_iplus1, codes[i])` writes the
        // bits the decoder reads at the end of seq i to advance from
        // seq_i.state to seq_(i+1).state. ✓
        for i in (0..n_seq).rev() {
            if i == n_seq - 1 {
                // No advance bits for the decoder's last sequence.
            } else {
                // Advance bits for the transition seq i → seq i+1.
                // Decoder reads in order LL, ML, OF; we write in reverse:
                // OF first, then ML, then LL.
                of_state = self
                    .of_enc
                    .encode_symbol(of_state, of_codes[i] as usize, &mut writer);
                ml_state = self
                    .ml_enc
                    .encode_symbol(ml_state, ml_codes[i] as usize, &mut writer);
                ll_state = self
                    .ll_enc
                    .encode_symbol(ll_state, ll_codes[i] as usize, &mut writer);
            }
            // Extras: decoder reads OF, ML, LL — write LL, ML, OF.
            writer.write_bits(ll_extras[i].1 as u64, ll_extras[i].0);
            writer.write_bits(ml_extras[i].1 as u64, ml_extras[i].0);
            writer.write_bits(of_extras[i].1 as u64, of_extras[i].0);
        }

        // Write final FSE states (decoder reads these via init in order
        // LL, OF, ML — we write reverse: ML, OF, LL).
        self.ml_enc.write_final_state(ml_state, &mut writer);
        self.of_enc.write_final_state(of_state, &mut writer);
        self.ll_enc.write_final_state(ll_state, &mut writer);

        let bitstream = writer.finish();
        out.extend_from_slice(&bitstream);
        out
    }

    /// Flush `pending` as a single block (compressed if profitable, raw
    /// otherwise). Sets `last` on the block header.
    fn flush_block(&mut self, last: bool) {
        if let Some(body) = self.try_compress_block() {
            Self::push_block_header(&mut self.out_buf, body.len() as u32, 2, last);
            self.out_buf.extend_from_slice(&body);
        } else {
            // Fall back to Raw_Block.
            let pending_snapshot = core::mem::take(&mut self.pending);
            Self::append_raw_block(&mut self.out_buf, &pending_snapshot, last);
            self.pending = pending_snapshot;
        }
        self.pending.clear();
    }

    /// Copy as much of `out_buf[out_idx..]` into `output[*written..]` as fits.
    fn drain_into(&mut self, output: &mut [u8], written: &mut usize) -> bool {
        let avail = output.len() - *written;
        let remaining = self.out_buf.len() - self.out_idx;
        let n = core::cmp::min(avail, remaining);
        if n > 0 {
            output[*written..*written + n]
                .copy_from_slice(&self.out_buf[self.out_idx..self.out_idx + n]);
            *written += n;
            self.out_idx += n;
        }
        let drained = self.out_idx == self.out_buf.len();
        if drained {
            self.out_buf.clear();
            self.out_idx = 0;
        }
        drained
    }
}

/// One LZ77 sequence in the compressor's internal form (uses real distance,
/// not the encoded offset_value).
#[derive(Clone, Copy, Debug)]
struct Seq {
    literal_length: u32,
    match_length: u32,
    distance: u32,
}

/// Build a Raw_Literals_Block section: literal-section header + raw bytes.
fn build_raw_literals_section(literals: &[u8], trailing: &[u8]) -> Vec<u8> {
    let regen = literals.len() + trailing.len();
    let mut out = Vec::with_capacity(3 + regen);
    // Choose size_format to fit `regen`. Raw_Literals_Block = type 0.
    if regen < 32 {
        // 1-byte header: SF=00, type=00.
        // SF=00, type=00 → just the size in the upper 5 bits.
        let hdr = (regen as u8) << 3;
        out.push(hdr);
    } else if regen < 4096 {
        // 2-byte header: SF=01, 12-bit regen.
        // Layout: byte 0 = (regen[3:0] << 4) | (sf << 2) | type
        //         byte 1 = regen[11:4]
        let byte0 = (((regen & 0xF) as u8) << 4) | (0b01 << 2);
        let byte1 = (regen >> 4) as u8;
        out.push(byte0);
        out.push(byte1);
    } else {
        // 3-byte header: SF=11 (still raw), 20-bit regen.
        // Layout: byte 0 = (regen[3:0] << 4) | (sf << 2) | type
        //         byte 1 = regen[11:4]
        //         byte 2 = regen[19:12]
        let byte0 = (((regen & 0xF) as u8) << 4) | (0b11 << 2);
        let byte1 = ((regen >> 4) & 0xFF) as u8;
        let byte2 = ((regen >> 12) & 0xFF) as u8;
        out.push(byte0);
        out.push(byte1);
        out.push(byte2);
    }
    out.extend_from_slice(literals);
    out.extend_from_slice(trailing);
    out
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.state {
                State::Accepting => {
                    // Lazily emit the frame header.
                    if !self.header_written {
                        self.write_frame_header();
                        self.header_written = true;
                    }
                    // Accept input up to BLOCK_SIZE.
                    let space = BLOCK_SIZE - self.pending.len();
                    let take = core::cmp::min(space, input.len() - consumed);
                    if take > 0 {
                        self.pending
                            .extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                    }
                    if self.pending.len() == BLOCK_SIZE {
                        // Flush a non-final block.
                        self.flush_block(false);
                        self.state = State::Draining { last: false };
                    } else if !self.out_buf.is_empty() {
                        // We have header bytes pending; drain them.
                        self.state = State::Draining { last: false };
                    } else {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                State::Draining { last } => {
                    let drained = self.drain_into(output, &mut written);
                    if !drained {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if last {
                        self.state = State::Done;
                    } else {
                        self.state = State::Accepting;
                    }
                }
                State::Done => {
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        loop {
            match self.state {
                State::Accepting => {
                    if !self.header_written {
                        self.write_frame_header();
                        self.header_written = true;
                    }
                    // Emit the final block (carries Last_Block = 1).
                    if self.pending.is_empty() {
                        // Empty last block (Raw_Block, size 0).
                        Self::push_block_header(&mut self.out_buf, 0, 0, true);
                    } else {
                        self.flush_block(true);
                    }
                    self.state = State::Draining { last: true };
                }
                State::Draining { last } => {
                    let drained = self.drain_into(output, &mut written);
                    if !drained {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    if last {
                        self.state = State::Done;
                    } else {
                        self.state = State::Accepting;
                    }
                }
                State::Done => {
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn reset(&mut self) {
        self.state = State::Accepting;
        self.pending.clear();
        self.out_buf.clear();
        self.out_idx = 0;
        self.matcher = MatchFinder::new(BLOCK_SIZE);
        self.header_written = false;
    }
}
