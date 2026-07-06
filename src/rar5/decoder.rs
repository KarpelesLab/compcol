//! Streaming RAR5 LZ77+Huffman decoder.
//!
//! ## Wire format
//!
//! Compressed input is a series of *blocks*. Every block starts with a
//! two-byte header:
//!
//! ```text
//! byte 0: block_flags
//!   bits 0..2  : codec_byte — valid bit count of the *final* compressed
//!                byte, minus 1. (i.e. the bitstream ends after
//!                `codec_byte + 1` bits of the last data byte.)
//!   bits 3..5  : byte_count — the block_size field below is
//!                `byte_count + 1` bytes long (1, 2 or 3 bytes).
//!   bit  6     : last_block — set on the final block of the stream.
//!   bit  7     : table_present — set when the block carries a fresh set
//!                of Huffman tables (otherwise the previous block's tables
//!                are reused).
//! byte 1: block_cksum — 0x5A ^ block_flags ^ size_b0 ^ size_b1 ^ size_b2
//! bytes 2..2+(byte_count+1): block_size (little-endian), number of
//!   compressed-data bytes that follow.
//! bytes 2+(byte_count+1) ..: the compressed bitstream proper.
//! ```
//!
//! The bitstream uses big-endian bit order (most-significant bit of each
//! byte first). When `table_present` is set, the very first bits of the
//! block carry a *pre-code* — 20 lengths in 4-bit nibbles (with an escape
//! sequence for runs of zeros) — followed by the canonical lengths of the
//! five main Huffman tables (sizes 306, 64, 16, 44) packed via the
//! pre-code's RLE.
//!
//! ## Calling convention
//!
//! Construct with [`Decoder::with_unpack_size`], specifying the expected
//! uncompressed byte count. Feed compressed input through [`decode`]; the
//! decoder buffers internally and emits the uncompressed bytes through
//! `output`. When the unpack-size has been emitted the decoder transitions
//! to a Done state.
//!
//! Window size is supplied via [`Decoder::with_window_size`] — the RAR5
//! container header carries it; for stand-alone fuzz / integration use a
//! 1 MiB default is reasonable.
//!
//! ## Limitations
//!
//! The decoder does **not** parse the RAR5 archive container. Callers that
//! need to extract files from a `.rar` are expected to peel off the
//! container framing themselves (header blocks, file headers, multi-volume
//! continuations, etc.) and hand the inner compressed-data run to this
//! decoder.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

use super::bits::BitBuf;
use super::filters::{Filter, FilterKind};
use super::huffman::Huffman;

// Huffman alphabet sizes per the RAR5 algorithm.
pub(crate) const HUFF_BC: usize = 20;
pub(crate) const HUFF_NC: usize = 306;
pub(crate) const HUFF_DC: usize = 64;
pub(crate) const HUFF_LDC: usize = 16;
pub(crate) const HUFF_RC: usize = 44;
pub(crate) const HUFF_TABLE_SIZE: usize = HUFF_NC + HUFF_DC + HUFF_LDC + HUFF_RC;

const MIN_WINDOW_SIZE: usize = 0x20000; // 128 KiB
const MAX_WINDOW_SIZE: usize = 0x4000_0000; // 1 GiB
const DEFAULT_WINDOW_SIZE: usize = 0x10_0000; // 1 MiB

/// Streaming RAR5 LZ77+Huffman decoder. See module docs for framing.
pub struct Decoder {
    state: State,
    poisoned: bool,
    /// Reusable input buffer. We append every byte of `input` here and
    /// process blocks lazily.
    input: VecDeque<u8>,
    unpack_total: u64,
    unpack_so_far: u64,
    window_size: usize,
    /// Cached `window_size - 1`. `window_size` is always a power of two
    /// so wrap-around is a single AND.
    window_mask: usize,
    /// LZ77 sliding window. Indexed via `window_mask`.
    window: Vec<u8>,
    window_pos: usize,
    /// 4-deep distance LRU. Entry 0 is the most recent.
    dist_cache: [u32; 4],
    /// Last decoded match length, for the "repeat last match" main code.
    last_len: u32,
    /// Cached tables across blocks (RAR5 lets a block opt out of carrying
    /// new tables).
    tables: Option<Box<Tables>>,
    /// Output bytes that have been emitted to the window but not yet handed
    /// back to the caller.
    out_queue: VecDeque<u8>,
    /// Pending filters waiting on their target byte range to be produced.
    pending_filters: Vec<Filter>,
    /// Output we've finalised (filters applied if applicable) and that is
    /// ready to flow to the caller. Always emitted from the front.
    ready: VecDeque<u8>,
    /// Absolute offset (in the unpacked stream) of the first byte still in
    /// `out_queue`. Used to identify which pending filters fire when.
    out_queue_start: u64,
}

#[derive(Debug)]
struct Tables {
    nc: Huffman,  // main code, 306 symbols
    dc: Huffman,  // distance code, 64 symbols
    ldc: Huffman, // low-distance code, 16 symbols
    rc: Huffman,  // repeat-distance / length code, 44 symbols
}

enum State {
    /// Awaiting the next block header.
    BlockHeader,
    /// Inside a block. The block has been fully buffered into `bits`.
    InBlock { bits: Box<BitBuf>, last_block: bool },
    /// Stream finished — we've emitted `unpack_total` bytes.
    Done,
}

impl Decoder {
    /// Construct a decoder with a default 1 MiB window and no declared
    /// unpack size. The decoder will continue producing output until it
    /// sees a block with the `last_block` flag set.
    pub fn new() -> Self {
        Self::with_unpack_size_and_window(u64::MAX, DEFAULT_WINDOW_SIZE)
    }

    /// Construct a decoder declaring the total uncompressed byte count.
    /// The decoder stops once it has emitted exactly `n` bytes, even if
    /// more compressed input is available.
    pub fn with_unpack_size(n: u64) -> Self {
        Self::with_unpack_size_and_window(n, DEFAULT_WINDOW_SIZE)
    }

    /// Construct a decoder with an explicit window size (must be a power
    /// of two in `MIN_WINDOW_SIZE..=MAX_WINDOW_SIZE`).
    pub fn with_window_size(window_size: usize) -> Self {
        Self::with_unpack_size_and_window(u64::MAX, window_size)
    }

    /// Combined constructor with both an unpack size and an explicit
    /// window size.
    pub fn with_unpack_size_and_window(unpack: u64, window_size: usize) -> Self {
        let ws = window_size
            .clamp(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE)
            .next_power_of_two();
        debug_assert!(ws.is_power_of_two());
        Self {
            state: State::BlockHeader,
            poisoned: false,
            input: VecDeque::new(),
            unpack_total: unpack,
            unpack_so_far: 0,
            window_size: ws,
            window_mask: ws - 1,
            window: vec![0u8; ws],
            window_pos: 0,
            dist_cache: [0; 4],
            last_len: 0,
            tables: None,
            out_queue: VecDeque::new(),
            pending_filters: Vec::new(),
            ready: VecDeque::new(),
            out_queue_start: 0,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
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
        // We accept all of `input` and buffer it. (RAR5 block sizes are
        // self-described in the header so we need random access to bytes
        // within a single block.)
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            // Drain whatever's ready into the caller's output.
            while written < output.len()
                && let Some(b) = self.ready.pop_front()
            {
                output[written] = b;
                written += 1;
            }
            if self.unpack_so_far == self.unpack_total
                && self.ready.is_empty()
                && self.out_queue.is_empty()
            {
                self.state = State::Done;
            }
            if matches!(self.state, State::Done) {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }
            if written == output.len() && !self.ready.is_empty() {
                return Ok(RawProgress {
                    consumed,
                    written,
                    done: false,
                });
            }

            // Accept more bytes from the caller.
            while consumed < input.len() {
                self.input.push_back(input[consumed]);
                consumed += 1;
            }

            // Try to make progress.
            let progressed = match self.step() {
                Ok(p) => p,
                Err(e) => return Err(self.poison(e)),
            };
            if !progressed {
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
        let mut written = 0usize;
        while written < output.len()
            && let Some(b) = self.ready.pop_front()
        {
            output[written] = b;
            written += 1;
        }
        if self.unpack_so_far == self.unpack_total
            && self.ready.is_empty()
            && self.out_queue.is_empty()
        {
            self.state = State::Done;
        }
        match &self.state {
            State::Done => Ok(RawProgress {
                consumed: 0,
                written,
                done: true,
            }),
            State::BlockHeader if self.input.is_empty() && self.unpack_total == 0 => {
                self.state = State::Done;
                Ok(RawProgress {
                    consumed: 0,
                    written,
                    done: true,
                })
            }
            _ => {
                if written == 0 {
                    Err(self.poison(Error::UnexpectedEnd))
                } else {
                    Ok(RawProgress {
                        consumed: 0,
                        written,
                        done: false,
                    })
                }
            }
        }
    }

    fn raw_reset(&mut self) {
        self.state = State::BlockHeader;
        self.poisoned = false;
        self.input.clear();
        self.unpack_so_far = 0;
        for b in &mut self.window {
            *b = 0;
        }
        self.window_pos = 0;
        self.dist_cache = [0; 4];
        self.last_len = 0;
        self.tables = None;
        self.out_queue.clear();
        self.pending_filters.clear();
        self.ready.clear();
        self.out_queue_start = 0;
    }
}

impl Decoder {
    /// Single attempt to advance the state machine. Returns true if we made
    /// progress (consumed input, produced output, or transitioned state).
    fn step(&mut self) -> Result<bool, Error> {
        match &mut self.state {
            State::Done => Ok(false),
            State::BlockHeader => {
                if self.input.len() < 2 {
                    return Ok(false);
                }
                // We need block_flags + cksum + size field. Peek the flags
                // to learn byte_count and refuse to consume anything until
                // the whole header has arrived.
                let flags = self.input[0];
                let byte_count = ((flags >> 3) & 7) as usize;
                if byte_count > 2 {
                    return Err(Error::Corrupt);
                }
                let header_len = 2 + byte_count + 1;
                if self.input.len() < header_len {
                    return Ok(false);
                }
                let bit_size = (flags & 7) + 1; // valid bits in last byte
                let last_block = (flags & 0x40) != 0;
                let table_present = (flags & 0x80) != 0;
                let cksum_byte = self.input[1];
                let mut size_bytes = [0u8; 3];
                for (i, sb) in size_bytes.iter_mut().enumerate().take(byte_count + 1) {
                    *sb = self.input[2 + i];
                }
                let computed_cksum = 0x5A ^ flags ^ size_bytes[0] ^ size_bytes[1] ^ size_bytes[2];
                if computed_cksum != cksum_byte {
                    return Err(Error::BadHeader);
                }
                let block_size =
                    u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], 0]) as usize;
                if block_size == 0 {
                    return Err(Error::Corrupt);
                }
                if self.input.len() < header_len + block_size {
                    return Ok(false);
                }
                // We have a whole block. Consume the header bytes…
                for _ in 0..header_len {
                    self.input.pop_front();
                }
                // …and copy the block body into a BitBuf.
                let mut block_bytes = Vec::with_capacity(block_size);
                for _ in 0..block_size {
                    if let Some(b) = self.input.pop_front() {
                        block_bytes.push(b);
                    }
                }
                let mut bits = Box::new(BitBuf::new());
                bits.reset(&block_bytes, bit_size);
                if table_present {
                    let tables = self.read_tables(&mut bits)?;
                    self.tables = Some(Box::new(tables));
                }
                if self.tables.is_none() {
                    // First block must carry tables.
                    return Err(Error::Corrupt);
                }
                self.state = State::InBlock { bits, last_block };
                Ok(true)
            }
            State::InBlock { bits, last_block } => {
                let last_block = *last_block;
                let mut bits_owned = core::mem::replace(bits, Box::new(BitBuf::new()));
                let res = self.decode_in_block(&mut bits_owned);
                // Restore the bits buffer for any subsequent re-entry,
                // unless we transitioned away.
                if let State::InBlock { bits: slot, .. } = &mut self.state {
                    *slot = bits_owned;
                }
                let made_progress = res?;
                // End-of-block: pull current BitBuf back out, advance state.
                let at_end = match &self.state {
                    State::InBlock { bits, .. } => bits.at_end(),
                    _ => true,
                };
                if at_end {
                    if last_block {
                        // Mark the stream as terminated; any extra input is
                        // surplus.
                        self.state = State::BlockHeader;
                        if self.unpack_total == u64::MAX {
                            self.unpack_total = self.unpack_so_far + self.out_queue.len() as u64;
                        }
                    } else {
                        self.state = State::BlockHeader;
                    }
                    // Flush the output queue / apply filters that became
                    // ready as a result of finishing the block.
                    self.flush_ready_through_filters()?;
                    return Ok(true);
                }
                Ok(made_progress)
            }
        }
    }

    /// Decode commands from the current block until either the block ends
    /// or the unpack-size cap is reached. Returns true if any forward
    /// progress was made.
    fn decode_in_block(&mut self, bits: &mut BitBuf) -> Result<bool, Error> {
        let mut progressed = false;
        loop {
            if bits.at_end() {
                return Ok(progressed);
            }
            if self.unpack_so_far + self.out_queue.len() as u64 >= self.unpack_total {
                return Ok(progressed);
            }
            // Cap the in-flight out_queue to avoid unbounded growth. We
            // flush it through filters at every iteration so this only
            // matters when filters are pending.
            if self.out_queue.len() > 1 << 20 {
                self.flush_ready_through_filters()?;
            }
            let t = self.tables.as_ref().ok_or(Error::Corrupt)?;
            let num = t.nc.decode(bits)?;
            progressed = true;
            match num {
                0..=255 => {
                    self.emit_literal(num as u8);
                }
                256 => {
                    // Filter descriptor.
                    let filter = read_filter(bits, self.window_size, self.cur_out_pos())?;
                    self.pending_filters.push(filter);
                }
                257 => {
                    // Repeat the *previous* match — last_len from dist_cache[0].
                    if self.last_len == 0 {
                        return Err(Error::Corrupt);
                    }
                    let dist = self.dist_cache[0];
                    self.emit_match(self.last_len, dist)?;
                }
                258..=261 => {
                    let idx = (num - 258) as usize;
                    let dist = self.dist_cache[idx];
                    // Touch: move dist to front.
                    for j in (1..=idx).rev() {
                        self.dist_cache[j] = self.dist_cache[j - 1];
                    }
                    self.dist_cache[0] = dist;
                    let len_sym = t.rc.decode(bits)?;
                    let length = decode_length(bits, len_sym)?;
                    self.emit_match(length, dist)?;
                }
                262..=305 => {
                    let len_sym = (num - 262) as u32;
                    let length = decode_length(bits, len_sym as u16)?;
                    // New distance.
                    let dist_slot = t.dc.decode(bits)?;
                    let dist = decode_distance(bits, dist_slot, &t.ldc)?;
                    // Length is adjusted by distance per RAR5 spec.
                    let adj_len = adjust_length(length, dist);
                    self.dist_cache[3] = self.dist_cache[2];
                    self.dist_cache[2] = self.dist_cache[1];
                    self.dist_cache[1] = self.dist_cache[0];
                    self.dist_cache[0] = dist;
                    self.emit_match(adj_len, dist)?;
                }
                _ => return Err(Error::Corrupt),
            }
            // Periodically push the head of out_queue through filters.
            if self.out_queue.len() >= 4096 {
                self.flush_ready_through_filters()?;
            }
        }
    }

    fn emit_literal(&mut self, b: u8) {
        self.window[self.window_pos] = b;
        self.window_pos = (self.window_pos + 1) & self.window_mask;
        self.out_queue.push_back(b);
    }

    fn emit_match(&mut self, length: u32, dist: u32) -> Result<(), Error> {
        if dist == 0 || dist as usize > self.window_size {
            return Err(Error::InvalidDistance);
        }
        if length < 2 {
            return Err(Error::Corrupt);
        }
        let ws = self.window_size;
        let wmask = self.window_mask;
        let off = dist as usize;
        // Clamp the run to the declared unpack total (the old loop broke per
        // byte once it was reached — produce exactly the same byte count).
        let produced = self.unpack_so_far + self.out_queue.len() as u64;
        let remaining = self.unpack_total.saturating_sub(produced);
        let length_n = (length as u64).min(remaining) as usize;
        let mut src = (self.window_pos + ws - off) & wmask;

        if off == 1 {
            // Distance-1 run: one repeated byte.
            let b = self.window[src];
            for _ in 0..length_n {
                self.window[self.window_pos] = b;
                self.window_pos = (self.window_pos + 1) & wmask;
                self.out_queue.push_back(b);
            }
        } else if off >= length_n {
            // Non-overlapping: copy in contiguous window segments.
            let mut done = 0usize;
            while done < length_n {
                let run = (length_n - done).min(ws - src).min(ws - self.window_pos);
                let sp = self.window_pos;
                // off >= length_n >= run and the run is capped to avoid a ring
                // wrap, so source and destination never overlap: bulk-copy the
                // disjoint window segment, matching the per-byte writes exactly.
                self.out_queue
                    .extend(self.window[src..src + run].iter().copied());
                self.window.copy_within(src..src + run, sp);
                src = (src + run) & wmask;
                self.window_pos = (self.window_pos + run) & wmask;
                done += run;
            }
        } else {
            // Overlapping match: each written byte feeds a later read.
            for _ in 0..length_n {
                let b = self.window[src];
                self.window[self.window_pos] = b;
                src = (src + 1) & wmask;
                self.window_pos = (self.window_pos + 1) & wmask;
                self.out_queue.push_back(b);
            }
        }
        self.last_len = length;
        Ok(())
    }

    /// Current absolute offset of the next byte we *would* emit if we
    /// added one to `out_queue`.
    fn cur_out_pos(&self) -> u64 {
        self.out_queue_start + self.out_queue.len() as u64
    }

    /// Pull bytes out of `out_queue` into `ready`, applying any filters
    /// whose target range is fully produced. Filters that aren't yet fully
    /// covered stay in `pending_filters`.
    fn flush_ready_through_filters(&mut self) -> Result<(), Error> {
        // First, push bytes out of out_queue into ready until we hit a
        // pending filter's start (in absolute coordinates) — those bytes
        // can flow without modification.
        let mut pos = self.out_queue_start;
        // Pending filters sorted by start so we serve them in order.
        self.pending_filters.sort_by_key(|f| f.start);

        loop {
            // Find the first pending filter whose start lies at or before
            // the head of out_queue.
            let next_filter_start = self.pending_filters.first().map(|f| f.start);

            match next_filter_start {
                None => {
                    // No filters — drain everything in out_queue to ready.
                    let drained = self.out_queue.len() as u64;
                    while let Some(b) = self.out_queue.pop_front() {
                        self.ready.push_back(b);
                    }
                    self.out_queue_start += drained;
                    self.unpack_so_far += drained;
                    return Ok(());
                }
                Some(s) if s > pos => {
                    // Drain up to `s` from out_queue into ready.
                    let n = (s - pos) as usize;
                    let avail = self.out_queue.len();
                    let take = n.min(avail);
                    for _ in 0..take {
                        if let Some(b) = self.out_queue.pop_front() {
                            self.ready.push_back(b);
                        }
                    }
                    pos += take as u64;
                    self.out_queue_start = pos;
                    self.unpack_so_far += take as u64;
                    if (take as u64) < n as u64 {
                        // out_queue is empty before reaching the filter.
                        return Ok(());
                    }
                }
                Some(_) => {
                    // Filter starts at or before `pos`. Check if its full
                    // range is covered by what's in out_queue.
                    let f = self.pending_filters[0];
                    let end = f.start + f.length as u64;
                    let buf_end = pos + self.out_queue.len() as u64;
                    if end > buf_end {
                        // Not enough bytes yet — wait.
                        return Ok(());
                    }
                    // We have the whole filter range. Extract it into a
                    // contiguous Vec, apply the filter, then push back to
                    // ready.
                    if f.start < pos {
                        // The filter wants to reach into bytes we've
                        // already emitted. Unsupported in our streaming
                        // model — refuse.
                        // (This shouldn't happen with normal RAR5 streams.)
                        return Ok(());
                    }
                    let leading = (f.start - pos) as usize;
                    for _ in 0..leading {
                        if let Some(b) = self.out_queue.pop_front() {
                            self.ready.push_back(b);
                        }
                    }
                    pos += leading as u64;
                    self.unpack_so_far += leading as u64;
                    self.out_queue_start = pos;

                    // Collect the filter region.
                    let length = f.length as usize;
                    let mut region = Vec::with_capacity(length);
                    for _ in 0..length {
                        if let Some(b) = self.out_queue.pop_front() {
                            region.push(b);
                        }
                    }
                    // Propagate filter failures instead of silently emitting
                    // the raw, unfiltered bytes. An unsupported or corrupt
                    // filter would otherwise yield wrong output with no error.
                    super::filters::apply(&f, &mut region)?;
                    for &b in &region {
                        self.ready.push_back(b);
                    }
                    pos += length as u64;
                    self.unpack_so_far += length as u64;
                    self.out_queue_start = pos;
                    self.pending_filters.remove(0);
                }
            }
        }
    }

    /// Read the five Huffman tables (BC pre-code + NC + DC + LDC + RC) at
    /// the start of a `table_present` block.
    fn read_tables(&mut self, bits: &mut BitBuf) -> Result<Tables, Error> {
        // Phase A: 20 nibbles for the bit-length pre-code, with an escape.
        let mut bc_lens = [0u8; HUFF_BC];
        let mut i = 0;
        while i < HUFF_BC {
            let n = bits.read(4)? as u8;
            if n < 15 {
                bc_lens[i] = n;
                i += 1;
            } else {
                // Escape: read another nibble.
                let m = bits.read(4)? as u8;
                if m == 0 {
                    bc_lens[i] = 15;
                    i += 1;
                } else {
                    let run = (m as usize) + 2;
                    let end = (i + run).min(HUFF_BC);
                    while i < end {
                        bc_lens[i] = 0;
                        i += 1;
                    }
                }
            }
        }
        let bc = Huffman::from_lengths(&bc_lens)?;
        if bc.is_empty() {
            return Err(Error::InvalidHuffmanTree);
        }

        // Phase B: decode HUFF_TABLE_SIZE entries using `bc`, with the RLE
        // codes 16..=19.
        let mut table = vec![0u8; HUFF_TABLE_SIZE];
        let mut idx = 0;
        while idx < HUFF_TABLE_SIZE {
            let sym = bc.decode(bits)?;
            match sym {
                0..=15 => {
                    table[idx] = sym as u8;
                    idx += 1;
                }
                16 => {
                    // Repeat previous code (idx-1) for (read 3 bits) + 3 times.
                    if idx == 0 {
                        return Err(Error::Corrupt);
                    }
                    let n = bits.read(3)? as usize + 3;
                    let prev = table[idx - 1];
                    let end = (idx + n).min(HUFF_TABLE_SIZE);
                    while idx < end {
                        table[idx] = prev;
                        idx += 1;
                    }
                }
                17 => {
                    if idx == 0 {
                        return Err(Error::Corrupt);
                    }
                    let n = bits.read(7)? as usize + 11;
                    let prev = table[idx - 1];
                    let end = (idx + n).min(HUFF_TABLE_SIZE);
                    while idx < end {
                        table[idx] = prev;
                        idx += 1;
                    }
                }
                18 => {
                    let n = bits.read(3)? as usize + 3;
                    let end = (idx + n).min(HUFF_TABLE_SIZE);
                    while idx < end {
                        table[idx] = 0;
                        idx += 1;
                    }
                }
                _ => {
                    // 19 or higher: run of zeros (variable size).
                    let n = bits.read(7)? as usize + 11;
                    let end = (idx + n).min(HUFF_TABLE_SIZE);
                    while idx < end {
                        table[idx] = 0;
                        idx += 1;
                    }
                }
            }
        }

        let nc = Huffman::from_lengths(&table[0..HUFF_NC])?;
        let dc = Huffman::from_lengths(&table[HUFF_NC..HUFF_NC + HUFF_DC])?;
        let ldc = Huffman::from_lengths(&table[HUFF_NC + HUFF_DC..HUFF_NC + HUFF_DC + HUFF_LDC])?;
        let rc = Huffman::from_lengths(&table[HUFF_NC + HUFF_DC + HUFF_LDC..HUFF_TABLE_SIZE])?;
        if nc.is_empty() {
            return Err(Error::InvalidHuffmanTree);
        }
        Ok(Tables { nc, dc, ldc, rc })
    }
}

/// Decode an RAR5 length value from the bitstream given a length symbol
/// `code` (the value read out of either the main code minus 262, or the
/// length-code table RC). Returns the *unadjusted* length.
fn decode_length(bits: &mut BitBuf, code: u16) -> Result<u32, Error> {
    let mut length: u32 = 2;
    let lbits: u32;
    if code < 8 {
        lbits = 0;
        length += code as u32;
    } else {
        lbits = (code as u32 / 4) - 1;
        length += (4 | (code as u32 & 3)) << lbits;
    }
    if lbits > 0 {
        length += bits.read(lbits)?;
    }
    Ok(length)
}

/// Distance adjustment: per RAR5, larger distances imply a "small length
/// bonus" because they're statistically used for longer copies.
fn adjust_length(length: u32, dist: u32) -> u32 {
    let mut len = length;
    if dist > 0x100 {
        len += 1;
    }
    if dist > 0x2000 {
        len += 1;
    }
    if dist > 0x40000 {
        len += 1;
    }
    len
}

/// Decode a distance given the distance slot. For slots with extra bits
/// >= 4, the lower 4 bits come from the low-distance Huffman table `ldc`.
fn decode_distance(bits: &mut BitBuf, dist_slot: u16, ldc: &Huffman) -> Result<u32, Error> {
    // `dist_slot` is decoded from the DC Huffman table, which has exactly
    // HUFF_DC (64) symbols, so it is in 0..=63. Guard against an
    // out-of-contract value: with slots > 63, `dbits` would exceed 30 and
    // the shifts below could overflow. This keeps the function within the
    // RAR5 distance-slot range.
    if dist_slot as usize >= HUFF_DC {
        return Err(Error::Corrupt);
    }
    // Accumulate in u64. For slot 63 the base is 0xC0000001 and the
    // attacker-supplied high/low bits can push the running total past
    // u32::MAX (e.g. 0xC0000001 + 0x3FFFFFF0 + 0xF == 0x1_0000_0000),
    // which would overflow a u32 — a debug-build panic and a release-build
    // wrap. Working in u64 keeps every intermediate exact; we bound-check
    // before narrowing back to the u32 that `emit_match` consumes.
    let mut dist: u64;
    let dbits: u32;
    if dist_slot < 4 {
        dbits = 0;
        dist = 1 + dist_slot as u64;
    } else {
        dbits = (dist_slot as u32 / 2) - 1;
        dist = 1 + ((2 | (dist_slot as u64 & 1)) << dbits);
    }
    if dbits > 0 {
        if dbits >= 4 {
            // `high_extra = dbits - 4` can be as large as 26 for slot 63,
            // which exceeds BitBuf::read's documented 1..=16-bit limit (it
            // debug-asserts n <= 16). Read it in <=16-bit chunks so debug
            // builds don't panic and the value is assembled MSB-first
            // exactly as a single wide read would have produced it.
            let high_extra = dbits - 4;
            if high_extra > 0 {
                let mut high: u32 = 0;
                let mut remaining = high_extra;
                while remaining > 0 {
                    let chunk = remaining.min(16);
                    let part = bits.read(chunk)?;
                    high = (high << chunk) | part;
                    remaining -= chunk;
                }
                dist += (high as u64) << 4;
            }
            let low = ldc.decode(bits)? as u64;
            dist += low;
        } else {
            let extra = bits.read(dbits)? as u64;
            dist += extra;
        }
    }
    // A distance above u32::MAX cannot be a valid back-reference (the window
    // is at most 4 GiB and `emit_match` works in u32), so reject it here
    // before the narrowing cast rather than letting it wrap. `emit_match`
    // applies the precise `> window_size` bound on the in-range value.
    if dist > u32::MAX as u64 {
        return Err(Error::InvalidDistance);
    }
    Ok(dist as u32)
}

/// Read a filter descriptor immediately after the main code emits 256.
/// `cur_pos` is the absolute offset in the unpacked stream of the next
/// byte the decoder *would* emit.
fn read_filter(bits: &mut BitBuf, window_size: usize, cur_pos: u64) -> Result<Filter, Error> {
    let block_start = read_filter_uint(bits)?;
    let block_length = read_filter_uint(bits)?;
    if !(4..=0x40_0000).contains(&block_length) {
        return Err(Error::Corrupt);
    }
    if block_length as usize > window_size / 2 {
        return Err(Error::Corrupt);
    }
    let ftype_raw = bits.read(3)?;
    let kind = match ftype_raw {
        1 => FilterKind::X86Call,
        2 => FilterKind::X86CallJmp,
        0 => {
            let channels = bits.read(5)? as u8 + 1;
            FilterKind::Delta { channels }
        }
        3 => FilterKind::Arm,
        _ => return Err(Error::Unsupported),
    };
    Ok(Filter {
        start: cur_pos + block_start as u64,
        length: block_length,
        kind,
    })
}

/// Parse an RAR5 "filter uint" — 2 bits encode the byte count `n`, then
/// `n + 1` 8-bit values combine little-endian.
fn read_filter_uint(bits: &mut BitBuf) -> Result<u32, Error> {
    let bc = bits.read(2)?;
    let mut v: u32 = 0;
    for i in 0..=bc {
        let b = bits.read(8)?;
        v |= b << (i * 8);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_decoding_small_codes() {
        // For code < 8, length = 2 + code with no extra bits.
        let mut br = BitBuf::new();
        br.reset(&[0; 4], 8);
        assert_eq!(decode_length(&mut br, 0).unwrap(), 2);
        assert_eq!(decode_length(&mut br, 7).unwrap(), 9);
    }

    #[test]
    fn length_decoding_large_codes_consume_extra_bits() {
        // For code = 8, lbits = 1, base = 2 + (4 << 1) = 10. Reading a
        // single 1-bit adds 1 to give 11.
        let mut br = BitBuf::new();
        // bit 0 = 1, rest don't matter.
        br.reset(&[0b1000_0000], 8);
        assert_eq!(decode_length(&mut br, 8).unwrap(), 11);
    }

    #[test]
    fn distance_adjustment_rules() {
        assert_eq!(adjust_length(3, 0x10), 3);
        assert_eq!(adjust_length(3, 0x101), 4);
        assert_eq!(adjust_length(3, 0x2001), 5);
        assert_eq!(adjust_length(3, 0x4_0001), 6);
    }

    /// Regression: slot 63 with maximal attacker-supplied extra/low bits used
    /// to overflow the u32 distance accumulator. base = 0xC0000001, the 26
    /// high bits add 0x3FFFFFF0 (→ 0xFFFFFFF1), and the LDC low (15) would
    /// push it to 0x1_0000_0000 — an `attempt to add with overflow` panic in
    /// the dev profile (overflow-checks on) and a silent wrap in release.
    /// The fix accumulates in u64 and rejects distances above u32::MAX with
    /// `InvalidDistance` before narrowing. This test panics if unfixed.
    #[test]
    fn slot_63_max_bits_does_not_overflow() {
        // Complete 16-symbol LDC code, every symbol length 4. Canonical
        // assignment gives symbol 15 the all-ones code 0b1111, so an
        // all-ones bitstream decodes the low nibble to 15 (the maximum).
        let ldc = Huffman::from_lengths(&[4u8; HUFF_LDC]).unwrap();
        let mut br = BitBuf::new();
        // 26 high bits + 4 LDC bits = 30 bits; supply 8 bytes of 1s so the
        // 16-bit peeks never run dry.
        br.reset(&[0xFF; 8], 8);
        // Must return an error rather than panicking or wrapping.
        assert_eq!(
            decode_distance(&mut br, 63, &ldc),
            Err(Error::InvalidDistance)
        );
    }
}
