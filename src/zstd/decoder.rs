//! Streaming Zstandard decoder.
//!
//! Supports frames whose data blocks are all `Raw_Block` (Block_Type=0) or
//! `RLE_Block` (Block_Type=1). A `Compressed_Block` (Block_Type=2) causes the
//! decoder to return [`Error::Unsupported`]; `Reserved` (Block_Type=3) is
//! [`Error::Corrupt`].
//!
//! The decoder also refuses frames whose Frame_Header sets the
//! `Content_Checksum_Flag` — we do not implement XXH64 in this crate, so we
//! cannot validate the trailing 4-byte checksum and treat the option as
//! unsupported (per task spec).

use crate::error::Error;
use crate::traits::{Decoder as DecoderTrait, Progress};

const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// Skippable_Frame magic numbers occupy 0x184D2A50..=0x184D2A5F. We do not
/// decode them; they're rejected as unsupported.
const SKIPPABLE_MAGIC_HI3: [u8; 3] = [0x4D, 0x2A, 0x18];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DecPhase {
    /// Reading 4 bytes of frame magic.
    Magic,
    /// Reading 1-byte Frame_Header_Descriptor.
    Fhd,
    /// Reading 0..=1 bytes of Window_Descriptor.
    WindowDescriptor,
    /// Reading 0/1/2/4 bytes of Dictionary_ID.
    DictionaryId,
    /// Reading 0/1/2/4/8 bytes of Frame_Content_Size.
    FrameContentSize,
    /// Reading 3-byte block header.
    BlockHeader,
    /// Streaming a Raw_Block payload through to the output.
    RawBlock,
    /// Reading the single byte of an RLE_Block.
    RleByte,
    /// Emitting the byte read in `RleByte` `rle_remaining` times.
    RleEmit,
    /// Reading 4-byte Content_Checksum trailer (only entered if we somehow
    /// allowed a checksummed frame — currently we refuse such frames in
    /// `Fhd`).
    ContentChecksum,
    /// Frame fully consumed; subsequent input is ignored (we do not handle
    /// concatenated frames).
    Done,
}

/// Streaming Zstandard decoder. See module-level docs for the supported subset.
pub struct Decoder {
    phase: DecPhase,
    poisoned: bool,

    /// Buffer used by every multi-byte fixed-length phase (Magic, FHD, WD,
    /// Dictionary_ID, Frame_Content_Size, Block_Header, RLE byte read,
    /// Content_Checksum). The exact field sizes are small (≤ 8), so one
    /// shared buffer keeps the struct compact.
    scratch: [u8; 8],
    scratch_idx: u8,
    scratch_need: u8,

    single_segment: bool,
    fcs_field_size: u8,     // 0, 1, 2, 4, or 8
    dict_id_field_size: u8, // 0, 1, 2, or 4
    has_content_checksum: bool,

    /// Window size (informational; we don't enforce it for Raw/RLE blocks
    /// since we don't need back-references).
    #[allow(dead_code)]
    window_size: u64,
    /// Frame_Content_Size, if known (Single_Segment frames always report it).
    /// Currently unused — we don't validate against actual decoded length.
    #[allow(dead_code)]
    frame_content_size: Option<u64>,

    /// `Last_Block` bit of the block currently being decoded.
    last_block: bool,
    /// Block_Size remaining for the in-flight Raw_Block.
    raw_remaining: u32,
    /// RLE_Block payload byte.
    rle_byte: u8,
    /// RLE_Block remaining repeats.
    rle_remaining: u32,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            phase: DecPhase::Magic,
            poisoned: false,
            scratch: [0u8; 8],
            scratch_idx: 0,
            scratch_need: 4,
            single_segment: false,
            fcs_field_size: 0,
            dict_id_field_size: 0,
            has_content_checksum: false,
            window_size: 0,
            frame_content_size: None,
            last_block: false,
            raw_remaining: 0,
            rle_byte: 0,
            rle_remaining: 0,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Fill `scratch[..scratch_need]` from `input`, advancing `consumed`.
    /// Returns true if the scratch buffer is now full.
    fn fill_scratch(&mut self, input: &[u8], consumed: &mut usize) -> bool {
        while self.scratch_idx < self.scratch_need && *consumed < input.len() {
            self.scratch[self.scratch_idx as usize] = input[*consumed];
            self.scratch_idx += 1;
            *consumed += 1;
        }
        self.scratch_idx == self.scratch_need
    }

    fn begin_scratch(&mut self, need: u8) {
        self.scratch_idx = 0;
        self.scratch_need = need;
    }

    fn parse_fhd(&mut self) -> Result<(), Error> {
        let fhd = self.scratch[0];

        let reserved_bit = (fhd >> 3) & 1;
        if reserved_bit != 0 {
            return Err(self.poison(Error::Corrupt));
        }

        let dict_id_flag = fhd & 0b11;
        let cchk_flag = (fhd >> 2) & 1;
        let ss_flag = (fhd >> 5) & 1;
        let fcs_flag = (fhd >> 6) & 0b11;

        self.single_segment = ss_flag != 0;
        self.has_content_checksum = cchk_flag != 0;

        // We don't implement XXH64 in this build, so checksummed frames are
        // unsupported (per task spec).
        if self.has_content_checksum {
            return Err(self.poison(Error::Unsupported));
        }

        self.dict_id_field_size = match dict_id_flag {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        };

        // FCS_Field_Size lookup (RFC 8478 §3.1.1.1.4):
        // FCS_Flag | Single_Segment_Flag=0 | Single_Segment_Flag=1
        //    0    |          0            |          1
        //    1    |          2            |          2
        //    2    |          4            |          4
        //    3    |          8            |          8
        self.fcs_field_size = match fcs_flag {
            0 => {
                if self.single_segment {
                    1
                } else {
                    0
                }
            }
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };

        // We don't support Dictionary_ID lookup (no dictionary registry); we
        // still parse and skip the field for forward-compat with framed data
        // that names a dictionary it doesn't actually need (rare in practice;
        // most real frames using a dictionary cannot be decoded without it).
        // To keep behavior honest we reject any non-zero Dictionary_ID later.
        Ok(())
    }

    fn parse_window_descriptor(&mut self) {
        let wd = self.scratch[0];
        let exponent = ((wd >> 3) & 0x1F) as u32;
        let mantissa = (wd & 0x07) as u32;
        // RFC 8478 §3.1.1.1.2: Window_Size = (1 << Exp) + (1 << Exp) / 8 * Mant
        let base = 1u64 << (exponent + 10);
        let add = (base >> 3) * mantissa as u64;
        self.window_size = base + add;
    }

    fn parse_dictionary_id(&mut self) -> Result<(), Error> {
        let mut id: u32 = 0;
        for i in 0..self.dict_id_field_size {
            id |= (self.scratch[i as usize] as u32) << (8 * i);
        }
        if id != 0 {
            // We have no dictionary registry; frames that name a specific
            // dictionary cannot be decoded.
            return Err(self.poison(Error::Unsupported));
        }
        Ok(())
    }

    fn parse_fcs(&mut self) {
        if self.fcs_field_size == 0 {
            self.frame_content_size = None;
            return;
        }
        let mut v: u64 = 0;
        for i in 0..self.fcs_field_size {
            v |= (self.scratch[i as usize] as u64) << (8 * i);
        }
        // RFC quirk: when FCS_Field_Size == 2, the field encodes
        // `frame_content_size - 256`.
        if self.fcs_field_size == 2 {
            v += 256;
        }
        self.frame_content_size = Some(v);
    }

    fn parse_block_header(&mut self) -> Result<DecPhase, Error> {
        // 3-byte little-endian.
        let bh = (self.scratch[0] as u32)
            | ((self.scratch[1] as u32) << 8)
            | ((self.scratch[2] as u32) << 16);
        let last = (bh & 1) != 0;
        let block_type = (bh >> 1) & 0b11;
        let block_size = (bh >> 3) & 0x1F_FFFF;
        self.last_block = last;

        match block_type {
            0 => {
                // Raw_Block: `block_size` literal bytes follow.
                // Spec caps Block_Size at min(Window_Size, 128 KiB).
                if block_size as u64 > 128 * 1024 {
                    return Err(self.poison(Error::Corrupt));
                }
                self.raw_remaining = block_size;
                Ok(DecPhase::RawBlock)
            }
            1 => {
                // RLE_Block: 1 payload byte, expanded to `block_size` bytes.
                if block_size == 0 {
                    // An RLE block with size 0 makes no sense — still need
                    // to consume the byte? RFC implies size > 0 for RLE.
                    // Be defensive: treat as corrupt.
                    return Err(self.poison(Error::Corrupt));
                }
                self.rle_remaining = block_size;
                Ok(DecPhase::RleByte)
            }
            2 => {
                // Compressed_Block — not implemented in this build.
                Err(self.poison(Error::Unsupported))
            }
            3 => {
                // Reserved.
                Err(self.poison(Error::Corrupt))
            }
            _ => unreachable!(),
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let initial_consumed = consumed;
            let initial_written = written;

            match self.phase {
                DecPhase::Magic => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if self.scratch[..4] != MAGIC {
                        // Skippable_Frame magic: 0x184D2A5? where the low
                        // nibble of the high byte is 0x5. We don't decode
                        // skippable frames — but the user is feeding us
                        // unexpected data either way.
                        if self.scratch[0] & 0xF0 == 0x50
                            && self.scratch[1..4] == SKIPPABLE_MAGIC_HI3
                        {
                            return Err(self.poison(Error::Unsupported));
                        }
                        return Err(self.poison(Error::BadHeader));
                    }
                    self.phase = DecPhase::Fhd;
                    self.begin_scratch(1);
                }
                DecPhase::Fhd => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.parse_fhd()?;
                    if self.single_segment {
                        // No Window_Descriptor.
                        if self.dict_id_field_size > 0 {
                            self.phase = DecPhase::DictionaryId;
                            self.begin_scratch(self.dict_id_field_size);
                        } else if self.fcs_field_size > 0 {
                            self.phase = DecPhase::FrameContentSize;
                            self.begin_scratch(self.fcs_field_size);
                        } else {
                            // FCS_Field_Size is always >= 1 when SS=1, so
                            // this branch is unreachable in well-formed
                            // input; defensively fall through to block read.
                            self.phase = DecPhase::BlockHeader;
                            self.begin_scratch(3);
                        }
                    } else {
                        self.phase = DecPhase::WindowDescriptor;
                        self.begin_scratch(1);
                    }
                }
                DecPhase::WindowDescriptor => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.parse_window_descriptor();
                    if self.dict_id_field_size > 0 {
                        self.phase = DecPhase::DictionaryId;
                        self.begin_scratch(self.dict_id_field_size);
                    } else if self.fcs_field_size > 0 {
                        self.phase = DecPhase::FrameContentSize;
                        self.begin_scratch(self.fcs_field_size);
                    } else {
                        self.phase = DecPhase::BlockHeader;
                        self.begin_scratch(3);
                    }
                }
                DecPhase::DictionaryId => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.parse_dictionary_id()?;
                    if self.fcs_field_size > 0 {
                        self.phase = DecPhase::FrameContentSize;
                        self.begin_scratch(self.fcs_field_size);
                    } else {
                        self.phase = DecPhase::BlockHeader;
                        self.begin_scratch(3);
                    }
                }
                DecPhase::FrameContentSize => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.parse_fcs();
                    self.phase = DecPhase::BlockHeader;
                    self.begin_scratch(3);
                }
                DecPhase::BlockHeader => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let next = self.parse_block_header()?;
                    self.phase = next;
                    if matches!(next, DecPhase::RleByte) {
                        self.begin_scratch(1);
                    }
                    // A zero-length Raw_Block (legal per spec) skips straight
                    // to the next block / end-of-frame.
                    if matches!(self.phase, DecPhase::RawBlock) && self.raw_remaining == 0 {
                        self.advance_after_block();
                    }
                }
                DecPhase::RawBlock => {
                    let in_avail = input.len() - consumed;
                    let out_avail = output.len() - written;
                    let n = core::cmp::min(
                        self.raw_remaining as usize,
                        core::cmp::min(in_avail, out_avail),
                    );
                    if n == 0 {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    output[written..written + n].copy_from_slice(&input[consumed..consumed + n]);
                    consumed += n;
                    written += n;
                    self.raw_remaining -= n as u32;
                    if self.raw_remaining == 0 {
                        self.advance_after_block();
                    }
                }
                DecPhase::RleByte => {
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.rle_byte = self.scratch[0];
                    self.phase = DecPhase::RleEmit;
                }
                DecPhase::RleEmit => {
                    let out_avail = output.len() - written;
                    if out_avail == 0 {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let n = core::cmp::min(self.rle_remaining as usize, out_avail);
                    for slot in &mut output[written..written + n] {
                        *slot = self.rle_byte;
                    }
                    written += n;
                    self.rle_remaining -= n as u32;
                    if self.rle_remaining == 0 {
                        self.advance_after_block();
                    }
                }
                DecPhase::ContentChecksum => {
                    // Currently unreachable — we reject checksummed frames
                    // in `parse_fhd`. Kept as a state for future XXH64 work.
                    if !self.fill_scratch(input, &mut consumed) {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    self.phase = DecPhase::Done;
                }
                DecPhase::Done => {
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == initial_consumed && written == initial_written {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let empty: [u8; 0] = [];
        let p = self.decode(&empty, output)?;
        match self.phase {
            DecPhase::Done => Ok(Progress {
                consumed: 0,
                written: p.written,
                done: true,
            }),
            // If we're still in RLE_Emit and the output filled up, we owe
            // more bytes — not done yet, no error.
            DecPhase::RleEmit => Ok(Progress {
                consumed: 0,
                written: p.written,
                done: false,
            }),
            _ => Err(self.poison(Error::UnexpectedEnd)),
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Decoder {
    /// Called after a block body has been fully consumed/emitted. Transitions
    /// either to the next block header, the optional content checksum, or
    /// `Done`.
    fn advance_after_block(&mut self) {
        if self.last_block {
            if self.has_content_checksum {
                // Currently unreachable (FHD rejects this), kept honest.
                self.phase = DecPhase::ContentChecksum;
                self.begin_scratch(4);
            } else {
                self.phase = DecPhase::Done;
            }
        } else {
            self.phase = DecPhase::BlockHeader;
            self.begin_scratch(3);
        }
    }
}
