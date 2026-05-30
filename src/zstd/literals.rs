//! Literals_Section decoder (RFC 8478 §3.1.1.3.1).
//!
//! Inputs: the body of a Compressed_Block. Outputs: the decoded literal byte
//! string plus the offset within the block at which the Sequences_Section
//! starts.
//!
//! Four literal-encoding modes are recognised:
//!
//! - `Raw_Literals_Block` (00): literals copied verbatim.
//! - `RLE_Literals_Block` (01): single byte repeated `regenerated_size` times.
//! - `Compressed_Literals_Block` (10): Huffman-coded; the block carries a
//!   fresh tree.
//! - `Treeless_Literals_Block` (11): Huffman-coded; tree reused from the
//!   previous Compressed_Literals_Block (carried across blocks via
//!   [`LiteralsState`]).
//!
//! Huffman literals may use 1-stream or 4-stream mode depending on whether
//! `Size_Format` was 00 (single 1-stream) or any other value (4-stream).

use alloc::vec::Vec;

use crate::error::Error;
use crate::zstd::bitreader::RevBitReader;
use crate::zstd::huffman::{HuffTable, decode_huffman_tree};

/// State carried across blocks: the most recently seen Huffman tree (used by
/// `Treeless_Literals_Block`).
#[derive(Default)]
pub struct LiteralsState {
    pub huff_tree: Option<HuffTable>,
}

/// Result of decoding the literals section.
pub struct LiteralsResult {
    pub literals: Vec<u8>,
    /// Bytes of the block consumed by the literals section header + payload.
    pub consumed: usize,
}

/// Decode the literals section starting at `block[0]`.
pub fn decode_literals(block: &[u8], state: &mut LiteralsState) -> Result<LiteralsResult, Error> {
    if block.is_empty() {
        return Err(Error::Corrupt);
    }
    let lhd = block[0];
    let lit_block_type = lhd & 0b11;
    let size_format = (lhd >> 2) & 0b11;

    match lit_block_type {
        0 | 1 => decode_raw_or_rle(block, lit_block_type == 1, size_format),
        2 => decode_compressed_literals(block, size_format, state, /*reuse=*/ false),
        3 => decode_compressed_literals(block, size_format, state, /*reuse=*/ true),
        _ => unreachable!(),
    }
}

fn decode_raw_or_rle(block: &[u8], is_rle: bool, sf: u8) -> Result<LiteralsResult, Error> {
    // For Raw/RLE blocks, the header carries only `Regenerated_Size`.
    let (regen_size, header_bytes) = match sf {
        0b00 | 0b10 => {
            // 1-byte header: 5-bit regen size
            let rs = (block[0] >> 3) as usize;
            (rs, 1)
        }
        0b01 => {
            // 2-byte header: 12-bit regen size
            if block.len() < 2 {
                return Err(Error::Corrupt);
            }
            let rs = ((block[0] >> 4) as usize) | ((block[1] as usize) << 4);
            (rs, 2)
        }
        0b11 => {
            // 3-byte header: 20-bit regen size
            if block.len() < 3 {
                return Err(Error::Corrupt);
            }
            let rs = ((block[0] >> 4) as usize)
                | ((block[1] as usize) << 4)
                | ((block[2] as usize) << 12);
            (rs, 3)
        }
        _ => unreachable!(),
    };

    // Cap only the capacity HINT (per-block output is bounded to 128 KiB by the
    // decoder) so a tiny malformed header can't force a multi-MiB reservation
    // before the backing data is known to exist. The logical size is unchanged:
    // the RLE resize / raw copy below still produce exactly `regen_size` bytes.
    let mut literals = Vec::with_capacity(regen_size.min(128 * 1024));
    if is_rle {
        if block.len() < header_bytes + 1 {
            return Err(Error::Corrupt);
        }
        let byte = block[header_bytes];
        literals.resize(regen_size, byte);
        Ok(LiteralsResult {
            literals,
            consumed: header_bytes + 1,
        })
    } else {
        if block.len() < header_bytes + regen_size {
            return Err(Error::Corrupt);
        }
        literals.extend_from_slice(&block[header_bytes..header_bytes + regen_size]);
        Ok(LiteralsResult {
            literals,
            consumed: header_bytes + regen_size,
        })
    }
}

fn decode_compressed_literals(
    block: &[u8],
    sf: u8,
    state: &mut LiteralsState,
    reuse: bool,
) -> Result<LiteralsResult, Error> {
    // Header layout depends on size_format. For SF=00 (1-stream) we also have
    // the smallest header.
    //   sf = 00: 3-byte header, 1-stream, Regen=10b, Comp=10b
    //   sf = 01: 3-byte header, 4-stream, Regen=10b, Comp=10b
    //   sf = 10: 4-byte header, 4-stream, Regen=14b, Comp=14b
    //   sf = 11: 5-byte header, 4-stream, Regen=18b, Comp=18b
    let (regen_size, comp_size, header_bytes, four_streams) = match sf {
        0b00 | 0b01 => {
            if block.len() < 3 {
                return Err(Error::Corrupt);
            }
            // 10 bits regen, 10 bits comp.
            // Layout: [LHD bits 7..4 = regen lo 4][byte1 = regen hi 6 + comp lo 2][byte2 = comp hi 8]
            let h0 = block[0] as u32;
            let h1 = block[1] as u32;
            let h2 = block[2] as u32;
            let regen = ((h0 >> 4) | ((h1 & 0x3F) << 4)) as usize;
            let comp = ((h1 >> 6) | (h2 << 2)) as usize;
            (regen, comp, 3, sf != 0b00)
        }
        0b10 => {
            if block.len() < 4 {
                return Err(Error::Corrupt);
            }
            // 14 bits regen, 14 bits comp.
            let h0 = block[0] as u32;
            let h1 = block[1] as u32;
            let h2 = block[2] as u32;
            let h3 = block[3] as u32;
            let regen = ((h0 >> 4) | (h1 << 4) | ((h2 & 0x03) << 12)) as usize;
            let comp = ((h2 >> 2) | (h3 << 6)) as usize;
            (regen, comp, 4, true)
        }
        0b11 => {
            if block.len() < 5 {
                return Err(Error::Corrupt);
            }
            // Layout: 4-bit (type+sf) + 18-bit regen + 18-bit comp = 40 bits.
            let bits: u64 = (block[0] as u64)
                | ((block[1] as u64) << 8)
                | ((block[2] as u64) << 16)
                | ((block[3] as u64) << 24)
                | ((block[4] as u64) << 32);
            let regen = ((bits >> 4) & 0x3_FFFF) as usize;
            let comp = ((bits >> 22) & 0x3_FFFF) as usize;
            (regen, comp, 5, true)
        }
        _ => unreachable!(),
    };

    if block.len() < header_bytes + comp_size {
        return Err(Error::Corrupt);
    }

    // Decode Huffman tree (only when not reusing). The tree's bytes count
    // toward `comp_size` (i.e. the literals payload includes them).
    let payload = &block[header_bytes..header_bytes + comp_size];
    let (tree, tree_bytes) = if reuse {
        match state.huff_tree.take() {
            Some(t) => (t, 0),
            None => return Err(Error::Corrupt),
        }
    } else {
        let (t, used) = decode_huffman_tree(payload)?;
        (t, used)
    };

    let bitstreams = &payload[tree_bytes..];

    // Decode the streams. Cap only the capacity HINT (see decode_raw_or_rle);
    // the decode loop still appends exactly `regen_size` symbols.
    let mut literals = Vec::with_capacity(regen_size.min(128 * 1024));
    if !four_streams {
        decode_huff_stream(bitstreams, &tree, regen_size, &mut literals)?;
    } else {
        // 4-stream: first 6 bytes are 3 little-endian u16 lengths for streams
        // 1..=3; stream 4's length is the remainder.
        if bitstreams.len() < 6 {
            return Err(Error::Corrupt);
        }
        let l1 = (bitstreams[0] as usize) | ((bitstreams[1] as usize) << 8);
        let l2 = (bitstreams[2] as usize) | ((bitstreams[3] as usize) << 8);
        let l3 = (bitstreams[4] as usize) | ((bitstreams[5] as usize) << 8);
        if 6 + l1 + l2 + l3 > bitstreams.len() {
            return Err(Error::Corrupt);
        }
        let l4 = bitstreams.len() - 6 - l1 - l2 - l3;
        let s1 = &bitstreams[6..6 + l1];
        let s2 = &bitstreams[6 + l1..6 + l1 + l2];
        let s3 = &bitstreams[6 + l1 + l2..6 + l1 + l2 + l3];
        let s4 = &bitstreams[6 + l1 + l2 + l3..];
        let _ = l4;

        // Real 4-stream mode requires at least 4 regenerated bytes (one per
        // stream) plus the 6-byte jump table parsed above. Reject anything
        // smaller before computing per-stream sizes to avoid the usize
        // subtraction below underflowing on malformed input.
        if regen_size < 4 {
            return Err(Error::Corrupt);
        }
        // Each of the first 3 streams emits ceil(regen_size / 4) bytes; the
        // 4th emits the remainder.
        let per = regen_size.div_ceil(4);
        let last = regen_size.checked_sub(3 * per).ok_or(Error::Corrupt)?;
        decode_huff_stream(s1, &tree, per, &mut literals)?;
        decode_huff_stream(s2, &tree, per, &mut literals)?;
        decode_huff_stream(s3, &tree, per, &mut literals)?;
        decode_huff_stream(s4, &tree, last, &mut literals)?;
    }

    // Stash the tree for potential Treeless reuse next block.
    state.huff_tree = Some(tree);

    Ok(LiteralsResult {
        literals,
        consumed: header_bytes + comp_size,
    })
}

fn decode_huff_stream(
    data: &[u8],
    tree: &HuffTable,
    n: usize,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if n == 0 {
        // Per RFC: a zero-length stream is still terminated by the start
        // marker — but it's harmless to skip.
        return Ok(());
    }
    let mut br = RevBitReader::new(data)?;
    for _ in 0..n {
        let sym = tree.decode(&mut br)?;
        out.push(sym);
    }
    Ok(())
}
