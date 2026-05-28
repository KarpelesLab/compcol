//! LZFSE v2 block decoder.
//!
//! ## Status in this build
//!
//! **`bvx2` blocks return [`Error::Unsupported`]**. The FSE primitives that
//! a full v2 implementation needs are present in [`super::fse`], but the
//! intricate bit-packed v2 block header, the L/M/D table parsing, and the
//! reverse FSE bit stream are sufficiently subtle that a half-correct
//! implementation would silently corrupt output for some inputs.
//!
//! The decoder dispatches on `bvx2` magic, parses just enough of the v2
//! header to know how many bytes the block claims to occupy (so we can
//! advance past it cleanly), and returns Unsupported rather than risk a
//! buggy decode.
//!
//! ## Wire format reference
//!
//! For a future round, the v2 header layout is (LSB-first packed):
//! - `n_raw_bytes: 20`
//! - `n_payload_bytes: 20`
//! - `n_literals: 20`
//! - `n_matches: 20`
//! - `n_literal_payload_bytes: 20`
//! - `n_lmd_payload_bytes: 20`
//! - `literal_bits: 3` (number of stub bits in the literal stream final byte)
//! - `literal_state[0..=3]: 10 each` (40 bits — four interleaved FSE states)
//! - `lmd_bits: 3`
//! - `l_state: 10`
//! - `m_state: 10`
//! - `d_state: 10`
//! - followed by packed frequency tables for D (64 syms), M (20 syms),
//!   L (20 syms), and LIT (256 syms).
//!
//! The two payload streams (literal then LMD) are encoded *in reverse*:
//! the decoder pulls bytes from the end of each payload toward its start.

#![allow(dead_code)]

use crate::error::Error;
use crate::lzfse::bits::HeaderBits;

/// Size of the fixed-width portion of the v2 header (the packed bit fields
/// before the variable-length frequency tables). Apple's reference: the v2
/// header is 28 bytes of packed fields plus the freq-table payload.
pub(crate) const V2_HEADER_FIXED_BYTES: usize = 28;

/// Parse just the `n_payload_bytes` field out of a v2 block header. Used
/// by the main decoder to know how many bytes the block occupies so we
/// can skip it cleanly when returning Unsupported.
///
/// `bytes` is the slice starting **after** the 4-byte magic.
/// Returns `Err(Error::UnexpectedEnd)` if `bytes.len() < V2_HEADER_FIXED_BYTES`.
pub(crate) fn parse_payload_size(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() < V2_HEADER_FIXED_BYTES {
        return Err(Error::UnexpectedEnd);
    }
    let mut bits = HeaderBits::new(&bytes[..V2_HEADER_FIXED_BYTES]);
    // Skip n_raw_bytes (20 bits).
    let _n_raw = bits.read(20)?;
    let n_payload = bits.read(20)?;
    Ok(n_payload)
}
