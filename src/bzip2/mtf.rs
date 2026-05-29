//! Move-to-front transform over an arbitrary byte alphabet.
//!
//! Used in bzip2 between BWT and RLE-2/Huffman: the BWT exposes a
//! locally biased byte distribution (long runs of the same byte), MTF
//! turns that bias into a heavy concentration of zeros (because most
//! symbols match the most-recently-seen symbol).
//!
//! Both halves of bzip2 work over a **reduced alphabet** containing
//! only the bytes that actually appear in the block (so the MTF list is
//! the sorted list of those `N ≤ 256` bytes). We expose two flavours:
//!
//! - `mtf_forward_reduced(input, alphabet)` — encode side. Caller has
//!   already computed the sorted reduced alphabet; we return a vector
//!   of MTF indices in `0..alphabet.len()`.
//! - `mtf_inverse_reduced(indices, alphabet)` — decode side. Inverse
//!   of the above.

extern crate alloc;
use alloc::vec::Vec;

/// Encode `input` under MTF, given an initial list `alphabet` of the
/// distinct bytes present in the block (sorted ascending — bzip2's
/// canonical initial MTF order).
///
/// The returned vector has the same length as `input`. Each element is
/// the MTF position (0-based) of the corresponding input byte at the
/// moment it was emitted; the byte is then moved to the front of the
/// list.
pub(crate) fn mtf_forward_reduced(input: &[u8], alphabet: &[u8]) -> Vec<u8> {
    debug_assert!(alphabet.len() <= 256);
    // Local copy of the MTF list we mutate.
    let mut list: [u8; 256] = [0u8; 256];
    let n = alphabet.len();
    list[..n].copy_from_slice(alphabet);

    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        // Linear scan to find b in list[..n]. For bzip2 block sizes
        // (up to 900 KB) the cache-friendliness of the linear scan
        // beats any fancy structure; the alphabet is at most 256 long.
        let mut pos = 0;
        while pos < n && list[pos] != b {
            pos += 1;
        }
        debug_assert!(pos < n, "byte {} not in MTF alphabet", b);
        out.push(pos as u8);
        // Move b to the front: shift list[0..pos] right by 1, set list[0] = b.
        if pos > 0 {
            list.copy_within(0..pos, 1);
            list[0] = b;
        }
    }
    out
}

/// Inverse of `mtf_forward_reduced`: turn a stream of MTF indices back
/// into the original byte stream.
pub(crate) fn mtf_inverse_reduced(indices: &[u8], alphabet: &[u8]) -> Vec<u8> {
    debug_assert!(alphabet.len() <= 256);
    let mut list: [u8; 256] = [0u8; 256];
    let n = alphabet.len();
    list[..n].copy_from_slice(alphabet);

    let mut out = Vec::with_capacity(indices.len());
    for &idx in indices {
        let pos = idx as usize;
        debug_assert!(pos < n);
        let b = list[pos];
        out.push(b);
        if pos > 0 {
            list.copy_within(0..pos, 1);
            list[0] = b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn forward_then_inverse_roundtrip() {
        let input = b"banana banana banana";
        // Reduced alphabet = sorted distinct bytes.
        let mut alpha: Vec<u8> = input.to_vec();
        alpha.sort_unstable();
        alpha.dedup();
        let f = mtf_forward_reduced(input, &alpha);
        let inv = mtf_inverse_reduced(&f, &alpha);
        assert_eq!(inv, input);
    }

    #[test]
    fn long_run_becomes_zeros() {
        let input = vec![b'a'; 100];
        let alpha = vec![b'a'];
        let f = mtf_forward_reduced(&input, &alpha);
        // First emit is the position of 'a' in [a] = 0; after that the
        // MTF list is still [a], so every position is 0.
        assert!(f.iter().all(|&x| x == 0));
    }
}
