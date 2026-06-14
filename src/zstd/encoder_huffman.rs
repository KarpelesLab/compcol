//! Huffman encoder for the Zstandard literals section (RFC 8478 §4.2).
//!
//! Builds a length-limited canonical Huffman code from a byte-frequency
//! histogram, then encodes the tree description as a "weight" array
//! (direct nibble-packed — we do not emit FSE-compressed weight tables) and
//! one or four reverse-bitstream Huffman streams.
//!
//! The output layout matches the decoder side in [`crate::zstd::huffman`] and
//! [`crate::zstd::literals`]. Codes are canonical, MSB-first; the streams use
//! the same reverse layout as the FSE bitstream and share the
//! [`RevBitWriter`].
//!
//! Streams use:
//! - **1-stream** mode when `regen_size` fits in the 10-bit Size_Format=00 header (≤ 1023).
//! - **4-stream** mode otherwise. Three 16-bit little-endian Jump_Table words
//!   give the byte length of streams 1..=3; stream 4 fills the rest of the
//!   payload. Each stream encodes `ceil(regen_size / 4)` bytes except the
//!   fourth, which gets the remainder.

use alloc::vec::Vec;

use crate::zstd::encoder_bitwriter::RevBitWriter;
use crate::zstd::huffman::HUF_MAX_BITS;

/// Per-symbol code-length array. Index = byte value (0..256), value = bit
/// length of that symbol's Huffman code (`0` = symbol absent).
pub type HuffLengths = [u8; 256];

/// Encoder-side Huffman table: per-symbol (code, length). Codes are
/// canonical, MSB-first (same convention as the decoder's lookup).
pub struct HuffEncoder {
    /// `codes[sym]` is the canonical Huffman code (right-justified in `u16`)
    /// for length `lengths[sym]`. Undefined when `lengths[sym] == 0`.
    pub codes: [u16; 256],
    /// `lengths[sym]` is the code length in bits, or 0 if the symbol is absent.
    pub lengths: HuffLengths,
}

impl HuffEncoder {
    /// Encode one symbol. Caller guarantees the symbol is present
    /// (i.e. `self.lengths[sym] != 0`).
    pub fn encode_symbol(&self, writer: &mut RevBitWriter, sym: u8) {
        let len = self.lengths[sym as usize];
        debug_assert!(len > 0, "encoding absent symbol {sym}");
        let code = self.codes[sym as usize];
        writer.write_bits(code as u64, len as u32);
    }
}

// ─── Length-limited Huffman code construction ─────────────────────────────

/// Build a length-limited Huffman tree from a 256-bin frequency histogram.
///
/// Returns the canonical per-symbol code lengths capped at
/// [`HUF_MAX_BITS`] (11). Returns `None` if fewer than 2 distinct symbols
/// appear in the histogram — that case is unsuitable for Huffman coding and
/// should be handled with an RLE or raw literal block by the caller.
pub fn build_huff_lengths(freq: &[u32; 256]) -> Option<HuffLengths> {
    let present: Vec<usize> = (0..256).filter(|&s| freq[s] > 0).collect();
    if present.len() < 2 {
        return None;
    }

    // Build the unconstrained Huffman tree with a sorted-vector "heap".
    // Tree node: (weight, parent_id). Parent of u32::MAX means root.
    #[derive(Clone, Copy)]
    struct Node {
        parent: u32,
    }
    let mut nodes: Vec<Node> = Vec::with_capacity(2 * present.len());
    // Heap stores (weight, id) sorted with largest LAST → pop = swap_remove last.
    let mut heap: Vec<(u64, u32)> = Vec::with_capacity(present.len());
    let mut leaf_id_of_sym = [u32::MAX; 256];
    for &s in &present {
        let id = nodes.len() as u32;
        nodes.push(Node { parent: u32::MAX });
        heap.push((freq[s] as u64, id));
        leaf_id_of_sym[s] = id;
    }
    heap.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));

    while heap.len() >= 2 {
        let (w1, id1) = heap.pop().unwrap();
        let (w2, id2) = heap.pop().unwrap();
        let new_id = nodes.len() as u32;
        let new_weight = w1.saturating_add(w2);
        nodes.push(Node { parent: u32::MAX });
        nodes[id1 as usize].parent = new_id;
        nodes[id2 as usize].parent = new_id;
        let entry = (new_weight, new_id);
        // Insert maintaining sort.
        let pos = heap
            .iter()
            .rposition(|x| x.0 > new_weight || (x.0 == new_weight && x.1 > new_id))
            .map(|i| i + 1)
            .unwrap_or(0);
        heap.insert(pos, entry);
    }

    // Compute leaf depths.
    let mut lengths: HuffLengths = [0u8; 256];
    for s in 0..256 {
        let leaf = leaf_id_of_sym[s];
        if leaf == u32::MAX {
            continue;
        }
        let mut depth = 0u32;
        let mut cur = nodes[leaf as usize].parent;
        while cur != u32::MAX {
            depth += 1;
            cur = nodes[cur as usize].parent;
        }
        if depth == 0 {
            depth = 1;
        }
        lengths[s] = if depth > 255 { 255 } else { depth as u8 };
    }

    cap_code_lengths(&mut lengths, HUF_MAX_BITS);
    Some(lengths)
}

/// Cap code lengths at `max_len`, re-distributing slots to keep the Kraft
/// equality `Σ 2^-len == 1` satisfied for a complete tree.
fn cap_code_lengths(lengths: &mut HuffLengths, max_len: u8) {
    // Clamp anything > max_len down to max_len. May overflow the Kraft budget.
    for l in lengths.iter_mut() {
        if *l > max_len {
            *l = max_len;
        }
    }
    // Kraft total in units of 2^(-max_len). Budget = 2^max_len.
    let mut total: u64 = 0;
    for &l in lengths.iter() {
        if l > 0 {
            total += 1u64 << (max_len - l);
        }
    }
    let budget: u64 = 1u64 << max_len;

    // Phase 1: reduce total if it exceeds budget by lengthening shorter codes
    // (largest "savings" go to the shortest codes since they contribute the
    // most). Repeatedly lengthen the SHORTEST present code by 1.
    while total > budget {
        // Find the shortest present code with length < max_len.
        let mut best_sym = usize::MAX;
        let mut best_len = u8::MAX;
        for (s, &l) in lengths.iter().enumerate() {
            if l > 0 && l < max_len && l < best_len {
                best_sym = s;
                best_len = l;
            }
        }
        if best_sym == usize::MAX {
            break;
        }
        let old_contrib = 1u64 << (max_len - best_len);
        let new_contrib = 1u64 << (max_len - best_len - 1);
        let delta = old_contrib - new_contrib;
        lengths[best_sym] = best_len + 1;
        total -= delta;
    }

    // Phase 2: if we over-corrected and total < budget, top up by shortening
    // max-length codes (each shortening doubles its contribution).
    while total < budget {
        let mut best_sym = usize::MAX;
        for (s, &l) in lengths.iter().enumerate() {
            if l == max_len {
                best_sym = s;
                break;
            }
        }
        if best_sym == usize::MAX {
            // Try any code; shortening adds contribution.
            for (s, &l) in lengths.iter().enumerate() {
                if l > 1 {
                    best_sym = s;
                    break;
                }
            }
            if best_sym == usize::MAX {
                break;
            }
        }
        let cur = lengths[best_sym];
        let cur_contrib = 1u64 << (max_len - cur);
        if total + cur_contrib > budget {
            // Try a longer code instead.
            let mut alt = usize::MAX;
            for (s, &l) in lengths.iter().enumerate() {
                if l > cur {
                    let lc = 1u64 << (max_len - l);
                    if total + lc <= budget {
                        alt = s;
                        break;
                    }
                }
            }
            if alt == usize::MAX {
                break;
            }
            let alt_len = lengths[alt];
            let alt_contrib = 1u64 << (max_len - alt_len);
            lengths[alt] = alt_len - 1;
            total += alt_contrib;
        } else {
            lengths[best_sym] = cur - 1;
            total += cur_contrib;
        }
    }
}

/// Build the canonical Huffman codes from per-symbol lengths.
///
/// Uses the same canonical ordering as the decoder (RFC 8478 §4.2.1.3):
/// longest codes get the lowest numeric values, within each length symbols
/// are assigned codes in ascending symbol-id order.
pub fn build_huff_encoder(lengths: &HuffLengths) -> HuffEncoder {
    let mut max_len = 0u8;
    for &l in lengths {
        if l > max_len {
            max_len = l;
        }
    }
    let mut counts = [0u32; (HUF_MAX_BITS as usize) + 1];
    for &l in lengths {
        if l > 0 {
            counts[l as usize] += 1;
        }
    }
    let mut next_code = [0u32; (HUF_MAX_BITS as usize) + 2];
    next_code[max_len as usize] = 0;
    for l in (1..max_len).rev() {
        next_code[l as usize] = (next_code[(l + 1) as usize] + counts[(l + 1) as usize]) >> 1;
    }

    let mut codes = [0u16; 256];
    for current_len in (1..=max_len).rev() {
        for (sym, &len) in lengths.iter().enumerate() {
            if len != current_len {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            codes[sym] = code as u16;
        }
    }
    HuffEncoder {
        codes,
        lengths: *lengths,
    }
}

// ─── Weight derivation and serialisation ──────────────────────────────────

/// Convert per-symbol code lengths to the spec's "weight" representation
/// (§4.2.1.3). For length L, weight = `max_num_bits + 1 - L`; absent symbols
/// → weight 0.
///
/// Returns the weight array **truncated** to exclude the last present symbol
/// (the decoder reconstructs that weight implicitly). Also returns
/// `max_num_bits`.
pub fn lengths_to_weights(lengths: &HuffLengths) -> (Vec<u8>, u8) {
    let mut max_len = 0u8;
    for &l in lengths {
        if l > max_len {
            max_len = l;
        }
    }
    let max_num_bits = max_len;
    let mut last_present: usize = 0;
    for (s, &l) in lengths.iter().enumerate() {
        if l > 0 {
            last_present = s;
        }
    }
    let mut weights = Vec::with_capacity(last_present);
    for &l in &lengths[0..last_present] {
        if l == 0 {
            weights.push(0);
        } else {
            weights.push(max_num_bits + 1 - l);
        }
    }
    (weights, max_num_bits)
}

/// Encode a Huffman tree description using direct nibble-packed weight
/// encoding (Header_Byte = 127 + num_symbols, then weights packed two per
/// byte, hi nibble first).
///
/// Returns the serialised bytes — always `1 + ceil(num_symbols / 2)` long.
pub fn encode_huff_tree_direct(weights: &[u8]) -> Vec<u8> {
    debug_assert!(
        weights.len() <= 128,
        "direct encoding limited to 128 weights (got {})",
        weights.len()
    );
    let n = weights.len();
    let mut out = Vec::with_capacity(1 + n.div_ceil(2));
    out.push(127 + n as u8);
    let mut i = 0;
    while i < n {
        let hi = weights[i] & 0x0F;
        let lo = if i + 1 < n { weights[i + 1] & 0x0F } else { 0 };
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Encode a Huffman tree description using FSE-compressed weights
/// (Header_Byte < 128: the byte value is the FSE payload length in bytes).
///
/// This is needed when the literal alphabet spans more than 128 byte values
/// (e.g. UTF-8 text, whose multi-byte lead/continuation bytes push the
/// highest-indexed present symbol past 127) — the direct nibble encoding caps
/// at 128 weights, so without this path such blocks fall back to a
/// Raw_Literals_Block and get no entropy coding at all.
///
/// The payload layout matches the decoder in
/// [`crate::zstd::huffman::decode_fse_weights`]: an FSE table header
/// (accuracy_log ≤ 6, weight alphabet 0..=11) followed by two interleaved FSE
/// streams written backwards. Returns `None` if the weights can't be
/// FSE-coded smaller than (or the structure doesn't fit) — caller falls back.
pub fn encode_huff_tree_fse(weights: &[u8]) -> Option<Vec<u8>> {
    use crate::zstd::encoder_fse::{FseEncoder, build_normalised_counts, encode_fse_table_header};

    let n = weights.len();
    // Need at least 2 weights to run the 2-state interleaved encoder, and the
    // decoder also requires ≥ 2 symbols (it inits two states).
    if n < 2 {
        return None;
    }

    // Histogram of weight values (alphabet 0..=11).
    const WALPHA: usize = 12; // weights are 0..=HUF_MAX_BITS(11)
    let mut hist = [0u32; WALPHA];
    let mut max_w = 0usize;
    for &w in weights {
        let w = w as usize;
        if w >= WALPHA {
            return None;
        }
        hist[w] += 1;
        if w > max_w {
            max_w = w;
        }
    }
    let max_symbol = max_w; // highest present weight value

    // Choose accuracy_log: weights use a small alphabet, RFC caps at 6.
    // Pick the largest log (≤6) that still lets every present symbol get a
    // slot; smaller tables save header bytes but a log of 6 keeps the streams
    // tight, and the header is only a handful of bytes either way.
    let mut accuracy_log: u8 = 6;
    // accuracy_log must be ≥ 5 for the table-header encoder and large enough
    // to hold the distinct present symbols.
    let distinct = hist.iter().filter(|&&c| c > 0).count();
    while accuracy_log > 5 && (1u32 << accuracy_log) > (n as u32).max(distinct as u32) * 4 {
        accuracy_log -= 1;
    }
    if accuracy_log < 5 {
        accuracy_log = 5;
    }

    let counts = build_normalised_counts(&hist[..=max_symbol], n as u32, accuracy_log)?;
    let header = encode_fse_table_header(&counts, accuracy_log);
    let enc = FseEncoder::from_normalized(&counts, accuracy_log);

    // The decoder (`decode_fse_weights`) emits weights in index order, with
    // even indices owned by state 1 and odd indices by state 2:
    //   w0(s1) w1(s2) w2(s1) w3(s2) …
    // It initialises s1 then s2 (each reads accuracy_log bits at the very end
    // of the bitstream, so s1's init bits are read before s2's), then
    // alternately emits+advances each state in increasing index order, and
    // terminates by emitting the partner state's pending symbol.
    //
    // To replay `weights[0..n]` forward we run the two FSE state machines
    // backwards: seed each state's `init_state` with the HIGHEST-index symbol
    // it owns (the last symbol that state emits), then `encode_symbol` the
    // remaining symbols from the highest index down to 0, picking the owning
    // state by index parity. Each `encode_symbol(state, sym)` writes the bits
    // the decoder consumes to land on `sym` while advancing — so forward
    // decoding reproduces the original order.
    let last_even = (n - 1).is_multiple_of(2);
    let s1_high = if last_even { n - 1 } else { n - 2 };
    let s2_high = if last_even { n - 2 } else { n - 1 };
    let mut writer = RevBitWriter::new();
    let mut s1 = enc.init_state(weights[s1_high] as usize);
    let mut s2 = enc.init_state(weights[s2_high] as usize);
    let mut i1: isize = s1_high as isize - 2;
    let mut i2: isize = s2_high as isize - 2;
    loop {
        if i1 < 0 && i2 < 0 {
            break;
        }
        // Emit in strictly decreasing index order (the mirror of the decoder's
        // increasing reads).
        if i1 >= i2 {
            s1 = enc.encode_symbol(s1, weights[i1 as usize] as usize, &mut writer);
            i1 -= 2;
        } else {
            s2 = enc.encode_symbol(s2, weights[i2 as usize] as usize, &mut writer);
            i2 -= 2;
        }
    }
    // Final states: the decoder reads s1's init before s2's, and the reverse
    // writer's last-written bits are read first — so write s2 first, then s1.
    enc.write_final_state(s2, &mut writer);
    enc.write_final_state(s1, &mut writer);

    let bitstream = writer.finish();
    let mut payload = Vec::with_capacity(1 + header.len() + bitstream.len());
    let fse_len = header.len() + bitstream.len();
    if fse_len >= 128 {
        // Header_Byte must be < 128 (it IS the payload length). Too big to
        // address — bail (caller falls back to direct/raw).
        return None;
    }
    payload.push(fse_len as u8);
    payload.extend_from_slice(&header);
    payload.extend_from_slice(&bitstream);
    Some(payload)
}

// ─── Stream encoding ──────────────────────────────────────────────────────

/// Encode a slice of bytes as a single Huffman bitstream using `enc`.
///
/// Symbols are written in REVERSE order so the decoder (which reads from the
/// end via [`RevBitReader`](crate::zstd::bitreader::RevBitReader)) recovers
/// them in the original order.
pub fn encode_huff_stream(enc: &HuffEncoder, data: &[u8]) -> Vec<u8> {
    let mut writer = RevBitWriter::new();
    for &b in data.iter().rev() {
        enc.encode_symbol(&mut writer, b);
    }
    writer.finish()
}

/// Encode `data` as a 4-stream Huffman payload, returning
/// (stream1, stream2, stream3, stream4). Stream lengths in the resulting
/// payload are `(s1.len(), s2.len(), s3.len(), s4.len())`.
///
/// Streams 1..=3 each handle `ceil(data.len() / 4)` bytes; stream 4 handles
/// the remainder.
pub fn encode_huff_4streams(
    enc: &HuffEncoder,
    data: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let regen = data.len();
    let per = regen.div_ceil(4);
    let last = regen - 3 * per;
    let s1 = encode_huff_stream(enc, &data[0..per]);
    let s2 = encode_huff_stream(enc, &data[per..2 * per]);
    let s3 = encode_huff_stream(enc, &data[2 * per..3 * per]);
    let s4 = encode_huff_stream(enc, &data[3 * per..3 * per + last]);
    (s1, s2, s3, s4)
}

// ─── Helpers for the encoder pipeline ─────────────────────────────────────

/// Sum of `lengths[sym] * freq[sym]` — the raw bit count we'd emit, before
/// the tree-header overhead. Used to decide whether Huffman compression is a
/// net win over a Raw_Literals_Block.
pub fn predicted_bits(lengths: &HuffLengths, freq: &[u32; 256]) -> u64 {
    let mut total = 0u64;
    for s in 0..256 {
        if lengths[s] > 0 {
            total += (lengths[s] as u64) * (freq[s] as u64);
        }
    }
    total
}

/// Histogram bytes from `data` into a 256-bin frequency array.
pub fn histogram(data: &[u8]) -> [u32; 256] {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    freq
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zstd::bitreader::RevBitReader;
    use crate::zstd::huffman::decode_huffman_tree;

    fn round_trip_huff(freq: &[u32; 256]) -> (HuffEncoder, Vec<u8>) {
        let lengths = build_huff_lengths(freq).unwrap();
        // Verify Kraft equality.
        let mut max_len = 0u8;
        for &l in &lengths {
            if l > max_len {
                max_len = l;
            }
        }
        let mut kraft: u64 = 0;
        for &l in &lengths {
            if l > 0 {
                kraft += 1u64 << (max_len - l);
            }
        }
        assert_eq!(kraft, 1u64 << max_len, "Kraft not satisfied");
        let enc = build_huff_encoder(&lengths);
        let (weights, _max) = lengths_to_weights(&lengths);
        let tree_bytes = encode_huff_tree_direct(&weights);
        (enc, tree_bytes)
    }

    #[test]
    fn simple_huff_round_trip() {
        let mut freq = [0u32; 256];
        freq[b'a' as usize] = 10;
        freq[b'b' as usize] = 5;
        freq[b'c' as usize] = 3;
        freq[b'd' as usize] = 2;
        let (enc, tree_bytes) = round_trip_huff(&freq);
        let (dec_table, _consumed) = decode_huffman_tree(&tree_bytes).unwrap();
        // Encode some symbols, decode them back.
        let symbols: &[u8] = b"abcdabcdab";
        let stream = encode_huff_stream(&enc, symbols);
        let mut br = RevBitReader::new(&stream).unwrap();
        let mut decoded: Vec<u8> = Vec::new();
        for _ in 0..symbols.len() {
            decoded.push(dec_table.decode(&mut br).unwrap());
        }
        assert_eq!(decoded, symbols);
    }

    #[test]
    fn larger_alphabet_round_trip() {
        let text = b"the quick brown fox jumps over the lazy dog. the lazy dog sleeps.";
        let mut freq = [0u32; 256];
        for &b in text {
            freq[b as usize] += 1;
        }
        let (enc, tree_bytes) = round_trip_huff(&freq);
        let (dec_table, _consumed) = decode_huffman_tree(&tree_bytes).unwrap();
        let stream = encode_huff_stream(&enc, text);
        let mut br = RevBitReader::new(&stream).unwrap();
        let mut decoded: Vec<u8> = Vec::new();
        for _ in 0..text.len() {
            decoded.push(dec_table.decode(&mut br).unwrap());
        }
        assert_eq!(decoded, text);
    }

    #[test]
    fn four_stream_round_trip() {
        // Use a real-looking input large enough that 4-stream makes sense.
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..32 {
            input.extend_from_slice(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ");
        }
        let freq = histogram(&input);
        let lengths = build_huff_lengths(&freq).unwrap();
        let enc = build_huff_encoder(&lengths);
        let (weights, _) = lengths_to_weights(&lengths);
        let tree_bytes = encode_huff_tree_direct(&weights);
        let (dec_table, _) = decode_huffman_tree(&tree_bytes).unwrap();
        let (s1, s2, s3, s4) = encode_huff_4streams(&enc, &input);
        // Decode each stream.
        let regen = input.len();
        let per = regen.div_ceil(4);
        let last = regen - 3 * per;
        let mut out: Vec<u8> = Vec::new();
        for (stream_bytes, n) in [(s1, per), (s2, per), (s3, per), (s4, last)].into_iter() {
            let mut br = RevBitReader::new(&stream_bytes).unwrap();
            for _ in 0..n {
                out.push(dec_table.decode(&mut br).unwrap());
            }
        }
        assert_eq!(out, input);
    }

    #[test]
    fn fse_weights_round_trip() {
        use crate::zstd::huffman::decode_huffman_tree_weights_for_test;
        // Build a literal alphabet that spans > 128 byte values so the direct
        // nibble path would be rejected. UTF-8-ish: bytes scattered across the
        // 0..=200 range with skewed frequencies.
        let mut freq = [0u32; 256];
        for b in 0u32..200 {
            // Skewed: low bytes common, high bytes rare but present.
            freq[b as usize] = 200 - b + 1;
        }
        let lengths = build_huff_lengths(&freq).unwrap();
        let (weights, _max) = lengths_to_weights(&lengths);
        assert!(weights.len() > 128, "test needs > 128 weights");
        let payload = encode_huff_tree_fse(&weights).expect("fse weight encode");
        let decoded = decode_huffman_tree_weights_for_test(&payload).unwrap();
        assert_eq!(decoded, weights, "FSE weight round-trip mismatch");
    }

    #[test]
    fn fse_weights_round_trip_small_alphabet() {
        use crate::zstd::huffman::decode_huffman_tree_weights_for_test;
        // Even a modest alphabet should round-trip (when it has ≥ 2 weights).
        let text =
            b"the quick brown fox jumps over the lazy dog. pack my box with five dozen liquor jugs.";
        let mut freq = [0u32; 256];
        for &b in text {
            freq[b as usize] += 1;
        }
        let lengths = build_huff_lengths(&freq).unwrap();
        let (weights, _max) = lengths_to_weights(&lengths);
        if let Some(payload) = encode_huff_tree_fse(&weights) {
            let decoded = decode_huffman_tree_weights_for_test(&payload).unwrap();
            assert_eq!(decoded, weights);
        }
    }

    #[test]
    fn cap_code_lengths_idempotent_under_limit() {
        let mut lengths = [0u8; 256];
        // Two symbols, both length 1 — already a valid complete tree.
        lengths[0] = 1;
        lengths[1] = 1;
        cap_code_lengths(&mut lengths, 11);
        assert_eq!(lengths[0], 1);
        assert_eq!(lengths[1], 1);
    }

    #[test]
    fn cap_code_lengths_caps_long_codes() {
        let mut lengths = [0u8; 256];
        // Construct an over-length tree: two length-15 codes + a length-1 code.
        lengths[0] = 1;
        lengths[1] = 15;
        lengths[2] = 15;
        // Kraft = 0.5 + 2*(1/32768) = 0.500061 — but with length-1 + 2 longs
        // this isn't actually a valid complete tree. We're just stressing
        // the capping function: after capping at 11, lengths[1..3] become 11.
        cap_code_lengths(&mut lengths, 11);
        assert!(lengths[1] <= 11 && lengths[2] <= 11);
    }
}
