//! HPACK string Huffman coding — RFC 7541 §5.2, table from Appendix B.
//!
//! This is the "h2 huffman" primitive: a fixed canonical Huffman code over
//! 257 symbols (the 256 byte values plus a 30-bit EOS used only for
//! padding). Strings are coded MSB-first; the final byte is padded with the
//! most-significant bits of the EOS code (all `1`s).
//!
//! The codec wrapper [`Http2Huffman`] exposes this primitive through the
//! crate's uniform [`Encoder`](crate::Encoder) / [`Decoder`](crate::Decoder)
//! traits (encode = compress a byte string, decode = expand one). The full
//! HPACK header codec lives in the parent module.
//!
//! Clean-room: the code table is transcribed from RFC 7541 Appendix B.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

/// Number of real symbols (byte values 0..=255); index 256 is EOS.
const EOS: u16 = 256;

/// `(code, bit_length)` for symbols 0..=256, transcribed from RFC 7541
/// Appendix B. Index = symbol; entry 256 is the EOS marker.
#[rustfmt::skip]
pub(crate) const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
];

#[cfg(test)]
const MAX_LEN: usize = 30;

// ─── nibble FSA fast decoder ─────────────────────────────────────────────
//
// Bit-at-a-time canonical decoding is correct but slow (one table probe per
// input bit). Instead we precompute a finite-state machine over the code's
// binary trie whose transitions each consume four input bits: a Huffman
// string then costs two table lookups per input byte.
//
// The states are the trie's 256 internal nodes (257 leaves ⇒ 256 internal
// nodes), so a state fits a `u8`, and because the shortest codeword is five
// bits a nibble completes at most one symbol. The whole machine is therefore
// 256 × 16 three-byte entries (12 KiB) and is built by a `const fn` into a
// `static`: decoding a string allocates and initialises nothing but its own
// output. (An earlier byte-wide machine was ~1.5 MB and was rebuilt on every
// `decode` call, which made each string — however short — cost the better
// part of a millisecond; a header block of thousands of empty Huffman strings
// was a cheap CPU-exhaustion vector.)
//
// The byte-for-byte output and every RFC 7541 §5.2 rejection (EOS symbol,
// over-long padding, non-`1` padding) are identical to the bit-at-a-time
// path — the FSA is just a faster way to walk the same trie.

/// Number of FSA states = internal nodes of the code trie.
const N_STATES: usize = 256;
/// Total trie nodes: 257 leaves + 256 internal nodes.
const N_NODES: usize = 2 * CODES.len() - 1;

/// [`Nib::flags`] bit: this transition completes the symbol in [`Nib::sym`].
const NIB_EMIT: u8 = 1;
/// [`Nib::flags`] bit: this transition completes the EOS symbol (→ Corrupt).
const NIB_EOS: u8 = 2;

/// One nibble transition: where to go and what (if anything) to emit.
#[derive(Clone, Copy)]
struct Nib {
    /// State reached after consuming this nibble's 4 bits.
    next: u8,
    /// `NIB_EMIT` / `NIB_EOS`.
    flags: u8,
    /// The emitted byte (meaningful only with `NIB_EMIT`).
    sym: u8,
}

/// Nibble FSA. State 0 is the trie root, the only clean symbol boundary.
struct Fsa {
    /// `trans[state][nibble]`.
    trans: [[Nib; 16]; N_STATES],
    /// Whether the input may end in this state: the partial path from the
    /// root is fewer than 8 bits and all `1`s (the RFC 7541 §5.2 EOS-prefix
    /// padding rule; the root itself is the zero-padding case).
    accept: [bool; N_STATES],
}

/// The decode machine, evaluated at compile time.
static FSA: Fsa = build_fsa();

const fn build_fsa() -> Fsa {
    /// `leaf[node]` value for a node that is not a leaf.
    const INTERNAL: u16 = u16::MAX;

    // Binary trie of the code. Node 0 is the root; `child[node][bit]` is the
    // next node index (0 = unset, since the root is never a child) and
    // `leaf[node]` the symbol of a leaf.
    let mut child = [[0u16; 2]; N_NODES];
    let mut leaf = [INTERNAL; N_NODES];
    let mut n_nodes = 1usize;
    let mut sym = 0usize;
    while sym < CODES.len() {
        let (code, len) = CODES[sym];
        let mut node = 0usize;
        let mut i = len as u32;
        while i > 0 {
            i -= 1;
            let bit = ((code >> i) & 1) as usize;
            // A codeword may not extend another one (prefix-free code).
            assert!(leaf[node] == INTERNAL);
            if child[node][bit] == 0 {
                child[node][bit] = n_nodes as u16;
                n_nodes += 1;
            }
            node = child[node][bit] as usize;
        }
        // … nor be a prefix of (or equal to) an earlier one.
        assert!(leaf[node] == INTERNAL && child[node][0] == 0 && child[node][1] == 0);
        leaf[node] = sym as u16;
        sym += 1;
    }
    assert!(n_nodes == N_NODES);

    // Number the internal nodes densely (root → state 0) and record, for each
    // node, its depth and whether its path from the root is all `1` bits.
    // Children are always created after their parent, so one forward pass in
    // creation order sees every parent before its children.
    let mut state_of = [0u8; N_NODES];
    let mut depth = [0u8; N_NODES];
    let mut ones = [true; N_NODES];
    let mut accept = [false; N_STATES];
    let mut n_states = 0usize;
    let mut node = 0usize;
    while node < N_NODES {
        if leaf[node] == INTERNAL {
            // The code is complete: every internal node has both children.
            assert!(child[node][0] != 0 && child[node][1] != 0);
            assert!(n_states < N_STATES);
            state_of[node] = n_states as u8;
            accept[n_states] = depth[node] < 8 && ones[node];
            n_states += 1;
            let mut bit = 0usize;
            while bit < 2 {
                let c = child[node][bit] as usize;
                depth[c] = depth[node] + 1;
                ones[c] = ones[node] && bit == 1;
                bit += 1;
            }
        }
        node += 1;
    }
    assert!(n_states == N_STATES);

    let mut trans = [[Nib {
        next: 0,
        flags: 0,
        sym: 0,
    }; 16]; N_STATES];
    let mut start = 0usize;
    while start < N_NODES {
        if leaf[start] == INTERNAL {
            let mut nibble = 0usize;
            while nibble < 16 {
                let mut node = start;
                let mut flags = 0u8;
                let mut out = 0u8;
                let mut i = 4u32;
                while i > 0 {
                    i -= 1;
                    node = child[node][(nibble >> i) & 1] as usize;
                    if leaf[node] != INTERNAL {
                        if leaf[node] == EOS {
                            flags |= NIB_EOS;
                        } else {
                            // Shortest codeword is 5 bits: one symbol at most.
                            assert!(flags & NIB_EMIT == 0);
                            flags |= NIB_EMIT;
                            out = leaf[node] as u8;
                        }
                        node = 0;
                    }
                }
                trans[state_of[start] as usize][nibble] = Nib {
                    next: state_of[node],
                    flags,
                    sym: out,
                };
                nibble += 1;
            }
        }
        start += 1;
    }

    Fsa { trans, accept }
}

/// Canonical decode tables reconstructed from [`CODES`], retained only for
/// the canonicality self-test (which also underpins the FSA's correctness).
#[cfg(test)]
struct DecodeTable {
    /// `first_code[len]` = numeric value of the first codeword of length
    /// `len` (1..=30).
    first_code: [u32; MAX_LEN + 1],
    /// Symbols ordered by (length asc, code asc).
    symbols: Vec<u16>,
}

#[cfg(test)]
impl DecodeTable {
    fn build() -> Self {
        let mut count = [0u32; MAX_LEN + 1];
        for &(_, len) in CODES.iter() {
            count[len as usize] += 1;
        }
        // Symbols sorted by length then symbol number. For a canonical code
        // (which Appendix B is) that is also code-ascending order.
        let mut symbols: Vec<u16> = Vec::with_capacity(CODES.len());
        for len in 1..=MAX_LEN {
            for (sym, &(_, l)) in CODES.iter().enumerate() {
                if l as usize == len {
                    symbols.push(sym as u16);
                }
            }
        }
        let mut first_code = [0u32; MAX_LEN + 1];
        let mut code = 0u32;
        for len in 1..=MAX_LEN {
            first_code[len] = code;
            code = (code + count[len]) << 1;
        }
        DecodeTable {
            first_code,
            symbols,
        }
    }
}

/// Huffman-encode `data` (RFC 7541 §5.2): each byte's codeword MSB-first,
/// final byte padded with EOS-prefix `1` bits.
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (code, len) = CODES[b as usize];
        acc = (acc << len) | code as u64;
        nbits += len as u32;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        // Pad the low (8 - nbits) bits with 1s (the MSBs of EOS).
        let pad = 8 - nbits;
        let byte = ((acc << pad) | ((1u64 << pad) - 1)) as u8;
        out.push(byte);
    }
    out
}

/// Number of bytes [`encode`] would produce for `data`, without allocating.
/// Used by the HPACK encoder to choose Huffman vs raw per RFC 7541 §5.2.
pub fn encoded_len(data: &[u8]) -> usize {
    let bits: usize = data.iter().map(|&b| CODES[b as usize].1 as usize).sum();
    bits.div_ceil(8)
}

/// Huffman-decode `data`. Rejects (RFC 7541 §5.2): padding longer than 7
/// bits, padding not consisting of EOS-prefix `1`s, and any appearance of
/// the EOS symbol — all as [`Error::Corrupt`].
pub fn decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    let fsa = &FSA;
    let mut out = Vec::with_capacity(data.len() * 2);
    // Current state (internal trie node). State 0 = root = symbol boundary.
    let mut state = 0u8;
    for &byte in data {
        let hi = fsa.trans[state as usize][(byte >> 4) as usize];
        if hi.flags & NIB_EMIT != 0 {
            out.push(hi.sym);
        }
        let lo = fsa.trans[hi.next as usize][(byte & 0x0f) as usize];
        if lo.flags & NIB_EMIT != 0 {
            out.push(lo.sym);
        }
        if (hi.flags | lo.flags) & NIB_EOS != 0 {
            return Err(Error::Corrupt);
        }
        state = lo.next;
    }
    // Trailing bits are padding: must be < 8 bits, all 1s. A prefix-free code
    // guarantees these EOS-prefix 1s cannot complete a real symbol above.
    if !fsa.accept[state as usize] {
        return Err(Error::Corrupt);
    }
    Ok(out)
}

// ─── codec wrapper (uniform Encoder/Decoder surface) ─────────────────────

/// HTTP/2 HPACK string Huffman coding ([RFC 7541] §5.2) as a standalone
/// compcol codec. `NAME = "h2-huffman"`.
///
/// Encoding compresses a byte string with the fixed HPACK code; decoding
/// expands one. There is no framing — the whole input is one Huffman string,
/// exactly as it appears inside an HPACK string literal.
///
/// [RFC 7541]: https://www.rfc-editor.org/rfc/rfc7541
#[derive(Debug, Clone, Copy, Default)]
pub struct Http2Huffman;

impl Algorithm for Http2Huffman {
    const NAME: &'static str = "h2-huffman";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_: ()) -> Encoder {
        Encoder::default()
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::default()
    }
}

/// Streaming wrapper that buffers the whole input, then Huffman-encodes it
/// in `finish` and drains the result. (The padding can't be emitted until
/// the input ends, so the transform is whole-buffer.)
#[derive(Debug, Default)]
pub struct Encoder {
    input: Vec<u8>,
    output: Vec<u8>,
    cursor: usize,
    done: bool,
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _out: &mut [u8]) -> Result<RawProgress, Error> {
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.done {
            self.output = encode(&self.input);
            self.done = true;
        }
        Ok(drain(&self.output, &mut self.cursor, output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.cursor = 0;
        self.done = false;
    }
}

/// Streaming wrapper that buffers the whole input, then Huffman-decodes it
/// in `finish` and drains the result.
#[derive(Debug, Default)]
pub struct Decoder {
    input: Vec<u8>,
    output: Vec<u8>,
    cursor: usize,
    decoded: bool,
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.decoded {
            self.input.extend_from_slice(input);
            return Ok(RawProgress {
                consumed: input.len(),
                written: 0,
                done: false,
            });
        }
        Ok(drain(&self.output, &mut self.cursor, output))
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.decoded {
            self.output = decode(&self.input)?;
            self.decoded = true;
        }
        Ok(drain(&self.output, &mut self.cursor, output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.cursor = 0;
        self.decoded = false;
    }
}

fn drain(buf: &[u8], cursor: &mut usize, output: &mut [u8]) -> RawProgress {
    let remaining = buf.len() - *cursor;
    let take = remaining.min(output.len());
    output[..take].copy_from_slice(&buf[*cursor..*cursor + take]);
    *cursor += take;
    RawProgress {
        consumed: 0,
        written: take,
        done: *cursor >= buf.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_canonical_and_complete() {
        // Reconstructing codes from lengths must reproduce the table exactly,
        // which both validates the transcription and proves the code is
        // canonical (so the decoder's first_code math is correct).
        let table = DecodeTable::build();
        assert_eq!(table.symbols.len(), 257);
        let mut next = table.first_code;
        for &sym in &table.symbols {
            let (code, len) = CODES[sym as usize];
            let l = len as usize;
            assert_eq!(next[l], code, "symbol {sym} code mismatch");
            next[l] += 1;
        }
    }

    #[test]
    fn rfc_c4_string_vectors() {
        // RFC 7541 C.4.1: "www.example.com" → f1e3 c2e5 f23a 6ba0 ab90 f4ff
        let enc = encode(b"www.example.com");
        assert_eq!(
            enc,
            [
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
            ]
        );
        assert_eq!(decode(&enc).unwrap(), b"www.example.com");

        // C.4.2: "no-cache" → a8eb 1064 9cbf
        let enc = encode(b"no-cache");
        assert_eq!(enc, [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
        assert_eq!(decode(&enc).unwrap(), b"no-cache");

        // C.4.3: "custom-key" → 25a8 49e9 5ba9 7d7f
        assert_eq!(
            encode(b"custom-key"),
            [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]
        );
        // C.4.3: "custom-value" → 25a8 49e9 5bb8 e8b4 bf
        assert_eq!(
            encode(b"custom-value"),
            [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]
        );
    }

    #[test]
    fn round_trip_all_bytes_and_empty() {
        assert_eq!(encode(b""), b"");
        assert_eq!(decode(b"").unwrap(), b"");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn eos_symbol_rejected() {
        // 30 one-bits = EOS code; as a full byte-aligned input it decodes to
        // the EOS symbol and must be rejected.
        let bytes = [0xffu8, 0xff, 0xff, 0xff, 0xc0]; // 30 ones + 10 pad ones
        // (40 bits: first 30 = EOS) → Corrupt
        assert!(matches!(decode(&bytes), Err(Error::Corrupt)));
    }

    #[test]
    fn bad_padding_rejected() {
        // "0" encodes as symbol 48 = 00000 (5 bits); pad with zeros instead of
        // ones → invalid padding.
        let bad = [0b0000_0000u8]; // 5-bit code 00000 then 000 padding
        assert!(matches!(decode(&bad), Err(Error::Corrupt)));
    }

    /// Slow reference decoder: canonical bit-at-a-time decoding straight from
    /// the RFC 7541 §5.2 rules, sharing nothing with the table-driven
    /// [`decode`] but the code table itself.
    fn decode_reference(table: &DecodeTable, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut count = [0u32; MAX_LEN + 1];
        for &(_, len) in CODES.iter() {
            count[len as usize] += 1;
        }
        let mut offset = [0u32; MAX_LEN + 1];
        for len in 1..=MAX_LEN {
            offset[len] = offset[len - 1] + count[len - 1];
        }

        let mut out = Vec::new();
        // The bits of the codeword in progress.
        let mut code = 0u32;
        let mut len = 0usize;
        let mut all_ones = true;
        for &byte in data {
            for i in (0..8).rev() {
                let bit = ((byte >> i) & 1) as u32;
                code = (code << 1) | bit;
                len += 1;
                all_ones &= bit == 1;
                assert!(len <= MAX_LEN, "prefix code must resolve within 30 bits");
                let rel = code.wrapping_sub(table.first_code[len]);
                if code >= table.first_code[len] && rel < count[len] {
                    let sym = table.symbols[(offset[len] + rel) as usize];
                    if sym == EOS {
                        return Err(Error::Corrupt);
                    }
                    out.push(sym as u8);
                    code = 0;
                    len = 0;
                    all_ones = true;
                }
            }
        }
        // Whatever is left is padding: fewer than 8 bits, all of them `1`.
        if len >= 8 || !all_ones {
            return Err(Error::Corrupt);
        }
        Ok(out)
    }

    /// Outcome of a decode, comparable across implementations.
    fn outcome(r: Result<Vec<u8>, Error>) -> Option<Vec<u8>> {
        match r {
            Ok(v) => Some(v),
            Err(Error::Corrupt) => None,
            Err(e) => panic!("unexpected error kind {e:?}"),
        }
    }

    #[test]
    fn table_decoder_matches_bitwise_reference() {
        let table = DecodeTable::build();
        let check = |data: &[u8]| {
            assert_eq!(
                outcome(decode(data)),
                outcome(decode_reference(&table, data)),
                "decoders disagree on {data:02x?}"
            );
        };

        // Every 0-, 1- and 2-byte input.
        check(&[]);
        for a in 0..=255u8 {
            check(&[a]);
            for b in 0..=255u8 {
                check(&[a, b]);
            }
        }

        // Runs of `1` bits around the padding limit and the 30-bit EOS code,
        // each with every possible final byte: valid 1..=7-bit padding,
        // over-long (>= 8 bit) padding, EOS in the stream, non-`1` padding.
        for ones in 0..=6usize {
            for last in 0..=255u8 {
                let mut v = alloc::vec![0xffu8; ones];
                v.push(last);
                check(&v);
                // The same tail after a real symbol.
                let mut w = encode(b"a-Z\x00\xff");
                w.pop();
                w.extend_from_slice(&v);
                check(&w);
            }
        }

        // Valid encodings of random strings, then the same with every value of
        // the final byte (flips padding bits / truncates the last symbol), a
        // dropped final byte, and an appended byte.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..300 {
            let n = (next() % 24) as usize;
            let plain: Vec<u8> = (0..n)
                .map(|_| {
                    let r = next();
                    // Mix common (short-code) and rare (long-code) symbols.
                    if round % 2 == 0 {
                        b"0123456789abcdefghij -/.:%=_"[(r % 28) as usize]
                    } else {
                        (r >> 8) as u8
                    }
                })
                .collect();
            let enc = encode(&plain);
            assert_eq!(decode(&enc).unwrap(), plain);
            assert_eq!(decode_reference(&table, &enc).unwrap(), plain);
            if let Some((&last, head)) = enc.split_last() {
                check(head);
                let mut v = enc.clone();
                for b in 0..=255u8 {
                    *v.last_mut().unwrap() = b;
                    check(&v);
                }
                *v.last_mut().unwrap() = last;
                for b in [0x00, 0x7f, 0x80, 0xfe, 0xff] {
                    v.push(b);
                    check(&v);
                    v.pop();
                }
            }
        }

        // Arbitrary bytes, biased towards 0xff so the long codes, EOS and the
        // all-ones padding paths are exercised.
        for _ in 0..20_000 {
            let n = (next() % 40) as usize;
            let data: Vec<u8> = (0..n)
                .map(|_| {
                    let r = next();
                    if r % 3 == 0 { 0xff } else { (r >> 8) as u8 }
                })
                .collect();
            check(&data);
        }
    }
}
