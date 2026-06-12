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

// ─── byte FSA fast decoder ───────────────────────────────────────────────
//
// Bit-at-a-time canonical decoding is correct but slow (one table probe per
// input bit). For throughput we precompute a byte-wide finite-state machine
// over the canonical code's binary trie: each transition consumes a whole
// input byte and emits 0..=8 complete symbols. A Huffman string then costs
// exactly one table lookup per input byte instead of ~8 bit probes. The FSA
// is rebuilt per `decode` call; its construction is a fixed sweep over the
// trie (≈ states × 256 steps), negligible against any non-trivial input.
//
// The byte-for-byte output and every RFC 7541 §5.2 rejection (EOS symbol,
// over-long padding, non-`1` padding) are identical to the bit-at-a-time
// path — the FSA is just a faster way to walk the same trie.

/// One byte transition: where to go and what to emit.
#[derive(Clone, Copy)]
struct Trans {
    /// Trie node reached after consuming this byte's 8 bits.
    next: u16,
    /// Number of complete symbols emitted while consuming the byte (0..=8).
    n: u8,
    /// Set if any consumed bit completed the EOS symbol (→ Corrupt).
    eos: bool,
    /// The emitted symbol bytes (only the first `n` are meaningful).
    out: [u8; 8],
}

/// Byte FSA: `trans[state * 256 + byte]` gives the transition. State 0 is the
/// trie root, the only valid end-of-string boundary.
struct FastTable {
    trans: Vec<Trans>,
    /// Per-state padding metadata: `(depth, all_ones)` for the partial path
    /// from the root to this node. A valid end state has `depth < 8` and
    /// `all_ones` (the RFC 7541 §5.2 EOS-prefix padding rule).
    pad: Vec<(u8, bool)>,
}

impl FastTable {
    fn build() -> Self {
        // Canonical binary trie. Node 0 is the root. `child[node][bit]` is the
        // next node index (0 = unset, since the root is never a child).
        // `leaf_sym[node]` is the symbol for a leaf, or -1.
        let mut child: Vec<[u16; 2]> = Vec::new();
        child.push([0, 0]); // root
        let mut leaf_sym: Vec<i32> = Vec::new();
        leaf_sym.push(-1);

        for (sym, &(code, len)) in CODES.iter().enumerate() {
            let len = len as u32;
            let mut node = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                let nxt = child[node][bit];
                if nxt == 0 {
                    let new = child.len() as u16;
                    child.push([0, 0]);
                    leaf_sym.push(-1);
                    child[node][bit] = new;
                    node = new as usize;
                } else {
                    node = nxt as usize;
                }
            }
            leaf_sym[node] = sym as i32;
        }

        let n_states = child.len();

        // Per-node padding metadata: depth from root and whether the path is
        // all `1`-bits. Leaves reset to the root after emitting, so only
        // non-leaf nodes are ever a resting state, but we fill every node.
        let mut pad = alloc::vec![(0u8, true); n_states];
        // Iterative DFS from the root; children are always added after their
        // parent, so a single forward pass over node indices in creation
        // order would also work, but we walk explicitly for clarity.
        let mut stack = alloc::vec![0usize];
        while let Some(node) = stack.pop() {
            let (d, ones) = pad[node];
            let kids = child[node];
            for (bit, &c) in kids.iter().enumerate() {
                if c != 0 {
                    let c = c as usize;
                    pad[c] = (d + 1, ones && bit == 1);
                    stack.push(c);
                }
            }
        }

        // Build a per-nibble transition first (n_states × 16, four bit-steps
        // each), then compose each byte transition from its two nibble halves.
        // This costs ≈ n_states·(16·4 + 256·2) build steps instead of
        // n_states·256·8 — roughly a 4× cheaper construction, which matters
        // because the table is rebuilt on every `decode` call.
        struct Nib {
            next: u16,
            n: u8,
            eos: bool,
            out: [u8; 4],
        }
        let mut nib = Vec::with_capacity(n_states * 16);
        for state in 0..n_states {
            for half in 0..16u32 {
                let mut node = state;
                let mut out = [0u8; 4];
                let mut n = 0u8;
                let mut eos = false;
                for i in (0..4).rev() {
                    let bit = ((half >> i) & 1) as usize;
                    node = child[node][bit] as usize;
                    if leaf_sym[node] >= 0 {
                        let sym = leaf_sym[node] as u16;
                        if sym == EOS {
                            eos = true;
                        } else {
                            out[n as usize] = sym as u8;
                            n += 1;
                        }
                        node = 0;
                    }
                }
                nib.push(Nib {
                    next: node as u16,
                    n,
                    eos,
                    out,
                });
            }
        }

        let mut trans = Vec::with_capacity(n_states * 256);
        for state in 0..n_states {
            for byte in 0..256usize {
                let hi = &nib[state * 16 + (byte >> 4)];
                let lo = &nib[hi.next as usize * 16 + (byte & 0x0f)];
                let mut out = [0u8; 8];
                let hn = hi.n as usize;
                out[..hn].copy_from_slice(&hi.out[..hn]);
                let ln = lo.n as usize;
                out[hn..hn + ln].copy_from_slice(&lo.out[..ln]);
                trans.push(Trans {
                    next: lo.next,
                    n: (hn + ln) as u8,
                    eos: hi.eos || lo.eos,
                    out,
                });
            }
        }

        FastTable { trans, pad }
    }
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
    let table = FastTable::build();
    let mut out = Vec::with_capacity(data.len() * 2);
    // Current trie node (state). State 0 = root = clean symbol boundary.
    let mut state = 0usize;
    let trans = &table.trans[..];
    for &byte in data {
        let t = &trans[state * 256 + byte as usize];
        if t.eos {
            return Err(Error::Corrupt);
        }
        // Emit the symbols completed in this byte (0..=8).
        out.extend_from_slice(&t.out[..t.n as usize]);
        state = t.next as usize;
    }
    // Trailing bits are padding: must be < 8 bits, all 1s. A prefix-free code
    // guarantees these EOS-prefix 1s cannot complete a real symbol above.
    let (depth, all_ones) = table.pad[state];
    if depth >= 8 || !all_ones {
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
}
