//! Integration tests for the PKZIP Implode decoder.
//!
//! Implode is decoder-only in this crate (encoder always returns
//! [`Error::Unsupported`]). PKZIP 1.x — the only widely-distributed
//! Implode encoder ever shipped — runs only under DOS and emits its
//! payload inside a `.zip` container, so we can't drop a `pkzip`
//! invocation into CI. The Info-ZIP `explode.c` reference and Hans
//! Wennborg's `hwzip-2.x` are both readable as source but not present
//! on this system as binaries.
//!
//! Workaround: this test file carries a small **fixture-builder**
//! helper that emits valid Implode streams matching the wire format
//! the decoder reads. It is **not** a public encoder — it makes no
//! attempt to choose good codeword lengths or pack densely; it just
//! emits something the decoder must accept per the spec. We use it to
//! produce fixtures for all four (window-size × tree-count) modes and
//! then verify the decoded output matches.
//!
//! In addition there is a hard-coded "golden" byte array — produced
//! once with this same builder and checked in — that the decoder
//! processes end-to-end as a smoke test against future builder
//! refactors.
//!
//! Canonical v0.4 (Progress, Status) driver throughout.

#![cfg(feature = "zip_implode")]

use compcol::zip_implode::{Decoder, Encoder, ZipImplode};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── fixture builder ─────────────────────────────────────────────────────
//
// Symbol-by-symbol LSB-first bit writer used to assemble Implode fixtures.

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    fn write(&mut self, value: u32, n: u32) {
        debug_assert!(n <= 32);
        let masked = if n == 32 {
            value as u64
        } else if n == 0 {
            0
        } else {
            (value as u64) & ((1u64 << n) - 1)
        };
        self.acc |= masked << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    fn align(&mut self) {
        if self.n > 0 {
            self.out.push(self.acc as u8);
            self.acc = 0;
            self.n = 0;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}

/// Build a canonical-code table mirroring Implode's *reversed* assignment.
/// Returns `codes[sym] = (lsb_first_wire_code, length)`.
fn build_codes(lens: &[u8]) -> Vec<(u32, u8)> {
    let max_len = *lens.iter().max().unwrap_or(&0) as usize;
    if max_len == 0 {
        return vec![(0, 0); lens.len()];
    }
    let mut len_count = vec![0u32; max_len + 1];
    for &l in lens {
        len_count[l as usize] += 1;
    }
    let mut next_code = vec![0u32; max_len + 2];
    let mut code = 0u32;
    for bits in 1..=max_len {
        code = (code + len_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    let mut codes = vec![(0u32, 0u8); lens.len()];
    for (sym, &l) in lens.iter().enumerate() {
        let l = l as usize;
        if l == 0 {
            continue;
        }
        let canonical = next_code[l];
        next_code[l] += 1;
        // Implode's "reversed" assignment: the wire code we emit, after
        // it's reversed for LSB-first I/O, must be the complement of
        // the canonical code so that the decoder's `!bits` lookup hits
        // the right slot. So we complement first, then reverse.
        let wire = reverse_bits((!canonical) & ((1u32 << l) - 1), l as u32);
        codes[sym] = (wire, l as u8);
    }
    codes
}

/// Emit a tree descriptor: `(count-1)` byte, then `count` pair bytes each
/// `(run-1) << 4 | (bits-1)`. Produces simple run-length groups in
/// increasing symbol order.
fn write_tree_descriptor(out: &mut Vec<u8>, lens: &[u8]) {
    let mut runs: Vec<(u8, u32)> = Vec::new();
    let mut i = 0;
    while i < lens.len() {
        let l = lens[i];
        let mut j = i;
        while j < lens.len() && lens[j] == l {
            j += 1;
        }
        let mut run = (j - i) as u32;
        while run > 0 {
            let take = run.min(16);
            runs.push((l, take));
            run -= take;
        }
        i = j;
    }
    assert!(!runs.is_empty(), "empty tree");
    assert!(runs.len() <= 256);
    out.push((runs.len() - 1) as u8);
    for &(bits, run) in &runs {
        let bits_nib = (bits - 1) & 0x0F;
        let run_nib = ((run as u8) - 1) & 0x0F;
        out.push((run_nib << 4) | bits_nib);
    }
}

const fn reverse_bits(mut v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    let mut i = 0;
    while i < n {
        out = (out << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    out
}

#[derive(Clone, Copy)]
enum Tok {
    Lit(u8),
    /// (distance ≥ 1, length ≥ min_len)
    Match(u32, u32),
}

/// Build a complete framed Implode stream.
fn build_stream(
    large_window: bool,
    lit_tree: bool,
    lit_lens: &[u8],
    len_lens: &[u8],
    dist_lens: &[u8],
    tokens: &[Tok],
    uncomp_len: u32,
) -> Vec<u8> {
    let mut header = Vec::new();
    let mut f = 0u8;
    if large_window {
        f |= 0b01;
    }
    if lit_tree {
        f |= 0b10;
    }
    header.push(f);
    header.extend_from_slice(&uncomp_len.to_le_bytes());

    let mut trees = Vec::new();
    if lit_tree {
        assert_eq!(lit_lens.len(), 256);
        write_tree_descriptor(&mut trees, lit_lens);
    }
    assert_eq!(len_lens.len(), 64);
    write_tree_descriptor(&mut trees, len_lens);
    assert_eq!(dist_lens.len(), 64);
    write_tree_descriptor(&mut trees, dist_lens);

    let lit_codes = if lit_tree {
        build_codes(lit_lens)
    } else {
        Vec::new()
    };
    let len_codes = build_codes(len_lens);
    let dist_codes = build_codes(dist_lens);
    let bdl = if large_window { 7u32 } else { 6 };
    let min_len = if lit_tree { 3u32 } else { 2 };

    let mut bits = BitWriter::default();
    for &tok in tokens {
        match tok {
            Tok::Lit(b) => {
                bits.write(1, 1);
                if lit_tree {
                    let (c, l) = lit_codes[b as usize];
                    assert!(l > 0, "literal {b} not in tree");
                    bits.write(c, l as u32);
                } else {
                    bits.write(b as u32, 8);
                }
            }
            Tok::Match(dist, len) => {
                assert!(dist >= 1);
                assert!(len >= min_len);
                bits.write(0, 1);
                let dm1 = dist - 1;
                let low = dm1 & ((1 << bdl) - 1);
                let hi = dm1 >> bdl;
                bits.write(low, bdl);
                let (dc, dl) = dist_codes[hi as usize];
                assert!(dl > 0, "dist hi {hi} not in tree");
                bits.write(dc, dl as u32);
                let len_off = len - min_len;
                let (sym, extra) = if len_off < 63 {
                    (len_off, None)
                } else {
                    let e = len_off - 63;
                    assert!(e < 256);
                    (63, Some(e))
                };
                let (lc, ll) = len_codes[sym as usize];
                assert!(ll > 0, "len sym {sym} not in tree");
                bits.write(lc, ll as u32);
                if let Some(e) = extra {
                    bits.write(e, 8);
                }
            }
        }
    }

    let payload = bits.finish();
    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(&trees);
    out.extend_from_slice(&payload);
    out
}

/// Length table covering N symbols at uniform bit-width log2(N). N must
/// be a power of two ≥ 2.
fn uniform_lens(n: usize, bits: u8) -> Vec<u8> {
    assert!(n >= 2);
    assert!(1usize << bits == n);
    vec![bits; n]
}

fn uniform_64_tree() -> Vec<u8> {
    uniform_lens(64, 6)
}
fn uniform_256_tree() -> Vec<u8> {
    uniform_lens(256, 8)
}

// ─── drivers ─────────────────────────────────────────────────────────────

fn decode_oneshot(stream: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    decode_chunked_with(&mut dec, stream, stream.len().max(1), 4096)
}

fn decode_chunked_with(
    dec: &mut Decoder,
    encoded: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0usize;
    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => return Ok(out),
                Status::InputEmpty => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    break;
                }
            }
        }
    }
    Ok(out)
}

// ─── algorithm metadata ─────────────────────────────────────────────────

#[test]
fn algorithm_name_is_zip_implode() {
    assert_eq!(<ZipImplode as Algorithm>::NAME, "zip-implode");
}

#[test]
fn algorithm_factory_produces_codec() {
    let _enc = <ZipImplode as Algorithm>::encoder();
    let _dec = <ZipImplode as Algorithm>::decoder();
}

// ─── encoder is permanently unsupported ─────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        enc.encode(b"hello", &mut out).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn encoder_reset_is_a_noop() {
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
}

// ─── 2-tree mode, 4 KiB ─────────────────────────────────────────────────

#[test]
fn two_tree_4k_literals_only() {
    let payload = b"hello world";
    let tokens: Vec<Tok> = payload.iter().map(|&b| Tok::Lit(b)).collect();
    let stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn two_tree_4k_with_match() {
    // "abcabc" — 3 literals then a back-ref of len=3, dist=3.
    let payload = b"abcabc";
    let tokens = vec![
        Tok::Lit(b'a'),
        Tok::Lit(b'b'),
        Tok::Lit(b'c'),
        Tok::Match(3, 3),
    ];
    let stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert_eq!(out, payload);
}

// ─── 2-tree mode, 8 KiB ─────────────────────────────────────────────────

#[test]
fn two_tree_8k_with_distant_match() {
    // Builds a sequence that exercises bdl = 7 (the 8 KiB-mode distance
    // encoding). Payload: 'x' marker + 200 zero bytes + 4-byte back-ref
    // to the marker, copying "x000" (the marker + the first three of
    // the zero bytes).
    let mut payload = Vec::new();
    payload.push(b'x');
    payload.extend_from_slice(&[0u8; 200]);
    payload.extend_from_slice(&[b'x', 0, 0, 0]);
    let mut tokens: Vec<Tok> = Vec::new();
    tokens.push(Tok::Lit(b'x'));
    for _ in 0..200 {
        tokens.push(Tok::Lit(0));
    }
    tokens.push(Tok::Match(201, 4));
    let stream = build_stream(
        true,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert_eq!(out, payload);
}

// ─── 3-tree mode, 4 KiB ─────────────────────────────────────────────────

#[test]
fn three_tree_4k_literals_only() {
    let payload = b"abcdefghi";
    let tokens: Vec<Tok> = payload.iter().map(|&b| Tok::Lit(b)).collect();
    let stream = build_stream(
        false,
        true,
        &uniform_256_tree(),
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn three_tree_4k_with_match() {
    // "the_the_the" — literal "the_" + back-ref(dist=4, len=7) (3-tree
    // min_len = 3).
    let payload = b"the_the_the";
    let tokens = vec![
        Tok::Lit(b't'),
        Tok::Lit(b'h'),
        Tok::Lit(b'e'),
        Tok::Lit(b'_'),
        Tok::Match(4, 7),
    ];
    let stream = build_stream(
        false,
        true,
        &uniform_256_tree(),
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert_eq!(out, payload);
}

// ─── 3-tree mode, 8 KiB ─────────────────────────────────────────────────

#[test]
fn three_tree_8k_long_match() {
    // 200-byte run by emitting one 'A' then a single match of length
    // 199 with dist=1. This exercises the 8 KiB-window path and the
    // length-extra-byte mechanism (199 - 3 = 196 ≥ 63, so the encoder
    // emits symbol 63 + extra byte = 196 - 63 = 133).
    let mut payload = Vec::new();
    payload.extend_from_slice(b"A");
    payload.extend(core::iter::repeat_n(b'A', 199));
    let tokens = vec![Tok::Lit(b'A'), Tok::Match(1, 199)];
    let stream = build_stream(
        true,
        true,
        &uniform_256_tree(),
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert_eq!(out, payload);
}

// ─── streaming / chunking ───────────────────────────────────────────────

#[test]
fn streaming_one_byte_at_a_time() {
    let payload = b"hello world hello world";
    let tokens: Vec<Tok> = {
        let mut t: Vec<Tok> = b"hello world ".iter().map(|&b| Tok::Lit(b)).collect();
        // Back-ref to the first "hello world " — dist=12, len=11.
        t.push(Tok::Match(12, 11));
        t
    };
    let stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let mut dec = Decoder::new();
    let out = decode_chunked_with(&mut dec, &stream, 1, 1).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn empty_uncompressed_length_decodes_to_empty() {
    // All three trees still appear in the stream per the format; the
    // payload bit-section is empty.
    let stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &[],
        0,
    );
    let out = decode_oneshot(&stream).unwrap();
    assert!(out.is_empty());
}

// ─── error paths ────────────────────────────────────────────────────────

#[test]
fn header_reserved_bits_rejected() {
    let mut stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &[Tok::Lit(b'x')],
        1,
    );
    stream[0] |= 0b1000_0000;
    let err = decode_oneshot(&stream).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn truncated_after_header_is_unexpected_end() {
    let stream = vec![0u8, 0, 0, 0, 1];
    let err = decode_oneshot(&stream).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_mid_payload_is_unexpected_end() {
    let mut stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &[Tok::Lit(b'a'), Tok::Lit(b'b'), Tok::Lit(b'c')],
        3,
    );
    stream.truncate(stream.len() - 2);
    let err = decode_oneshot(&stream).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn corrupt_tree_descriptor_rejected() {
    // Build a valid stream then overwrite the first tree's pair byte
    // so it declares an impossible (over-the-symbol-count) run.
    let mut stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &[Tok::Lit(0)],
        1,
    );
    // Tree descriptors start at byte 5; byte 5 is (count-1), byte 6 is
    // the first pair byte. Replace with one pair declaring run=16 at
    // 1 bit — but a 64-symbol tree only fits 4 such runs; one run of
    // 16 at 1 bit alone would fail the Kraft check.
    stream[5] = 0;
    stream[6] = 0xF0;
    let err = decode_oneshot(&stream).unwrap_err();
    assert!(matches!(err, Error::Corrupt | Error::InvalidHuffmanTree));
}

#[test]
fn reset_restores_decoder_to_pristine_state() {
    let payload = b"reset me";
    let tokens: Vec<Tok> = payload.iter().map(|&b| Tok::Lit(b)).collect();
    let stream = build_stream(
        false,
        false,
        &[],
        &uniform_64_tree(),
        &uniform_64_tree(),
        &tokens,
        payload.len() as u32,
    );
    let mut dec = Decoder::new();
    let out = decode_chunked_with(&mut dec, &stream, stream.len(), 4096).unwrap();
    assert_eq!(out, payload);
    dec.reset();
    let out2 = decode_chunked_with(&mut dec, &stream, stream.len(), 4096).unwrap();
    assert_eq!(out2, payload);
}

#[test]
fn garbage_does_not_panic() {
    let garbage = vec![0xFFu8; 64];
    let _ = decode_oneshot(&garbage);
}

// ─── hard-coded golden fixture ──────────────────────────────────────────
//
// Bytes produced by the in-test builder for the 2-tree 4 KiB
// "abcabc"+back-ref fixture, captured once and checked in so the
// decoder still passes if the builder is later rewritten.

#[test]
fn golden_two_tree_4k_decode() {
    // Decoded plaintext: "abcabc".
    let expected: &[u8] = b"abcabc";
    let fixture: &[u8] = &GOLDEN_2T4K;
    let out = decode_oneshot(fixture).unwrap();
    assert_eq!(out, expected);
}

/// Pre-computed (builder output for the abcabc test). Recompute by
/// adding `eprintln!("{stream:02x?}")` inside `two_tree_4k_with_match`
/// and running with `-- --nocapture` if the wire format ever changes.
#[rustfmt::skip]
const GOLDEN_2T4K: [u8; 21] = [
    // Header: flags=0, uncompressed_len=6.
    0x00, 0x06, 0x00, 0x00, 0x00,
    // Length tree: 64 symbols at 6 bits — (count-1)=3 + four pair bytes
    // declaring run=16, bits=6 (0xF5 = (15<<4)|5).
    0x03, 0xF5, 0xF5, 0xF5, 0xF5,
    // Distance tree: same shape.
    0x03, 0xF5, 0xF5, 0xF5, 0xF5,
    // Payload: 3 literal markers + 'a' + 'b' + 'c' + back-ref(dist=3,len=3),
    // assembled by the in-test builder.
    0xC3, 0x8A, 0x1D, 0x23, 0xFC, 0x1F,
];

// ─── factory (only if the feature is enabled) ────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_zip_implode_encoder_and_decoder() {
        assert!(factory::encoder_by_name("zip-implode").is_some());
        assert!(factory::decoder_by_name("zip-implode").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-zip-implode").is_none());
        assert!(factory::decoder_by_name("not-a-real-zip-implode").is_none());
    }

    #[test]
    fn names_contains_zip_implode() {
        assert!(factory::names().contains(&"zip-implode"));
    }

    #[test]
    fn boxed_encoder_is_unsupported() {
        use compcol::Error;
        let mut enc = factory::encoder_by_name("zip-implode").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn extension_is_zip_implode() {
        assert_eq!(factory::extension("zip-implode"), Some("implode"));
    }
}
